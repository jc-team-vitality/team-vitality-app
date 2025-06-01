from fastapi import APIRouter, HTTPException, Path, Body, Depends
from google.cloud import firestore_v1, secretmanager_v1
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import HttpUrl
import httpx
from google.cloud import kms_v1

from app.models import OIDCInitiateLoginResponse, OIDCTokenExchangeRequest, OIDCTokenExchangeResponse
from app.core.config import settings
from app.db_clients import get_firestore_db, get_secret_manager_client, get_async_db_session, get_kms_client
from app.services.oidc_service import (
    get_identity_provider_config_from_db,
    cache_oidc_state,
    get_cached_oidc_state,
    fetch_idp_well_known_config_impl,
    validate_id_token,
    jit_provision_user,
    fetch_gcp_secret
)

router = APIRouter()

@router.post("/initiate-login/{provider_name}", response_model=OIDCInitiateLoginResponse)
async def initiate_oidc_login(
    provider_name: str = Path(..., description="The common name of the identity provider (e.g., 'google')"),
    db: firestore_v1.AsyncClient = Depends(get_firestore_db),
    db_pg_session: AsyncSession = Depends(get_async_db_session)
):
    idp_config = await get_identity_provider_config_from_db(provider_name, db_pg_session)
    if not idp_config or not idp_config.is_active:
        raise HTTPException(status_code=404, detail=f"Provider '{provider_name}' not found or not active.")
    import secrets, hashlib, base64
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    code_verifier = secrets.token_urlsafe(64)
    code_challenge_hash = hashlib.sha256(code_verifier.encode('utf-8')).digest()
    code_challenge = base64.urlsafe_b64encode(code_challenge_hash).decode('utf-8').rstrip('=')
    await cache_oidc_state(state, nonce, code_verifier, provider_name, db)
    bff_callback_uri = settings.BFF_OIDC_CALLBACK_URI
    authorization_endpoint_base = str(idp_config.issuer_uri)
    if provider_name == "google":
        actual_authorization_endpoint = "https://accounts.google.com/o/oauth2/v2/auth"
    else:
        from urllib.parse import urljoin
        actual_authorization_endpoint = urljoin(authorization_endpoint_base, "authorize")
    from urllib.parse import urlencode
    params = {
        "client_id": idp_config.client_id,
        "response_type": "code",
        "scope": idp_config.scopes,
        "redirect_uri": bff_callback_uri,
        "state": state,
        "nonce": nonce,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256"
    }
    query_string = urlencode(params)
    authorization_url = f"{actual_authorization_endpoint}?{query_string}"
    return OIDCInitiateLoginResponse(authorization_url=authorization_url, state=state)

@router.post("/token/exchange", response_model=OIDCTokenExchangeResponse)
async def oidc_token_exchange(
    request_data: OIDCTokenExchangeRequest = Body(...),
    db: firestore_v1.AsyncClient = Depends(get_firestore_db),
    http_client: httpx.AsyncClient = Depends(lambda: httpx.AsyncClient()),
    sm_client: secretmanager_v1.SecretManagerServiceClient = Depends(get_secret_manager_client),
    db_pg_session: AsyncSession = Depends(get_async_db_session),
    kms_client: kms_v1.KeyManagementServiceClient = Depends(get_kms_client)
):
    cached_state_data = await get_cached_oidc_state(request_data.state, db)
    if not cached_state_data:
        raise HTTPException(status_code=400, detail="Invalid or expired state parameter. Login flow may have timed out.")
    provider_name = cached_state_data["provider_name"]
    expected_nonce = cached_state_data["nonce"]
    pkce_code_verifier = cached_state_data["pkce_code_verifier"]
    idp_config = await get_identity_provider_config_from_db(provider_name, db_pg_session)
    if not idp_config:
        raise HTTPException(status_code=500, detail=f"Configuration for provider '{provider_name}' not found unexpectedly.")
    well_known_config = await fetch_idp_well_known_config_impl(idp_config.well_known_uri, db, http_client)
    if not well_known_config or not well_known_config.get("token_endpoint"):
        raise HTTPException(status_code=500, detail=f"Could not retrieve token endpoint for provider '{provider_name}'.")
    token_endpoint = well_known_config["token_endpoint"]
    if not idp_config.client_secret_name:
        raise HTTPException(status_code=500, detail=f"Client secret name not configured for provider '{provider_name}'.")
    client_secret_value = await fetch_gcp_secret(
        secret_id=idp_config.client_secret_name,
        client=sm_client
    )
    if not client_secret_value:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve client secret for provider '{provider_name}'.")
    token_request_payload = {
        "grant_type": "authorization_code",
        "code": request_data.authorization_code,
        "redirect_uri": settings.BFF_OIDC_CALLBACK_URI,
        "client_id": idp_config.client_id,
        "client_secret": client_secret_value,
        "code_verifier": pkce_code_verifier
    }
    try:
        async with httpx.AsyncClient() as client:
            token_response = await client.post(token_endpoint, data=token_request_payload)
            token_response.raise_for_status()
            token_data = token_response.json()
    except httpx.HTTPStatusError as e:
        error_detail = e.response.json() if e.response.content else str(e)
        raise HTTPException(status_code=e.response.status_code, detail={"message": "Failed to exchange code for tokens.", "idp_error": error_detail})
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Token exchange HTTP request failed: {str(e)}")
    id_token = token_data.get("id_token")
    access_token = token_data.get("access_token")
    refresh_token = token_data.get("refresh_token")
    if not id_token:
        raise HTTPException(status_code=500, detail="ID token not found in token response.")
    user_claims = await validate_id_token(
        id_token,
        idp_config,
        well_known_config,
        expected_nonce,
        http_client,
        db
    )
    userinfo_endpoint = well_known_config.get("userinfo_endpoint")
    if not userinfo_endpoint:
        raise HTTPException(status_code=500, detail="Userinfo endpoint not found in .well-known config.")
    try:
        userinfo_headers = {"Authorization": f"Bearer {access_token}"}
        userinfo_response = await http_client.get(userinfo_endpoint, headers=userinfo_headers)
        userinfo_response.raise_for_status()
        userinfo_claims = userinfo_response.json()
    except Exception as e:
        raise HTTPException(status_code=500, detail="Failed to fetch userinfo from IdP.")
    merged_claims = {**user_claims, **userinfo_claims}
    try:
        app_user = await jit_provision_user(idp_config, merged_claims, db_pg_session)
    except HTTPException as e:
        if e.status_code == 409:
            return OIDCTokenExchangeResponse(status="email_conflict", message=e.detail, user_info=None)
        raise e
    if refresh_token and idp_config.supports_refresh_token:
        if settings.REFRESH_TOKEN_KMS_KEY_ID:
            from app.utils.kms_utils import encrypt_data_with_kms
            try:
                encrypted_rt_bytes = await encrypt_data_with_kms(
                    kms_client=kms_client,
                    kms_key_id=settings.REFRESH_TOKEN_KMS_KEY_ID,
                    plaintext=refresh_token
                )
                from sqlalchemy.sql import text as sql_text
                update_link_query = sql_text("""
                    UPDATE user_provider_links
                    SET encrypted_refresh_token = :encrypted_refresh_token, updated_at = NOW()
                    WHERE user_id = :user_id AND provider_id = :provider_id
                """)
                await db_pg_session.execute(
                    update_link_query,
                    {
                        "encrypted_refresh_token": encrypted_rt_bytes,
                        "user_id": app_user.id,
                        "provider_id": idp_config.id
                    }
                )
            except Exception:
                pass
    return OIDCTokenExchangeResponse(
        status="success",
        message="User authenticated successfully.",
        user_info=app_user
    )

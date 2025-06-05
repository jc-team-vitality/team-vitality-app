from fastapi import APIRouter, HTTPException, Path, Body, Depends
from google.cloud import firestore_v1, secretmanager_v1
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import HttpUrl
import httpx
from google.cloud import kms_v1
import secrets
import hashlib
import base64
from urllib.parse import urlencode
from sqlalchemy.sql import text as sql_text
from uuid import UUID

from app.models import OIDCInitiateLoginResponse, OIDCTokenExchangeRequest, OIDCTokenExchangeResponse, OIDCInitiateLinkAccountRequest, AppUser
from app.core.config import settings
from app.db_clients import get_firestore_db, get_secret_manager_client, get_async_db_session, get_kms_client
from app.services.oidc_service import (
    get_identity_provider_config_from_db,
    cache_oidc_state,
    get_cached_oidc_state,
    fetch_idp_well_known_config_impl,
    validate_id_token,
    jit_provision_user,
    fetch_gcp_secret,
    process_account_link,
    derive_roles_from_idp_claims
)
from app.utils.kms_utils import encrypt_data_with_kms

router = APIRouter()

@router.post("/initiate-login/{provider_name}", response_model=OIDCInitiateLoginResponse)
async def initiate_oidc_login(
    provider_name: str = Path(..., description="The common name of the identity provider (e.g., 'google')"),
    db: firestore_v1.AsyncClient = Depends(get_firestore_db),
    db_pg_session: AsyncSession = Depends(get_async_db_session)
):
    """
    Initiates the OIDC login flow for a given identity provider.

    This endpoint generates the necessary OIDC state, nonce, and PKCE code challenge, caches them,
    and constructs the authorization URL for the client to redirect the user to the IdP's login page.
    Now uses the authorization endpoint from the provider's .well-known config.
    """
    # --- Retrieve and validate the IdP configuration ---
    idp_config = await get_identity_provider_config_from_db(provider_name, db_pg_session)
    if not idp_config or not idp_config.is_active:
        raise HTTPException(status_code=404, detail=f"Provider '{provider_name}' not found or not active.")

    # --- Generate OIDC state, nonce, and PKCE code challenge ---
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    code_verifier = secrets.token_urlsafe(64)
    code_challenge_hash = hashlib.sha256(code_verifier.encode('utf-8')).digest()
    code_challenge = base64.urlsafe_b64encode(code_challenge_hash).decode('utf-8').rstrip('=')

    # --- Cache the OIDC state for later validation ---
    await cache_oidc_state(
        state, 
        nonce, 
        code_verifier, 
        provider_name, 
        db, # Firestore client
        flow_type="login", # Explicitly set flow_type
        linking_app_user_id=None
    )

    # --- Fetch the authorization endpoint from the provider's .well-known config ---
    well_known_config = await fetch_idp_well_known_config_impl(idp_config.well_known_uri, db)
    authorization_endpoint = well_known_config.get("authorization_endpoint")
    if not authorization_endpoint:
        raise HTTPException(status_code=500, detail=f"Could not retrieve authorization endpoint for provider '{provider_name}'.")

    # --- Build the authorization URL for the IdP ---
    bff_callback_uri = settings.BFF_OIDC_CALLBACK_URI
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
    authorization_url = f"{authorization_endpoint}?{query_string}"

    # --- Return the authorization URL and state to the client ---
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
    """
    Exchanges an OIDC authorization code for tokens and provisions the user in the application.

    This endpoint validates the OIDC state, exchanges the code for tokens, validates the ID token,
    fetches user info, and provisions the user in the app database. If a refresh token is present and supported,
    it is encrypted and stored for future use.
    """
    # --- Validate the OIDC state and retrieve cached data ---
    cached_state_data = await get_cached_oidc_state(request_data.state, db)
    if not cached_state_data:
        raise HTTPException(status_code=400, detail="Invalid or expired state parameter. Login flow may have timed out.")
    provider_name = cached_state_data["provider_name"]
    expected_nonce = cached_state_data["nonce"]
    pkce_code_verifier = cached_state_data["pkce_code_verifier"]
    flow_type = cached_state_data.get("flow_type", "login")
    linking_app_user_id_str = cached_state_data.get("linking_app_user_id")

    # --- Retrieve IdP configuration and .well-known endpoints ---
    idp_config = await get_identity_provider_config_from_db(provider_name, db_pg_session)
    if not idp_config:
        raise HTTPException(status_code=500, detail=f"Configuration for provider '{provider_name}' not found unexpectedly.")
    well_known_config = await fetch_idp_well_known_config_impl(idp_config.well_known_uri, db, http_client)
    if not well_known_config or not well_known_config.get("token_endpoint"):
        raise HTTPException(status_code=500, detail=f"Could not retrieve token endpoint for provider '{provider_name}'.")
    token_endpoint = well_known_config["token_endpoint"]

    # --- Retrieve client secret from Secret Manager ---
    if not idp_config.client_secret_name:
        raise HTTPException(status_code=500, detail=f"Client secret name not configured for provider '{provider_name}'.")
    client_secret_value = await fetch_gcp_secret(
        secret_id=idp_config.client_secret_name,
        client=sm_client
    )
    if not client_secret_value:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve client secret for provider '{provider_name}'.")

    # --- Exchange authorization code for tokens ---
    token_request_payload = {
        "grant_type": "authorization_code",
        "code": request_data.authorization_code,
        "redirect_uri": settings.BFF_OIDC_CALLBACK_URI,
        "client_id": idp_config.client_id,
        "client_secret": client_secret_value,
        "code_verifier": pkce_code_verifier
    }

    # --- Handle token exchange with the IdP ---
    try:
        token_response = await http_client.post(token_endpoint, data=token_request_payload)
        token_response.raise_for_status()  # Raises an exception for 4XX/5XX responses
        token_data = token_response.json()
    except httpx.HTTPStatusError as e:
        # Attempt to parse JSON error detail from IdP if available
        error_detail = {}
        try:
            if e.response.content:
                error_detail = e.response.json()
        except Exception: # If response is not JSON or other parsing error
            error_detail = {"raw_response": e.response.text[:500]} # Truncate if very long

        # Specific handling for invalid_grant (already present in your full file, ensure it stays)
        if e.response.status_code == 400 and error_detail.get("error") == "invalid_grant":
            # (The logic for clearing the stored token via nested transaction would be here,
            #  followed by raising this specific HTTPException)
            print(f"Refresh token (or auth code) for provider {idp_config.name} is invalid. Clearing stored token if applicable.")
            # ... (code to clear token, ideally in a nested transaction if this is for refresh token grant)
            # For now, focus on the exception being raised from here:
            raise HTTPException(status_code=400, detail={"message": "Authorization code or refresh token is invalid or expired.", "idp_error": error_detail})
        
        # General HTTP error from IdP for token exchange
        raise HTTPException(status_code=e.response.status_code, detail={"message": "Failed to exchange code for tokens with IdP.", "idp_error": error_detail})
    except httpx.RequestError as e:
        # For network errors, timeouts, etc., during the request to the IdP
        print(f"Network error during token exchange with {token_endpoint}: {e}")
        raise HTTPException(status_code=503, detail=f"Network error during token exchange: {str(e)}") # Service Unavailable
    except Exception as e:
        # For other unexpected errors, like JSONDecodeError if response is not JSON and not an HTTPStatusError
        print(f"Unexpected error during token exchange process: {e}")
        raise HTTPException(status_code=500, detail=f"Token exchange process failed due to an unexpected error: {str(e)}")

    # --- Extract tokens from response ---
    id_token = token_data.get("id_token")
    access_token = token_data.get("access_token")
    refresh_token = token_data.get("refresh_token")
    if not id_token:
        raise HTTPException(status_code=500, detail="ID token not found in token response.")

    # --- Validate the ID token and extract user claims ---
    user_claims = await validate_id_token(
        id_token,
        idp_config,
        well_known_config,
        expected_nonce,
        http_client,
        db
    )

    # --- Fetch userinfo from the IdP ---
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

    # --- Merge claims from ID token and userinfo endpoint ---
    merged_claims = {**user_claims, **userinfo_claims}

    final_app_user = None
    response_message = ""

    if flow_type == "link_account":
        if not linking_app_user_id_str:
            raise HTTPException(status_code=400, detail="Invalid state: linking_app_user_id missing for account linking flow.")
        current_app_user_id = UUID(str(linking_app_user_id_str))
        try:
            await process_account_link(idp_config, merged_claims, current_app_user_id, db_pg_session)
            # Fetch the app_user to return in response
            user_query = sql_text("SELECT id, email, first_name, last_name, created_at, updated_at, roles FROM app_users WHERE id = :user_id")
            result = await db_pg_session.execute(user_query, {"user_id": current_app_user_id})
            user_row = result.fetchone()
            if user_row:
                app_user_with_db_roles = AppUser.model_validate(dict(user_row._mapping))
            else:
                app_user_with_db_roles = None
            response_message = "Account linked successfully."
        except HTTPException as e:
            raise e
    elif flow_type == "login":
        try:
            app_user_with_db_roles = await jit_provision_user(idp_config, merged_claims, db_pg_session)
            response_message = "User authenticated successfully."
        except HTTPException as e:
            if e.status_code == 409:
                return OIDCTokenExchangeResponse(status="email_conflict", message=e.detail, user_info=None)
            raise e
    else:
        raise HTTPException(status_code=500, detail="Unknown flow type in OIDC state.")

    # --- Derive additional roles from IdP claims and merge with DB roles ---
    if not app_user_with_db_roles:
        raise HTTPException(status_code=500, detail="User processing failed prior to role merging.")
    additional_claim_derived_roles = await derive_roles_from_idp_claims(
        idp_config=idp_config,
        user_claims=merged_claims
    )
    final_effective_roles_set = set(app_user_with_db_roles.roles) | set(additional_claim_derived_roles)
    final_effective_roles_list = sorted(list(final_effective_roles_set))
    final_app_user_for_response = app_user_with_db_roles.model_copy(update={"roles": final_effective_roles_list})

    # --- Encrypt and store refresh token if present and supported ---
    if final_app_user_for_response and refresh_token and idp_config.supports_refresh_token:
        print(f"Attempting to encrypt and store refresh token for user {final_app_user_for_response.id}, provider {idp_config.name}, flow {flow_type}")
        if not settings.REFRESH_TOKEN_KMS_KEY_ID:
            print("WARNING: REFRESH_TOKEN_KMS_KEY_ID not set. Cannot encrypt refresh token.")
        else:
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
                    WHERE user_id = :user_id AND provider_id = :provider_id AND provider_user_id = :provider_user_id_claim
                """)
                provider_user_id_claim = merged_claims.get("sub")
                await db_pg_session.execute(
                    update_link_query,
                    {
                        "encrypted_refresh_token": encrypted_rt_bytes,
                        "user_id": final_app_user_for_response.id,
                        "provider_id": idp_config.id,
                        "provider_user_id_claim": provider_user_id_claim
                    }
                )
                print(f"Encrypted refresh token stored for user {final_app_user_for_response.id}, provider {idp_config.name}")
            except Exception as e:
                print(f"ERROR: Failed to encrypt and store refresh token during {flow_type} flow: {e}")

    if final_app_user_for_response:
        return OIDCTokenExchangeResponse(
            status="success",
            message=response_message,
            user_info=final_app_user_for_response
        )
    else:
        raise HTTPException(status_code=500, detail="User processing failed after OIDC exchange.")

@router.post(
    "/link-account/initiate/{provider_name}",
    response_model=OIDCInitiateLoginResponse, # Same response as normal login init
    summary="Initiate OIDC flow to link an external IdP to an existing authenticated user account",
    tags=["OIDC Authentication", "Account Linking"]
)
async def initiate_oidc_link_account(
    provider_name: str = Path(..., description="The common name of the identity provider to link (e.g., 'google')"),
    link_request: OIDCInitiateLinkAccountRequest = Body(...),
    db: firestore_v1.AsyncClient = Depends(get_firestore_db),
    db_pg_session: AsyncSession = Depends(get_async_db_session)
):
    """
    Initiates the OIDC account linking flow for an authenticated user.

    This endpoint generates the necessary OIDC state, nonce, and PKCE code challenge, caches them,
    and constructs the authorization URL for the client to redirect the user to the IdP's login page.
    The flow_type is set to 'link_account' to indicate this is an account linking operation.
    """
    # 1. TODO: Validate app_user_id exists in app_users table? For now, trust the BFF.
    print(f"Initiating account link for app_user_id: {link_request.app_user_id} with provider: {provider_name}")

    # --- Retrieve and validate the IdP configuration ---
    idp_config = await get_identity_provider_config_from_db(provider_name, db_pg_session)
    if not idp_config or not idp_config.is_active:
        raise HTTPException(status_code=404, detail=f"Provider '{provider_name}' not found or not active for linking.")

    # --- Generate OIDC state, nonce, and PKCE code challenge ---
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    code_verifier = secrets.token_urlsafe(64)
    code_challenge_hash = hashlib.sha256(code_verifier.encode('utf-8')).digest()
    code_challenge = base64.urlsafe_b64encode(code_challenge_hash).decode('utf-8').rstrip('=')

    # --- Cache the OIDC state for later validation ---
    await cache_oidc_state(
        state=state,
        nonce=nonce,
        pkce_code_verifier=code_verifier,
        provider_name=provider_name,
        db=db, # Firestore client
        flow_type="link_account", # Specify flow type
        linking_app_user_id=link_request.app_user_id # Pass the current user's ID
    )

    # --- Fetch the authorization endpoint from the provider's .well-known config ---
    well_known_config = await fetch_idp_well_known_config_impl(idp_config.well_known_uri, db)
    authorization_endpoint = well_known_config.get("authorization_endpoint")
    if not authorization_endpoint:
        raise HTTPException(status_code=500, detail=f"Could not retrieve authorization endpoint for provider '{provider_name}'.")

    # --- Build the authorization URL for the IdP ---
    bff_callback_uri = settings.BFF_OIDC_CALLBACK_URI
    params = {
        "client_id": idp_config.client_id,
        "response_type": "code",
        "scope": idp_config.scopes, # Consider if different scopes are needed for linking
        "redirect_uri": bff_callback_uri,
        "state": state,
        "nonce": nonce,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        # Optionally: "prompt": "consent" or "select_account" for linking
    }
    query_string = urlencode(params)
    authorization_url = f"{authorization_endpoint}?{query_string}"

    # --- Return the authorization URL and state to the client ---
    return OIDCInitiateLoginResponse(authorization_url=authorization_url, state=state)

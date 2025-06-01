# Standard library imports
import secrets
import hashlib
import base64
from uuid import UUID
from typing import Optional
from datetime import datetime, timezone, timedelta
from urllib.parse import urlencode, urljoin

# Third-party imports
from fastapi import FastAPI, HTTPException, Path, Depends, Body
import httpx
import jwt
from google.cloud import firestore_v1
from pydantic.networks import HttpUrl

# Local application imports
from .core.config import settings
from .db_clients import get_firestore_db
from .models import (
    IdentityProviderConfig,
    OIDCInitiateLoginResponse,
    OIDCTokenExchangeRequest,
    OIDCTokenExchangeResponse,
    AppUser,
    OIDCStateCache
)

app = FastAPI(title=settings.PROJECT_NAME)

@app.get("/health", tags=["Health"])
async def health_check():
    return {"status": "healthy", "project_name": settings.PROJECT_NAME}

# Placeholder for actual DB lookup for IdentityProviderConfig
async def get_identity_provider_config_from_db(provider_name: str) -> Optional[IdentityProviderConfig]:
    # In a real implementation, this would query the PostgreSQL 'identity_providers' table.
    # For now, simulate for a known provider, e.g., 'google'.
    if provider_name == "google":
        # These values would come from the DB based on 'provider_name'
        return IdentityProviderConfig(
            id="some-uuid", # Placeholder
            created_at=datetime.now(timezone.utc), # Placeholder
            updated_at=datetime.now(timezone.utc), # Placeholder
            name="google",
            issuer_uri="https://accounts.google.com", # Example, actual from DB
            well_known_uri="https://accounts.google.com/.well-known/openid-configuration", # Example, actual from DB
            client_id="YOUR_GOOGLE_CLIENT_ID_FROM_DB_CONFIG", # Example, actual from DB
            client_secret_name="google-client-secret-name", # Example, actual from DB
            scopes="openid email profile", # Example, actual from DB
            is_active=True,
            supports_refresh_token=True
        )
    return None

# --- Updated cache_oidc_state function (used by initiate_oidc_login) ---
async def cache_oidc_state(
    state: str,
    nonce: str,
    pkce_code_verifier: str,
    provider_name: str,
    db: firestore_v1.AsyncClient
):
    expires_at_dt = datetime.now(timezone.utc) + timedelta(seconds=settings.OIDC_STATE_TTL_SECONDS)
    state_data = OIDCStateCache(
        state=state,
        nonce=nonce,
        pkce_code_verifier=pkce_code_verifier,
        provider_name=provider_name,
        expires_at=expires_at_dt
    )
    doc_ref = db.collection(settings.FIRESTORE_OIDC_STATE_COLLECTION).document(state)
    await doc_ref.set(state_data.model_dump())
    print(f"OIDC state cached in Firestore for state: {state}")

# --- Updated get_cached_oidc_state function (used by oidc_token_exchange) ---
async def get_cached_oidc_state(
    state: str,
    db: firestore_v1.AsyncClient
) -> Optional[dict]:
    doc_ref = db.collection(settings.FIRESTORE_OIDC_STATE_COLLECTION).document(state)
    doc_snapshot = await doc_ref.get()
    if doc_snapshot.exists:
        cached_data = OIDCStateCache.model_validate(doc_snapshot.to_dict())
        await doc_ref.delete()
        print(f"OIDC state retrieved and deleted from Firestore for state: {state}")
        return {
            "nonce": cached_data.nonce,
            "pkce_code_verifier": cached_data.pkce_code_verifier,
            "provider_name": cached_data.provider_name
        }
    else:
        print(f"OIDC state not found or already used/expired for state: {state}")
        return None

# Placeholder for fetching IdP .well-known configuration
async def fetch_idp_well_known_config(well_known_uri: HttpUrl) -> Optional[dict]:
    print(f"HTTP_TODO: Fetch .well-known config from: {well_known_uri}")
    if "accounts.google.com" in str(well_known_uri):
        return {
            "issuer": "https://accounts.google.com",
            "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
            "token_endpoint": "https://oauth2.googleapis.com/token",
            "userinfo_endpoint": "https://openidconnect.googleapis.com/v1/userinfo",
            "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs",
        }
    return None

# Placeholder for JIT User Provisioning and linking
async def jit_provision_user(idp_config: IdentityProviderConfig, user_claims: dict) -> AppUser:
    print(f"JIT_DB_TODO: Implement JIT provisioning for user claims: {user_claims} from provider: {idp_config.name}")
    simulated_user_id = UUID('d9c09db0-045e-4b6f-8f8d-0761974649c3')
    return AppUser(
        id=simulated_user_id,
        email=user_claims.get("email", "test@example.com"),
        first_name=user_claims.get("given_name"),
        last_name=user_claims.get("family_name"),
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc)
    )

# Placeholder for ID Token Validation
async def validate_id_token(id_token: str, idp_config: IdentityProviderConfig, well_known_config: dict, expected_nonce: str) -> dict:
    print(f"JWT_VALIDATE_TODO: Implement robust ID token validation for token: {id_token[:20]}... and nonce: {expected_nonce}")
    try:
        decoded_token = jwt.decode(id_token, options={"verify_signature": False, "verify_aud": False, "verify_exp": False})
        if decoded_token.get("nonce") != expected_nonce:
            raise HTTPException(status_code=400, detail="ID token nonce mismatch.")
        return decoded_token
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid ID token: {str(e)}")

@app.post("/oidc/initiate-login/{provider_name}", response_model=OIDCInitiateLoginResponse, tags=["OIDC Authentication"])
async def initiate_oidc_login(
    provider_name: str = Path(..., description="The common name of the identity provider (e.g., 'google')"),
    db: firestore_v1.AsyncClient = Depends(get_firestore_db)
):
    idp_config = await get_identity_provider_config_from_db(provider_name)
    if not idp_config or not idp_config.is_active:
        raise HTTPException(status_code=404, detail=f"Provider '{provider_name}' not found or not active.")
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
        actual_authorization_endpoint = urljoin(authorization_endpoint_base, "authorize")
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

@app.post("/oidc/token/exchange", response_model=OIDCTokenExchangeResponse, tags=["OIDC Authentication"])
async def oidc_token_exchange(
    request_data: OIDCTokenExchangeRequest = Body(...),
    db: firestore_v1.AsyncClient = Depends(get_firestore_db)
):
    cached_state_data = await get_cached_oidc_state(request_data.state, db)
    if not cached_state_data:
        raise HTTPException(status_code=400, detail="Invalid or expired state parameter. Login flow may have timed out.")

    provider_name = cached_state_data["provider_name"]
    expected_nonce = cached_state_data["nonce"]
    pkce_code_verifier = cached_state_data["pkce_code_verifier"]

    idp_config = await get_identity_provider_config_from_db(provider_name)
    if not idp_config:
        raise HTTPException(status_code=500, detail=f"Configuration for provider '{provider_name}' not found unexpectedly.")

    well_known_config = await fetch_idp_well_known_config(idp_config.well_known_uri)
    if not well_known_config or not well_known_config.get("token_endpoint"):
        raise HTTPException(status_code=500, detail=f"Could not retrieve token endpoint for provider '{provider_name}'.")

    token_endpoint = well_known_config["token_endpoint"]
    client_secret_value = "FETCH_FROM_GCP_SECRET_MANAGER_USING_idp_config.client_secret_name"
    print(f"SECRET_FETCH_TODO: Fetch secret '{idp_config.client_secret_name}' from GCP Secret Manager.")

    token_request_payload = {
        "grant_type": "authorization_code",
        "code": request_data.authorization_code,
        "redirect_uri": settings.BFF_OIDC_CALLBACK_URI,
        "client_id": idp_config.client_id,
        "client_secret": client_secret_value,
        "code_verifier": pkce_code_verifier
    }

    async with httpx.AsyncClient() as client:
        try:
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

    user_claims = await validate_id_token(id_token, idp_config, well_known_config, expected_nonce)

    try:
        app_user = await jit_provision_user(idp_config, user_claims)
    except HTTPException as e:
        if e.status_code == 409:
            return OIDCTokenExchangeResponse(status="email_conflict", message=e.detail, user_info=None)
        raise e

    if refresh_token and idp_config.supports_refresh_token:
        print(f"REFRESH_TOKEN_TODO: Encrypt refresh token and store its reference for user {app_user.id} and provider {idp_config.name}.")
        pass

    return OIDCTokenExchangeResponse(
        status="success",
        message="User authenticated successfully.",
        user_info=app_user
    )

# Further imports and router inclusions will go here later

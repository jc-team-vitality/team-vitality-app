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
from google.cloud import secretmanager_v1
from pydantic import HttpUrl # Ensure HttpUrl is imported for function signature
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql import text

# Local application imports
from .core.config import settings
from .db_clients import get_firestore_db, get_secret_manager_client, get_async_db_session, get_kms_client
from .models import (
    IdentityProviderConfig,
    OIDCInitiateLoginResponse,
    OIDCTokenExchangeRequest,
    OIDCTokenExchangeResponse,
    AppUser,
    OIDCStateCache,
    OIDCWellKnownCache,
    JWKSCache, # Add JWKSCache import
    InternalTokenRefreshRequest, # Add InternalTokenRefreshRequest import
    InternalTokenRefreshResponse  # Add InternalTokenRefreshResponse import
)
from .utils.kms_utils import encrypt_data_with_kms, decrypt_data_with_kms
from google.cloud import kms_v1
from .routers import idp_configs as idp_configs_router

app = FastAPI(title=settings.PROJECT_NAME)

app.include_router(
    idp_configs_router.router,
    prefix="/admin/identity-providers",
    tags=["Admin - Identity Provider Configurations"]
)

@app.get("/health", tags=["Health"])
async def health_check():
    return {"status": "healthy", "project_name": settings.PROJECT_NAME}

# Dependency for httpx.AsyncClient
async def get_http_client() -> httpx.AsyncClient:
    return httpx.AsyncClient()

# --- Updated get_identity_provider_config_from_db: fetch from PostgreSQL ---
async def get_identity_provider_config_from_db(
    provider_name: str,
    db_session: AsyncSession
) -> Optional[IdentityProviderConfig]:
    query = text("""
        SELECT id, name, issuer_uri, well_known_uri, client_id, 
               client_secret_name, scopes, is_active, supports_refresh_token,
               created_at, updated_at
        FROM identity_providers
        WHERE name = :provider_name AND is_active = TRUE
    """)
    try:
        result = await db_session.execute(query, {"provider_name": provider_name})
        row = result.fetchone()
        if row:
            return IdentityProviderConfig.model_validate(dict(row._mapping))
        return None
    except Exception as e:
        print(f"Database error fetching IdP config for '{provider_name}': {e}")
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

# --- Firestore-cached OIDC .well-known config fetch ---
async def fetch_idp_well_known_config_impl(
    well_known_uri: HttpUrl,
    db: firestore_v1.AsyncClient,
    http_client: httpx.AsyncClient
) -> Optional[dict]:
    cache_key = str(well_known_uri).replace("://", "_").replace("/", "_").replace(".", "_").replace(":", "_")
    doc_ref = db.collection(settings.FIRESTORE_WELL_KNOWN_CONFIGS_COLLECTION).document(cache_key)
    doc_snapshot = await doc_ref.get()
    if doc_snapshot.exists:
        try:
            cached_config = OIDCWellKnownCache.model_validate(doc_snapshot.to_dict())
            if cached_config.expires_at > datetime.now(timezone.utc):
                print(f"Found valid .well-known config in cache for: {well_known_uri}")
                return cached_config.config_data
            else:
                print(f"Cached .well-known config expired for: {well_known_uri}")
        except Exception as e:
            print(f"Error validating cached .well-known config: {e}. Fetching anew.")
    print(f"Fetching .well-known config from: {well_known_uri}")
    try:
        response = await http_client.get(str(well_known_uri))
        response.raise_for_status()
        fetched_config_data = response.json()
    except httpx.HTTPStatusError as e:
        print(f"HTTP error fetching .well-known config from {well_known_uri}: {e}")
        raise HTTPException(status_code=e.response.status_code, detail=f"Failed to fetch OIDC discovery document: {e.response.text}")
    except Exception as e:
        print(f"Error fetching or parsing .well-known config from {well_known_uri}: {e}")
        raise HTTPException(status_code=500, detail="Failed to process OIDC discovery document.")
    expires_at_dt = datetime.now(timezone.utc) + timedelta(seconds=settings.WELL_KNOWN_CONFIG_CACHE_TTL_SECONDS)
    new_cached_config = OIDCWellKnownCache(config_data=fetched_config_data, expires_at=expires_at_dt)
    await doc_ref.set(new_cached_config.model_dump())
    print(f"Cached new .well-known config for: {well_known_uri}")
    return fetched_config_data

# --- JWKS Firestore-cached fetch helper ---
async def fetch_and_cache_jwks(
    jwks_uri: HttpUrl,
    db: firestore_v1.AsyncClient,
    http_client: httpx.AsyncClient
) -> list[dict]:
    cache_key = str(jwks_uri).replace("://", "_").replace("/", "_").replace(".", "_").replace(":", "_")
    doc_ref = db.collection(settings.FIRESTORE_JWKS_CACHE_COLLECTION).document(cache_key)
    doc_snapshot = await doc_ref.get()
    if doc_snapshot.exists:
        try:
            cached_jwks_data = JWKSCache.model_validate(doc_snapshot.to_dict())
            if cached_jwks_data.expires_at > datetime.now(timezone.utc):
                print(f"Found valid JWKS in cache for: {jwks_uri}")
                return cached_jwks_data.keys
            else:
                print(f"Cached JWKS expired for: {jwks_uri}")
        except Exception as e:
            print(f"Error validating cached JWKS: {e}. Fetching anew.")
    print(f"Fetching JWKS from: {jwks_uri}")
    try:
        response = await http_client.get(str(jwks_uri))
        response.raise_for_status()
        fetched_jwks = response.json()
        if "keys" not in fetched_jwks or not isinstance(fetched_jwks["keys"], list):
            raise HTTPException(status_code=500, detail="Invalid JWKS format received from provider.")
        jwks_keys_list = fetched_jwks["keys"]
    except httpx.HTTPStatusError as e:
        print(f"HTTP error fetching JWKS from {jwks_uri}: {e}")
        raise HTTPException(status_code=e.response.status_code, detail=f"Failed to fetch JWKS: {e.response.text}")
    except Exception as e:
        print(f"Error fetching or parsing JWKS from {jwks_uri}: {e}")
        raise HTTPException(status_code=500, detail="Failed to process JWKS.")
    expires_at_dt = datetime.now(timezone.utc) + timedelta(seconds=settings.JWKS_CACHE_TTL_SECONDS)
    new_cached_jwks = JWKSCache(
        keys=jwks_keys_list,
        expires_at=expires_at_dt
    )
    await doc_ref.set(new_cached_jwks.model_dump())
    print(f"Cached new JWKS for: {jwks_uri}")
    return jwks_keys_list

# Placeholder for JIT User Provisioning and linking
async def jit_provision_user(
    idp_config: IdentityProviderConfig,
    user_claims: dict,
    db_session: AsyncSession = Depends(get_async_db_session)
) -> AppUser:
    provider_user_id = user_claims.get("sub")
    email = user_claims.get("email")
    first_name = user_claims.get("given_name")
    last_name = user_claims.get("family_name")

    if not provider_user_id or not email:
        raise HTTPException(status_code=400, detail="Missing required user claims (sub or email) from IdP.")

    # 1. Check for existing UserProviderLink
    link_query = text("""
        SELECT ul.user_id, u.email, u.first_name, u.last_name, u.id, u.created_at, u.updated_at
        FROM user_provider_links ul
        JOIN app_users u ON ul.user_id = u.id
        WHERE ul.provider_id = :provider_id AND ul.provider_user_id = :provider_user_id
    """)
    result = await db_session.execute(link_query, {"provider_id": idp_config.id, "provider_user_id": provider_user_id})
    existing_linked_user_row = result.fetchone()

    if existing_linked_user_row:
        # User found via existing link, convert row to AppUser Pydantic model
        return AppUser.model_validate(dict(existing_linked_user_row._mapping))

    # 2. No link found, check for existing AppUser by email
    email_query = text("SELECT id, email, first_name, last_name, created_at, updated_at FROM app_users WHERE email = :email")
    result = await db_session.execute(email_query, {"email": email})
    existing_email_user_row = result.fetchone()

    if existing_email_user_row:
        # Email conflict: User with this email exists but is not linked to this IdP account.
        raise HTTPException(
            status_code=409,
            detail="An account with this email already exists. Please log in using your original method and link this provider from your account settings."
        )

    # 3. No existing link AND no email conflict: Create new AppUser and UserProviderLink
    new_user_query = text("""
        INSERT INTO app_users (email, first_name, last_name)
        VALUES (:email, :first_name, :last_name)
        RETURNING id, email, first_name, last_name, created_at, updated_at
    """)
    result = await db_session.execute(
        new_user_query,
        {"email": email, "first_name": first_name, "last_name": last_name}
    )
    new_user_row = result.fetchone()
    if not new_user_row:
        raise HTTPException(status_code=500, detail="Failed to create new user record.")
    new_app_user_id = new_user_row.id

    new_link_query = text("""
        INSERT INTO user_provider_links (user_id, provider_id, provider_user_id)
        VALUES (:user_id, :provider_id, :provider_user_id)
    """)
    await db_session.execute(
        new_link_query,
        {"user_id": new_app_user_id, "provider_id": idp_config.id, "provider_user_id": provider_user_id}
    )

    return AppUser.model_validate(dict(new_user_row._mapping))

# Placeholder for ID Token Validation
async def validate_id_token(
    id_token: str,
    idp_config: IdentityProviderConfig,
    well_known_config: dict,
    expected_nonce: str,
    http_client: httpx.AsyncClient,
    db: firestore_v1.AsyncClient
) -> dict:
    if not id_token:
        raise HTTPException(status_code=400, detail="ID token is missing.")

    jwks_uri_str = well_known_config.get("jwks_uri")
    if not jwks_uri_str:
        raise HTTPException(status_code=500, detail="JWKS URI not found in .well-known config.")
    try:
        jwks_uri = HttpUrl(jwks_uri_str)
    except Exception:
        raise HTTPException(status_code=500, detail="Invalid JWKS URI format in .well-known config.")

    # Fetch JWKS keys using Firestore cache
    jwks_keys = await fetch_and_cache_jwks(jwks_uri, db, http_client)

    try:
        unverified_header = jwt.get_unverified_header(id_token)
    except jwt.PyJWTError as e:
        raise HTTPException(status_code=400, detail=f"Invalid ID token header: {e}")

    kid = unverified_header.get("kid")
    if not kid:
        raise HTTPException(status_code=400, detail="ID token header missing 'kid'.")

    matching_key_data = None
    for key_data_item in jwks_keys:
        if key_data_item.get("kid") == kid:
            matching_key_data = key_data_item
            break

    if not matching_key_data:
        raise HTTPException(status_code=400, detail="No matching JWK found for token 'kid'.")

    # Optionally, verify issuer matches well-known config before decoding (defense-in-depth)
    if idp_config.issuer_uri != well_known_config.get("issuer"):
        raise HTTPException(status_code=401, detail="Configured issuer does not match well-known issuer.")

    try:
        public_key = jwt.algorithms.RSAAlgorithm.from_jwk(matching_key_data)
        # SECURE DECODE: verifies signature, audience, issuer, and standard claims
        decoded_token = jwt.decode(
            id_token,
            public_key,
            algorithms=[unverified_header.get("alg", "RS256")],
            audience=idp_config.client_id,
            issuer=idp_config.issuer_uri
        )
        # Nonce check (after successful decode)
        if decoded_token.get("nonce") != expected_nonce:
            raise HTTPException(status_code=400, detail="ID token nonce mismatch.")
        return decoded_token
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="ID token has expired.")
    except jwt.InvalidAudienceError:
        raise HTTPException(status_code=401, detail="Invalid ID token audience.")
    except jwt.InvalidIssuerError:
        raise HTTPException(status_code=401, detail="Invalid ID token issuer.")
    except jwt.MissingRequiredClaimError as e:
        raise HTTPException(status_code=400, detail=f"ID token missing required claim: {e}")
    except jwt.InvalidSignatureError:
        raise HTTPException(status_code=401, detail="Invalid ID token signature.")
    except jwt.PyJWTError as e:
        raise HTTPException(status_code=400, detail=f"Invalid ID token: {e}")
    except Exception as e:
        print(f"Unexpected error during token validation: {e}")
        raise HTTPException(status_code=500, detail="Token validation failed due to an unexpected error.")

@app.post("/oidc/initiate-login/{provider_name}", response_model=OIDCInitiateLoginResponse, tags=["OIDC Authentication"])
async def initiate_oidc_login(
    provider_name: str = Path(..., description="The common name of the identity provider (e.g., 'google')"),
    db: firestore_v1.AsyncClient = Depends(get_firestore_db),
    db_pg_session: AsyncSession = Depends(get_async_db_session)
):
    idp_config = await get_identity_provider_config_from_db(provider_name, db_pg_session)
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
    db: firestore_v1.AsyncClient = Depends(get_firestore_db),
    http_client: httpx.AsyncClient = Depends(get_http_client),
    sm_client: secretmanager_v1.SecretManagerServiceClient = Depends(get_secret_manager_client),
    db_pg_session: AsyncSession = Depends(get_async_db_session),
    kms_client: kms_v1.KeyManagementServiceClient = Depends(get_kms_client) # Inject KMS client
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

    user_claims = await validate_id_token(
        id_token,
        idp_config,
        well_known_config,
        expected_nonce,
        http_client,
        db
    )

    # --- Fetch and merge /userinfo claims ---
    userinfo_endpoint = well_known_config.get("userinfo_endpoint")
    if not userinfo_endpoint:
        raise HTTPException(status_code=500, detail="Userinfo endpoint not found in .well-known config.")
    try:
        userinfo_headers = {"Authorization": f"Bearer {access_token}"}
        userinfo_response = await http_client.get(userinfo_endpoint, headers=userinfo_headers)
        userinfo_response.raise_for_status()
        userinfo_claims = userinfo_response.json()
    except Exception as e:
        print(f"Failed to fetch userinfo: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch userinfo from IdP.")

    # Merge userinfo_claims into user_claims (userinfo takes precedence)
    merged_claims = {**user_claims, **userinfo_claims}

    try:
        app_user = await jit_provision_user(idp_config, merged_claims, db_pg_session)
    except HTTPException as e:
        if e.status_code == 409:
            return OIDCTokenExchangeResponse(status="email_conflict", message=e.detail, user_info=None)
        raise e

    if refresh_token and idp_config.supports_refresh_token:
        print(f"Attempting to encrypt and store refresh token for user {app_user.id}, provider {idp_config.name}")
        if not settings.REFRESH_TOKEN_KMS_KEY_ID:
            print("WARNING: REFRESH_TOKEN_KMS_KEY_ID not set. Cannot encrypt refresh token.")
        else:
            try:
                encrypted_rt_bytes = await encrypt_data_with_kms(
                    kms_client=kms_client,
                    kms_key_id=settings.REFRESH_TOKEN_KMS_KEY_ID,
                    plaintext=refresh_token
                )
                update_link_query = text("""
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
                print(f"Encrypted refresh token stored for user {app_user.id}, provider {idp_config.name}")
            except Exception as e:
                print(f"ERROR: Failed to encrypt and store refresh token: {e}")

    return OIDCTokenExchangeResponse(
        status="success",
        message="User authenticated successfully.",
        user_info=app_user
    )

async def fetch_gcp_secret(
    secret_id: str,
    client: secretmanager_v1.SecretManagerServiceClient, # Injected client
    project_id: str = settings.GCP_PROJECT_ID, # Use from settings
    version_id: str = "latest"
) -> Optional[str]:
    if not project_id:
        print("ERROR: GCP_PROJECT_ID not configured for fetching secret.")
        return None
    secret_name = f"projects/{project_id}/secrets/{secret_id}/versions/{version_id}"
    try:
        response = client.access_secret_version(request={"name": secret_name})
        payload = response.payload.data.decode("UTF-8")
        return payload
    except Exception as e:
        print(f"Error accessing secret '{secret_id}' in project '{project_id}': {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve critical secret: {secret_id}")

@app.post("/internal/token/refresh", response_model=InternalTokenRefreshResponse, tags=["Internal API", "OIDC Authentication"])
async def internal_refresh_access_token(
    request_data: InternalTokenRefreshRequest = Body(...),
    db_pg_session: AsyncSession = Depends(get_async_db_session),
    db_firestore: firestore_v1.AsyncClient = Depends(get_firestore_db),
    http_client: httpx.AsyncClient = Depends(get_http_client),
    sm_client: secretmanager_v1.SecretManagerServiceClient = Depends(get_secret_manager_client),
    kms_client: kms_v1.KeyManagementServiceClient = Depends(get_kms_client)
):
    # 1. Fetch IdP Configuration (now from DB)
    idp_config = await get_identity_provider_config_from_db(request_data.provider_name, db_pg_session)
    if not idp_config or not idp_config.is_active:
        raise HTTPException(status_code=404, detail=f"Provider '{request_data.provider_name}' not found or not active.")
    
    if not idp_config.supports_refresh_token:
        raise HTTPException(status_code=400, detail=f"Refresh token not supported by provider '{request_data.provider_name}'.")

    # 2. Fetch UserProviderLink to get the encrypted refresh token
    link_query = text("""
        SELECT encrypted_refresh_token 
        FROM user_provider_links
        WHERE user_id = :user_id AND provider_id = :provider_id
    """)
    result = await db_pg_session.execute(link_query, {"user_id": request_data.user_id, "provider_id": idp_config.id})
    link_row = result.fetchone()

    if not link_row or not link_row.encrypted_refresh_token:
        raise HTTPException(status_code=404, detail="No refresh token found for this user and provider, or user/provider link does not exist.")
    
    encrypted_rt_bytes = link_row.encrypted_refresh_token

    # 3. Fetch Client Secret
    if not idp_config.client_secret_name:
        raise HTTPException(status_code=500, detail=f"Client secret name not configured for provider '{request_data.provider_name}'.")
    client_secret_value = await fetch_gcp_secret(
        secret_id=idp_config.client_secret_name,
        client=sm_client
    )
    if not client_secret_value:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve client secret for provider '{request_data.provider_name}'.")

    # 4. Decrypt Refresh Token using KMS
    if not settings.REFRESH_TOKEN_KMS_KEY_ID:
        raise HTTPException(status_code=500, detail="Refresh token KMS key not configured.")
    
    try:
        decrypted_refresh_token = await decrypt_data_with_kms(
            kms_client=kms_client,
            kms_key_id=settings.REFRESH_TOKEN_KMS_KEY_ID,
            ciphertext=encrypted_rt_bytes
        )
    except Exception as e:
        print(f"Failed to decrypt refresh token for user {request_data.user_id}, provider {request_data.provider_name}: {e}")
        raise HTTPException(status_code=500, detail="Failed to process stored refresh token.")

    # 5. Fetch IdP .well-known config for token_endpoint
    well_known_config = await fetch_idp_well_known_config_impl(idp_config.well_known_uri, db_firestore, http_client)
    if not well_known_config or not well_known_config.get("token_endpoint"):
        raise HTTPException(status_code=500, detail=f"Could not retrieve token endpoint for provider '{request_data.provider_name}'.")
    token_endpoint = well_known_config["token_endpoint"]

    # 6. Call IdP Token Endpoint with refresh_token grant
    refresh_payload = {
        "grant_type": "refresh_token",
        "refresh_token": decrypted_refresh_token,
        "client_id": idp_config.client_id,
        "client_secret": client_secret_value,
        # "scope": idp_config.scopes # Uncomment if needed by IdP
    }

    try:
        token_response = await http_client.post(token_endpoint, data=refresh_payload)
        token_response.raise_for_status()
        new_token_data = token_response.json()
    except httpx.HTTPStatusError as e:
        error_detail = e.response.json() if e.response.content else str(e)
        if e.response.status_code == 400 and error_detail.get("error") == "invalid_grant":
            print(f"REFRESH_TOKEN_INVALID_GRANT_TODO: Refresh token for user {request_data.user_id}, provider {request_data.provider_name} is invalid. Consider deleting it.")
            raise HTTPException(status_code=400, detail={"message": "Refresh token is invalid or expired.", "idp_error": error_detail})
        raise HTTPException(status_code=e.response.status_code, detail={"message": "Failed to refresh access token.", "idp_error": error_detail})
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Access token refresh HTTP request failed: {str(e)}")

    new_access_token = new_token_data.get("access_token")
    new_expires_in = new_token_data.get("expires_in")
    new_scopes = new_token_data.get("scope")

    if not new_access_token:
        raise HTTPException(status_code=500, detail="New access token not found in refresh response.")

    # REFRESH_TOKEN_ROTATION_TODO:
    # If new_token_data contains a 'refresh_token', it means the IdP rotated it.
    # The new refresh_token should be encrypted using KMS and updated in the
    # user_provider_links table for this user_id and provider_id.
    # This is a critical step if the IdP supports refresh token rotation.
    if "refresh_token" in new_token_data:
        print(f"REFRESH_TOKEN_ROTATION_TODO: New refresh token received. Encrypt and update for user {request_data.user_id}, provider {request_data.provider_name}.")

    return InternalTokenRefreshResponse(
        access_token=new_access_token,
        expires_in=new_expires_in,
        token_type=new_token_data.get("token_type", "Bearer"),
        scopes=new_scopes
    )

# Further imports and router inclusions will go here later

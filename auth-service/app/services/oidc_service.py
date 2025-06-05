from app.core.config import settings
from app.models import (
    IdentityProviderConfig, OIDCStateCache, OIDCWellKnownCache, JWKSCache, AppUser
)
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql import text
from google.cloud import firestore_v1
from google.cloud import secretmanager_v1
from google.cloud import kms_v1
from pydantic import HttpUrl
from fastapi import HTTPException
import httpx
from typing import Optional, Literal, List, Dict, Any  # Add Literal, List, Dict, Any
from uuid import UUID
from datetime import datetime, timezone, timedelta
import jwt
from app.utils.kms_utils import decrypt_data_with_kms

# --- Service: Identity Provider Config from DB ---
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

# --- Service: Cache OIDC State ---
async def cache_oidc_state(
    state: str,
    nonce: str,
    pkce_code_verifier: str,
    provider_name: str,
    db: firestore_v1.AsyncClient,
    flow_type: Literal["login", "link_account"] = "login",
    linking_app_user_id: Optional[UUID] = None
):
    expires_at_dt = datetime.now(timezone.utc) + timedelta(seconds=settings.OIDC_STATE_TTL_SECONDS)
    state_data = OIDCStateCache(
        state=state,
        nonce=nonce,
        pkce_code_verifier=pkce_code_verifier,
        provider_name=provider_name,
        expires_at=expires_at_dt,
        flow_type=flow_type,  # Store new field
        linking_app_user_id=linking_app_user_id  # Store new field
    )
    doc_ref = db.collection(settings.FIRESTORE_OIDC_STATE_COLLECTION).document(state)
    await doc_ref.set(state_data.model_dump())
    print(f"OIDC state cached in Firestore for state: {state}, flow_type: {flow_type}")

# --- Service: Get Cached OIDC State ---
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

# --- Service: Fetch .well-known config with Firestore cache ---
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

# --- Service: JWKS Firestore-cached fetch helper ---
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

# --- Service: JIT User Provisioning and linking ---
async def jit_provision_user(
    idp_config: IdentityProviderConfig,
    user_claims: dict,
    db_session: AsyncSession
) -> AppUser:
    provider_user_id = user_claims.get("sub")
    email = user_claims.get("email")
    first_name = user_claims.get("given_name")
    last_name = user_claims.get("family_name")
    if not provider_user_id or not email:
        raise HTTPException(status_code=400, detail="Missing required user claims (sub or email) from IdP.")
    link_query = text("""
        SELECT ul.user_id, u.email, u.first_name, u.last_name, u.id, u.created_at, u.updated_at, u.roles
        FROM user_provider_links ul
        JOIN app_users u ON ul.user_id = u.id
        WHERE ul.provider_id = :provider_id AND ul.provider_user_id = :provider_user_id
    """)
    result = await db_session.execute(link_query, {"provider_id": idp_config.id, "provider_user_id": provider_user_id})
    existing_linked_user_row = result.fetchone()
    if existing_linked_user_row:
        return AppUser.model_validate(dict(existing_linked_user_row._mapping))
    email_query = text("SELECT id, email, first_name, last_name, created_at, updated_at, roles FROM app_users WHERE email = :email")
    result = await db_session.execute(email_query, {"email": email})
    existing_email_user_row = result.fetchone()
    if existing_email_user_row:
        raise HTTPException(
            status_code=409,
            detail="An account with this email already exists. Please log in using your original method and link this provider from your account settings."
        )
    # 3. No existing link AND no email conflict: Create new AppUser and UserProviderLink
    default_roles = ['User']  # Application defines the default roles
    new_user_query = text("""
        INSERT INTO app_users (email, first_name, last_name, roles)
        VALUES (:email, :first_name, :last_name, :roles)
        RETURNING id, email, first_name, last_name, created_at, updated_at, roles
    """)
    result = await db_session.execute(
        new_user_query,
        {
            "email": email,
            "first_name": first_name,
            "last_name": last_name,
            "roles": default_roles
        }
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

# --- Service: ID Token Validation ---
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
    if idp_config.issuer_uri != well_known_config.get("issuer"):
        raise HTTPException(status_code=401, detail="Configured issuer does not match well-known issuer.")
    try:
        public_key = jwt.algorithms.RSAAlgorithm.from_jwk(matching_key_data)
        decoded_token = jwt.decode(
            id_token,
            public_key,
            algorithms=[unverified_header.get("alg", "RS256")],
            audience=idp_config.client_id,
            issuer=idp_config.issuer_uri
        )
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

# --- Service: Fetch GCP Secret ---
async def fetch_gcp_secret(
    secret_id: str,
    client: secretmanager_v1.SecretManagerServiceClient,
    project_id: str = settings.GCP_PROJECT_ID,
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

# --- Service: Decrypt data with KMS (imported for internal_router) ---
async def process_account_link(
    idp_config: IdentityProviderConfig,
    new_idp_user_claims: dict,
    existing_app_user_id: UUID,
    db_session: AsyncSession
) -> bool:
    provider_user_id = new_idp_user_claims.get("sub")
    if not provider_user_id:
        raise HTTPException(status_code=400, detail="Missing 'sub' claim from the new IdP token, cannot link account.")

    # Check if this external IdP account is already linked to any user
    existing_link_query = text("""
        SELECT user_id FROM user_provider_links
        WHERE provider_id = :provider_id AND provider_user_id = :provider_user_id
    """)
    result = await db_session.execute(
        existing_link_query,
        {"provider_id": idp_config.id, "provider_user_id": provider_user_id}
    )
    link_row = result.fetchone()

    if link_row:
        if link_row.user_id == existing_app_user_id:
            print(f"Account linking: IdP {idp_config.name} account {provider_user_id} already linked to user {existing_app_user_id}.")
            return True # Already linked to the correct user
        else:
            # This external account is linked to a different app user. This is a conflict.
            raise HTTPException(
                status_code=409, # Conflict
                detail="This external identity is already linked to a different application account."
            )
    # No existing link for this external IdP account, proceed to create a new link
    print(f"Creating new provider link for user {existing_app_user_id} with provider {idp_config.name} (IdP sub: {provider_user_id}).")
    new_link_query = text("""
        INSERT INTO user_provider_links (user_id, provider_id, provider_user_id, encrypted_refresh_token)
        VALUES (:user_id, :provider_id, :provider_user_id, NULL)
        RETURNING id
    """)
    try:
        await db_session.execute(
            new_link_query,
            {
                "user_id": existing_app_user_id,
                "provider_id": idp_config.id,
                "provider_user_id": provider_user_id
            }
        )
        return True
    except Exception as e:
        print(f"Database error during account link creation: {e}")
        raise HTTPException(status_code=500, detail="Failed to link new provider account due to a database error.")

# --- Service: Derive Roles from IdP Claims ---
async def derive_roles_from_idp_claims(
    idp_config: IdentityProviderConfig,
    user_claims: Dict[str, Any]
) -> List[str]:
    """
    Derives additional roles from IdP claims if the IdP configuration enables it.
    These roles are determined on-the-fly based on the claims provided by the IdP.
    """
    derived_roles = set()
    if idp_config.derives_roles_from_claims:
        print(f"CLAIM_ROLE_DERIVATION_TODO: Deriving roles from claims for user: {user_claims.get('email')}, provider: {idp_config.name}")
        # Example 1: Check a generic 'groups' claim often provided by IdPs
        idp_groups = user_claims.get("groups", [])
        if isinstance(idp_groups, list):
            if "administrators_group_from_idp" in idp_groups:
                derived_roles.add("Admin")
            if "therapists_group_from_idp" in idp_groups:
                derived_roles.add("Therapist")
        # Example 2: Check a specific custom claim for roles (e.g., 'app_roles')
        custom_app_roles = user_claims.get("custom_app_roles", [])
        if isinstance(custom_app_roles, list):
            for role in custom_app_roles:
                if isinstance(role, str):
                    derived_roles.add(role.capitalize())
        # Example 3: Specific logic for your Google Workspace IdP
        if idp_config.name == "google_workspace_team_vitality":
            iam_mapped_roles = user_claims.get("gcp_iam_mapped_roles", [])
            if "team_vitality_app_admin_role_from_gcp_claim" in iam_mapped_roles:
                derived_roles.add("Admin")
    return sorted(list(derived_roles))

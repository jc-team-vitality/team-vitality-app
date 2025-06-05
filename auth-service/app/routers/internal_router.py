from fastapi import APIRouter, HTTPException, Body, Depends
from google.cloud import firestore_v1, secretmanager_v1
from sqlalchemy.ext.asyncio import AsyncSession
import httpx
from google.cloud import kms_v1
from sqlalchemy.sql import text as sql_text

from app.models import InternalTokenRefreshRequest, InternalTokenRefreshResponse
from app.db_clients import get_async_db_session, get_firestore_db, get_secret_manager_client, get_kms_client, AsyncSessionLocal
from app.services.oidc_service import get_identity_provider_config_from_db, fetch_gcp_secret
from app.services.oidc_service import decrypt_data_with_kms, fetch_idp_well_known_config_impl
from app.utils.kms_utils import encrypt_data_with_kms
from app.core.config import settings

router = APIRouter()

@router.post("/token/refresh", response_model=InternalTokenRefreshResponse)
async def internal_refresh_access_token(
    request_data: InternalTokenRefreshRequest = Body(...),
    db_pg_session: AsyncSession = Depends(get_async_db_session),
    db_firestore: firestore_v1.AsyncClient = Depends(get_firestore_db),
    http_client: httpx.AsyncClient = Depends(lambda: httpx.AsyncClient()),
    sm_client: secretmanager_v1.SecretManagerServiceClient = Depends(get_secret_manager_client),
    kms_client: kms_v1.KeyManagementServiceClient = Depends(get_kms_client)
):
    """
    Refreshes an access token using a stored refresh token for a given user and provider.

    This endpoint validates the provider and user link, decrypts the stored refresh token,
    calls the IdP's token endpoint to obtain a new access token, and handles refresh token rotation
    and invalidation. If a new refresh token is returned, it is encrypted and stored.
    """
    # --- Retrieve and validate the IdP configuration ---
    idp_config = await get_identity_provider_config_from_db(request_data.provider_name, db_pg_session)
    if not idp_config or not idp_config.is_active:
        raise HTTPException(status_code=404, detail=f"Provider '{request_data.provider_name}' not found or not active.")
    if not idp_config.supports_refresh_token:
        raise HTTPException(status_code=400, detail=f"Refresh token not supported by provider '{request_data.provider_name}'.")    

    # --- Retrieve the encrypted refresh token for the user/provider link ---
    link_query = sql_text("""
        SELECT encrypted_refresh_token 
        FROM user_provider_links
        WHERE user_id = :user_id AND provider_id = :provider_id
    """)
    result = await db_pg_session.execute(link_query, {"user_id": request_data.user_id, "provider_id": idp_config.id})
    link_row = result.fetchone()
    if not link_row or not link_row.encrypted_refresh_token:
        raise HTTPException(status_code=404, detail="No refresh token found for this user and provider, or user/provider link does not exist.")
    encrypted_rt_bytes = link_row.encrypted_refresh_token

    # --- Retrieve client secret from Secret Manager ---
    if not idp_config.client_secret_name:
        raise HTTPException(status_code=500, detail=f"Client secret name not configured for provider '{request_data.provider_name}'.")
    client_secret_value = await fetch_gcp_secret(
        secret_id=idp_config.client_secret_name,
        client=sm_client
    )
    if not client_secret_value:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve client secret for provider '{request_data.provider_name}'.")

    # --- Decrypt the stored refresh token using KMS ---
    if not settings.REFRESH_TOKEN_KMS_KEY_ID:
        raise HTTPException(status_code=500, detail="Refresh token KMS key not configured.")
    try:
        decrypted_refresh_token = await decrypt_data_with_kms(
            kms_client=kms_client,
            kms_key_id=settings.REFRESH_TOKEN_KMS_KEY_ID,
            ciphertext=encrypted_rt_bytes
        )
    except Exception:
        raise HTTPException(status_code=500, detail="Failed to process stored refresh token.")

    # --- Fetch the IdP's token endpoint from .well-known config ---
    well_known_config = await fetch_idp_well_known_config_impl(idp_config.well_known_uri, db_firestore, http_client)
    if not well_known_config or not well_known_config.get("token_endpoint"):
        raise HTTPException(status_code=500, detail=f"Could not retrieve token endpoint for provider '{request_data.provider_name}'.")
    token_endpoint = well_known_config["token_endpoint"]

    # --- Prepare the refresh token request payload ---
    refresh_payload = {
        "grant_type": "refresh_token",
        "refresh_token": decrypted_refresh_token,
        "client_id": idp_config.client_id,
        "client_secret": client_secret_value,
    }
    try:
        # --- Call the IdP's token endpoint to refresh the access token ---
        token_response = await http_client.post(token_endpoint, data=refresh_payload)
        token_response.raise_for_status()
        new_token_data = token_response.json()
    except httpx.HTTPStatusError as e:
        # --- Handle invalid_grant and clear stored refresh token if needed ---
        error_detail = e.response.json() if e.response.content else str(e)
        if e.response.status_code == 400 and error_detail.get("error") == "invalid_grant":
            print(f"Refresh token for user {request_data.user_id}, provider {request_data.provider_name} is invalid. Attempting to clear stored token independently.")
            nested_session = None
            try:
                if AsyncSessionLocal:
                    nested_session = AsyncSessionLocal()
                    clear_rt_query = sql_text("""
                        UPDATE user_provider_links
                        SET encrypted_refresh_token = NULL, updated_at = NOW()
                        WHERE user_id = :user_id AND provider_id = :provider_id
                    """)
                    await nested_session.execute(
                        clear_rt_query,
                        {"user_id": request_data.user_id, "provider_id": idp_config.id}
                    )
                    await nested_session.commit()
                    print(f"Successfully cleared invalid refresh token from DB for user {request_data.user_id}, provider {request_data.provider_name}.")
                else:
                    print("ERROR: AsyncSessionLocal not available to clear invalid refresh token.")
            except Exception as db_exc_nested:
                print(f"Failed to clear invalid refresh token from DB in nested transaction: {db_exc_nested}")
                if nested_session:
                    await nested_session.rollback()
            finally:
                if nested_session:
                    await nested_session.close()
            raise HTTPException(status_code=400, detail={"message": "Refresh token is invalid or expired.", "idp_error": error_detail})
        raise HTTPException(status_code=e.response.status_code, detail={"message": "Failed to refresh access token.", "idp_error": error_detail})
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Access token refresh HTTP request failed: {str(e)}")

    # --- Extract new tokens from the response ---
    new_access_token = new_token_data.get("access_token")
    new_expires_in = new_token_data.get("expires_in")
    new_scopes = new_token_data.get("scope")
    if not new_access_token:
        raise HTTPException(status_code=500, detail="New access token not found in refresh response.")

    # --- Handle refresh token rotation: encrypt and store new refresh token if present ---
    new_refresh_token_str = new_token_data.get("refresh_token")
    if new_refresh_token_str:
        print(f"New refresh token received during rotation for user {request_data.user_id}, provider {request_data.provider_name}. Updating stored token.")
        if not settings.REFRESH_TOKEN_KMS_KEY_ID:
            print("WARNING: REFRESH_TOKEN_KMS_KEY_ID not set. Cannot encrypt new refresh token.")
        else:
            try:
                new_encrypted_rt_bytes = await encrypt_data_with_kms(
                    kms_client=kms_client,
                    kms_key_id=settings.REFRESH_TOKEN_KMS_KEY_ID,
                    plaintext=new_refresh_token_str
                )
                update_rt_query = sql_text("""
                    UPDATE user_provider_links
                    SET encrypted_refresh_token = :encrypted_refresh_token, updated_at = NOW()
                    WHERE user_id = :user_id AND provider_id = :provider_id
                """)
                await db_pg_session.execute(
                    update_rt_query,
                    {
                        "encrypted_refresh_token": new_encrypted_rt_bytes,
                        "user_id": request_data.user_id,
                        "provider_id": idp_config.id
                    }
                )
                print("Successfully updated rotated refresh token in DB.")
            except Exception as e:
                print(f"ERROR: Failed to encrypt and store rotated refresh token: {e}")

    # --- Return the new access token and related info ---
    return InternalTokenRefreshResponse(
        access_token=new_access_token,
        expires_in=new_expires_in,
        token_type=new_token_data.get("token_type", "Bearer"),
        scopes=new_scopes
    )

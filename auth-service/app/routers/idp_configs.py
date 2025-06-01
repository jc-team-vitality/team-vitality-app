from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql import text
from typing import List, Optional
from uuid import UUID

from app.db_clients import get_async_db_session
from app.models import (
    IdentityProviderConfig,
    IdentityProviderConfigCreate,
    IdentityProviderConfigUpdate
)

router = APIRouter()

@router.post(
    "/", 
    response_model=IdentityProviderConfig, 
    status_code=status.HTTP_201_CREATED,
    summary="Create a new Identity Provider Configuration"
)
async def create_idp_config(
    idp_in: IdentityProviderConfigCreate,
    db_session: AsyncSession = Depends(get_async_db_session)
):
    """
    Create a new Identity Provider configuration.

    Attempts to insert a new IdP config into the database. Handles unique constraint violations
    for name and issuer_uri, returning a 409 if a duplicate exists.
    """
    # --- Prepare the SQL insert query and parameters ---
    # The database schema already has UNIQUE constraints on name and issuer_uri,
    # so an IntegrityError will be raised by the DB. We should catch it.
    query = text("""
        INSERT INTO identity_providers (name, issuer_uri, well_known_uri, client_id, 
                                    client_secret_name, scopes, is_active, supports_refresh_token)
        VALUES (:name, :issuer_uri, :well_known_uri, :client_id, 
                :client_secret_name, :scopes, :is_active, :supports_refresh_token)
        RETURNING id, name, issuer_uri, well_known_uri, client_id, 
                  client_secret_name, scopes, is_active, supports_refresh_token, 
                  created_at, updated_at
    """)
    try:
        # --- Execute the insert and fetch the created row ---
        result = await db_session.execute(
            query, 
            {
                "name": idp_in.name, "issuer_uri": str(idp_in.issuer_uri), 
                "well_known_uri": str(idp_in.well_known_uri), "client_id": idp_in.client_id,
                "client_secret_name": idp_in.client_secret_name, "scopes": idp_in.scopes,
                "is_active": idp_in.is_active, "supports_refresh_token": idp_in.supports_refresh_token
            }
        )
        created_idp_row = result.fetchone()
        if not created_idp_row:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to create IdP configuration.")
        # await db_session.commit() # Handled by get_async_db_session dependency
        return IdentityProviderConfig.model_validate(dict(created_idp_row._mapping))
    except Exception as e: # Catch potential IntegrityError from DB for unique constraints
        # await db_session.rollback() # Handled by get_async_db_session dependency
        # A more specific check for unique constraint violation error code might be better
        if "unique constraint" in str(e).lower(): # Basic check
             raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"IdP configuration with this name or issuer URI already exists: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Database error: {e}")


@router.get("/", response_model=List[IdentityProviderConfig], summary="List all Identity Provider Configurations")
async def list_idp_configs(
    skip: int = 0, 
    limit: int = 100, 
    db_session: AsyncSession = Depends(get_async_db_session)
):
    """
    List all Identity Provider configurations.

    Returns a paginated list of IdP configs, ordered by name.
    """
    # --- Prepare and execute the select query ---
    query = text("""
        SELECT id, name, issuer_uri, well_known_uri, client_id, 
               client_secret_name, scopes, is_active, supports_refresh_token, 
               created_at, updated_at
        FROM identity_providers
        ORDER BY name
        LIMIT :limit OFFSET :skip
    """)
    result = await db_session.execute(query, {"limit": limit, "skip": skip})
    idp_rows = result.fetchall()
    # --- Return the list of configs ---
    return [IdentityProviderConfig.model_validate(dict(row._mapping)) for row in idp_rows]


@router.get("/{provider_id}", response_model=IdentityProviderConfig, summary="Get a specific Identity Provider Configuration")
async def get_idp_config(
    provider_id: UUID, 
    db_session: AsyncSession = Depends(get_async_db_session)
):
    """
    Retrieve a specific Identity Provider configuration by its UUID.
    Returns 404 if not found.
    """
    # --- Prepare and execute the select query ---
    query = text("""
        SELECT id, name, issuer_uri, well_known_uri, client_id, 
               client_secret_name, scopes, is_active, supports_refresh_token, 
               created_at, updated_at
        FROM identity_providers
        WHERE id = :provider_id
    """)
    result = await db_session.execute(query, {"provider_id": provider_id})
    idp_row = result.fetchone()
    if not idp_row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Identity Provider configuration not found.")
    # --- Return the config ---
    return IdentityProviderConfig.model_validate(dict(idp_row._mapping))


@router.put("/{provider_id}", response_model=IdentityProviderConfig, summary="Update an Identity Provider Configuration")
async def update_idp_config(
    provider_id: UUID,
    idp_update: IdentityProviderConfigUpdate,
    db_session: AsyncSession = Depends(get_async_db_session)
):
    """
    Update an existing Identity Provider configuration.

    Only fields provided in the request body will be updated. Handles unique constraint violations.
    Returns 404 if the config does not exist.
    """
    # --- Prepare the update fields and SQL query ---
    update_fields = idp_update.model_dump(exclude_unset=True) # Pydantic v2
    if not update_fields:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No fields provided for update.")

    set_clauses = [f"{field} = :{field}" for field in update_fields.keys()]
    set_query_part = ", ".join(set_clauses)
    # Always update updated_at
    set_query_part += ", updated_at = NOW()"

    query_str = f"""
        UPDATE identity_providers
        SET {set_query_part}
        WHERE id = :provider_id
        RETURNING id, name, issuer_uri, well_known_uri, client_id, 
                  client_secret_name, scopes, is_active, supports_refresh_token, 
                  created_at, updated_at
    """
    params = {"provider_id": provider_id, **update_fields}
    # Convert HttpUrl to string for SQL query parameters if they are present in update_fields
    if 'issuer_uri' in params and params['issuer_uri'] is not None:
        params['issuer_uri'] = str(params['issuer_uri'])
    if 'well_known_uri' in params and params['well_known_uri'] is not None:
        params['well_known_uri'] = str(params['well_known_uri'])
    try:
        # --- Execute the update and fetch the updated row ---
        result = await db_session.execute(text(query_str), params)
        updated_idp_row = result.fetchone()
        if not updated_idp_row:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Identity Provider configuration not found for update.")
        # await db_session.commit() # Handled by get_async_db_session
        return IdentityProviderConfig.model_validate(dict(updated_idp_row._mapping))
    except Exception as e: # Catch potential IntegrityError for unique constraints
        # await db_session.rollback() # Handled by get_async_db_session
        if "unique constraint" in str(e).lower():
             raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"Update would violate unique constraint (name or issuer URI): {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Database error during update: {e}")


@router.delete("/{provider_id}", status_code=status.HTTP_204_NO_CONTENT, summary="Delete an Identity Provider Configuration")
async def delete_idp_config(
    provider_id: UUID,
    db_session: AsyncSession = Depends(get_async_db_session)
):
    """
    Delete an Identity Provider configuration by its UUID.
    Returns 404 if not found. Returns 204 No Content on success.
    """
    # --- Check if the config exists ---
    get_query = text("SELECT id FROM identity_providers WHERE id = :provider_id")
    result = await db_session.execute(get_query, {"provider_id": provider_id})
    if not result.fetchone():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Identity Provider configuration not found.")

    # --- Delete the config ---
    delete_query = text("DELETE FROM identity_providers WHERE id = :provider_id")
    await db_session.execute(delete_query, {"provider_id": provider_id})
    # await db_session.commit() # Handled by get_async_db_session
    return None # FastAPI will return 204 No Content

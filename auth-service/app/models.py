from pydantic import BaseModel, EmailStr, HttpUrl
from typing import Optional, List, Dict, Any, Literal  # Add Literal
from uuid import UUID
from datetime import datetime

# Base model for common fields like id, created_at, updated_at
class BaseAuditModel(BaseModel):
    id: UUID
    created_at: datetime
    updated_at: datetime

class IdentityProviderConfigBase(BaseModel):
    name: str
    issuer_uri: HttpUrl # Using HttpUrl for validation
    well_known_uri: HttpUrl # Using HttpUrl for validation
    client_id: str
    client_secret_name: str # Name of the secret in GCP Secret Manager
    scopes: str # Space-separated string
    is_active: bool = True
    supports_refresh_token: bool
    derives_roles_from_claims: bool = False  # New field for IdP role derivation

class IdentityProviderConfigCreate(IdentityProviderConfigBase):
    pass

class IdentityProviderConfig(IdentityProviderConfigBase, BaseAuditModel):
    class Config:
        from_attributes = True # orm_mode for Pydantic v1

class AppUserBase(BaseModel):
    email: EmailStr
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    roles: List[str]  # Add this line for user roles

class AppUserCreate(AppUserBase):
    pass # Roles will be defaulted by the database or can be set by admin flows later.

class AppUser(AppUserBase, BaseAuditModel):
    class Config:
        from_attributes = True

class UserProviderLinkBase(BaseModel):
    user_id: UUID
    provider_id: UUID
    provider_user_id: str # The 'sub' claim from the IdP
    encrypted_refresh_token: Optional[bytes] = None # Storing as bytes

class UserProviderLinkCreate(UserProviderLinkBase):
    pass

class UserProviderLink(UserProviderLinkBase, BaseAuditModel):
    class Config:
        from_attributes = True

class OIDCInitiateLoginResponse(BaseModel):
    authorization_url: HttpUrl
    state: str  # Optionally return state if BFF needs to verify it (though primary verification is in Auth service)
    # Nonce and code_verifier are NOT returned to the client/BFF

class OIDCTokenExchangeRequest(BaseModel):
    state: str
    authorization_code: str
    # The BFF might also pass the redirect_uri it used if it's dynamic per request,
    # or the Auth Service can assume a fixed one based on config.
    # For now, let's assume the Auth Service knows the redirect_uri from the IdP config
    # or a global app setting.

class OIDCTokenExchangeResponse(BaseModel):
    status: str # e.g., "success", "email_conflict", "error"
    message: Optional[str] = None
    user_info: Optional[AppUser] = None # The app_user model if login/JIT was successful
    # We might add session tokens or other details later for the BFF

class OIDCStateCache(BaseModel):
    state: str  # Will be the document ID in Firestore
    nonce: str
    pkce_code_verifier: str
    provider_name: str
    expires_at: datetime  # For Firestore TTL policy
    # New fields for account linking
    flow_type: Literal["login", "link_account"] = "login"  # Default to "login"
    linking_app_user_id: Optional[UUID] = None  # ID of the existing app_user initiating the link

class OIDCWellKnownCache(BaseModel):
    config_data: Dict[str, Any] # Stores the JSON content of the .well-known document
    expires_at: datetime # For Firestore TTL policy and manual cache validation

class JWKSCache(BaseModel):
    # The document ID in Firestore could be a sanitized version of the jwks_uri
    keys: List[Dict[str, Any]] # Stores the array of JWK objects
    expires_at: datetime # For Firestore TTL policy and manual cache validation

class InternalTokenRefreshRequest(BaseModel):
    user_id: UUID
    provider_name: str # The common name of the identity provider (e.g., 'google')

class InternalTokenRefreshResponse(BaseModel):
    access_token: str
    expires_in: Optional[int] = None # Seconds until expiry
    token_type: str = "Bearer"
    scopes: Optional[str] = None # Scopes associated with the new access token

from typing import List # Ensure List is imported if not already

class IdentityProviderConfigUpdate(BaseModel):
    name: Optional[str] = None
    issuer_uri: Optional[HttpUrl] = None
    well_known_uri: Optional[HttpUrl] = None
    client_id: Optional[str] = None
    client_secret_name: Optional[str] = None # Name of the secret in GCP Secret Manager
    scopes: Optional[str] = None # Space-separated string
    is_active: Optional[bool] = None
    supports_refresh_token: Optional[bool] = None
    derives_roles_from_claims: Optional[bool] = None  # New field for update
    # id, created_at, updated_at are typically not updatable directly via this DTO

class OIDCInitiateLinkAccountRequest(BaseModel):
    app_user_id: UUID  # The ID of the currently authenticated application user

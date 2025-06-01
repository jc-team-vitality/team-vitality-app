from pydantic import BaseModel, EmailStr, HttpUrl
from typing import Optional, List, Dict, Any
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

class IdentityProviderConfigCreate(IdentityProviderConfigBase):
    pass

class IdentityProviderConfig(IdentityProviderConfigBase, BaseAuditModel):
    class Config:
        from_attributes = True # orm_mode for Pydantic v1

class AppUserBase(BaseModel):
    email: EmailStr
    first_name: Optional[str] = None
    last_name: Optional[str] = None

class AppUserCreate(AppUserBase):
    pass # Add password fields here if managing local passwords, though OIDC is primary

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

class OIDCWellKnownCache(BaseModel):
    config_data: Dict[str, Any] # Stores the JSON content of the .well-known document
    expires_at: datetime # For Firestore TTL policy and manual cache validation

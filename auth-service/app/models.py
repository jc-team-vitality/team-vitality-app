from pydantic import BaseModel, EmailStr, HttpUrl
from typing import Optional, List
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

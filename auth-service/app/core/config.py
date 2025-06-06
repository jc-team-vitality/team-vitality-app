from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Optional

class Settings(BaseSettings):
    PROJECT_NAME: str = "TeamVitality Auth Service"
    API_V1_STR: str = "/api/v1"

    # Database configuration (must be loaded from environment variables or .env)
    DATABASE_URL: Optional[str] = None
    
    # KMS Key for encrypting/decrypting refresh tokens
    REFRESH_TOKEN_KMS_KEY_ID: Optional[str] = None

    # Firestore settings
    FIRESTORE_DATABASE_ID: Optional[str] = None # To be set in .env
    GCP_PROJECT_ID: Optional[str] = None # To be set in .env, used for Secret Manager
    FIRESTORE_OIDC_STATE_COLLECTION: str = "oidc_states"
    OIDC_STATE_TTL_SECONDS: int = 900 # 15 minutes

    # New settings for .well-known caching
    FIRESTORE_WELL_KNOWN_CONFIGS_COLLECTION: str = "oidc_well_known_configs"
    WELL_KNOWN_CONFIG_CACHE_TTL_SECONDS: int = 86400 # 24 hours

    # New settings for JWKS caching
    FIRESTORE_JWKS_CACHE_COLLECTION: str = "oidc_jwks_cache"
    JWKS_CACHE_TTL_SECONDS: int = 3600 # 1 hour (JWKS keys can rotate, but usually not too frequently)

    BFF_OIDC_CALLBACK_URI: str = None
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

settings = Settings()
# For local development, create a .env file with actual DATABASE_URL and REFRESH_TOKEN_KMS_KEY_ID values.
# NOTE: Ensure you add GCP_PROJECT_ID to your .env file for Secret Manager access.

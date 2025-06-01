from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Optional

class Settings(BaseSettings):
    PROJECT_NAME: str = "TeamVitality Auth Service"
    API_V1_STR: str = "/api/v1"

    # Database configuration (placeholders, to be loaded from environment variables)
    DATABASE_URL: Optional[str] = "postgresql://user:password@host:port/db"
    
    # KMS Key for encrypting/decrypting refresh tokens
    REFRESH_TOKEN_KMS_KEY_ID: Optional[str] = None

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

settings = Settings()
# For local development, create a .env file with actual DATABASE_URL and REFRESH_TOKEN_KMS_KEY_ID values.

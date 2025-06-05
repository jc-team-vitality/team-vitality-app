from google.cloud import firestore_v1
from app.core.config import settings
from google.cloud import secretmanager_v1
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy.sql import text
from typing import AsyncGenerator
from google.cloud import kms_v1

# Initialize Firestore client
# This will use Application Default Credentials when deployed on GCP (e.g., Cloud Run)
# For local development, ensure GOOGLE_APPLICATION_CREDENTIALS env var is set.
firestore_db = None
if settings.GCP_PROJECT_ID_FOR_FIRESTORE:
    firestore_db = firestore_v1.AsyncClient(project=settings.GCP_PROJECT_ID_FOR_FIRESTORE)
else:
    print("WARNING: GCP_PROJECT_ID_FOR_FIRESTORE not set. Firestore client not initialized.")

# Dependency for FastAPI to get Firestore client
async def get_firestore_db():
    if firestore_db is None:
        # This case should ideally not be hit if config is correct and app starts
        raise RuntimeError("Firestore client not initialized. Check GCP_PROJECT_ID_FOR_FIRESTORE setting.")
    return firestore_db

# Initialize Secret Manager client
secret_manager_client = None
if settings.GCP_PROJECT_ID:
    secret_manager_client = secretmanager_v1.SecretManagerServiceClient()
else:
    print("WARNING: GCP_PROJECT_ID not set for Secret Manager. Secret client not initialized.")

# Dependency for FastAPI to get Secret Manager client
async def get_secret_manager_client():
    if secret_manager_client is None:
        raise RuntimeError("Secret Manager client not initialized. Check GCP_PROJECT_ID setting.")
    return secret_manager_client

async_engine = None
AsyncSessionLocal = None

if settings.DATABASE_URL:
    async_engine = create_async_engine(settings.DATABASE_URL, echo=False)
    AsyncSessionLocal = sessionmaker(
        bind=async_engine, class_=AsyncSession, expire_on_commit=False
    )
else:
    print("WARNING: DATABASE_URL not set. SQLAlchemy async engine not initialized.")

# Dependency for FastAPI to get an async SQLAlchemy session
async def get_async_db_session() -> AsyncGenerator[AsyncSession, None]:
    if AsyncSessionLocal is None:
        raise RuntimeError("Database not configured. AsyncSessionLocal is None.")
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()

# Initialize Cloud KMS client
kms_client = None
if settings.GCP_PROJECT_ID and settings.REFRESH_TOKEN_KMS_KEY_ID: # Ensure project ID is available
    try:
        kms_client = kms_v1.KeyManagementServiceClient()
        # Verify key path format or existence (optional, basic check)
        if not settings.REFRESH_TOKEN_KMS_KEY_ID.startswith("projects/"):
            print(f"WARNING: REFRESH_TOKEN_KMS_KEY_ID ({settings.REFRESH_TOKEN_KMS_KEY_ID}) might not be a full key path. KMS client initialized but key path might be an issue.")
    except Exception as e:
        print(f"WARNING: Failed to initialize KMS client: {e}")
else:
    print("WARNING: GCP_PROJECT_ID or REFRESH_TOKEN_KMS_KEY_ID not set. KMS client not initialized.")

# Dependency for FastAPI to get KMS client
async def get_kms_client():
    if kms_client is None:
        raise RuntimeError("KMS client not initialized. Check GCP_PROJECT_ID and REFRESH_TOKEN_KMS_KEY_ID settings.")
    return kms_client

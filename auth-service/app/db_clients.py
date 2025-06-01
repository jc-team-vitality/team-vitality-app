from google.cloud import firestore_v1
from app.core.config import settings
from google.cloud import secretmanager_v1

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

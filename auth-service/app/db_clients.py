from google.cloud import firestore_v1
from app.core.config import settings

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

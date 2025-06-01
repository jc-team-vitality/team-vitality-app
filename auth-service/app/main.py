from fastapi import FastAPI
from .core.config import settings

app = FastAPI(title=settings.PROJECT_NAME)

@app.get("/health", tags=["Health"])
async def health_check():
    return {"status": "healthy", "project_name": settings.PROJECT_NAME}

# Further imports and router inclusions will go here later

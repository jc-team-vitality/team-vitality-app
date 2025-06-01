# Standard library imports

# Third-party imports
from fastapi import FastAPI

# Local application imports
from .core.config import settings
from .routers import idp_configs as idp_configs_router, oidc as oidc_router, internal as internal_router

# Import service functions from oidc_service.py

app = FastAPI(title=settings.PROJECT_NAME)

app.include_router(oidc_router.router, prefix="/oidc", tags=["OIDC Authentication"])
app.include_router(internal_router.router, prefix="/internal", tags=["Internal API"])
app.include_router(
    idp_configs_router.router,
    prefix="/admin/identity-providers",
    tags=["Admin - Identity Provider Configurations"]
)

# Only keep endpoints not implemented in routers
@app.get("/health", tags=["Health"])
async def health_check():
    return {"status": "healthy", "project_name": settings.PROJECT_NAME}
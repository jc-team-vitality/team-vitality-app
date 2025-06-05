# Standard library imports

# Third-party imports
from fastapi import FastAPI

# Local application imports
from .core.config import settings
from .routers import oidc_router, internal_router, idp_configs

app = FastAPI(title=settings.PROJECT_NAME)

app.include_router(oidc_router.router, prefix="/oidc", tags=["OIDC Authentication"])
app.include_router(internal_router.router, prefix="/internal", tags=["Internal API"])
app.include_router(
    idp_configs.router,
    prefix="/admin/identity-providers",
    tags=["Admin - Identity Provider Configurations"]
)

# Only keep endpoints not implemented in routers
@app.get("/health", tags=["Health"])
async def health_check():
    return {"status": "healthy", "project_name": settings.PROJECT_NAME}
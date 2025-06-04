from fastapi import APIRouter
from .endpoints import models, threat_intelligence, ml_models, settings
from .. import users # users.py is in backend/app/api/

# This is the main router for all v1 endpoints
api_v1_router = APIRouter()

# Include the models router
api_v1_router.include_router(models.router, prefix="/models", tags=["Models"]) # Changed tag for consistency
api_v1_router.include_router(threat_intelligence.router, prefix="/threat-intelligence", tags=["Threat Intelligence"])
api_v1_router.include_router(users.router, prefix="/users", tags=["Users"])
api_v1_router.include_router(ml_models.router, prefix="/ml-models", tags=["ML Models"])
api_v1_router.include_router(settings.router, prefix="/settings", tags=["Settings"])


# Future v1 endpoints can be added here, for example:
# from .endpoints import other_v1_endpoint
# api_v1_router.include_router(other_v1_endpoint.router, prefix="/other", tags=["other"])

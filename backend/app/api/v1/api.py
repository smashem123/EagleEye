"""
API router configuration for ScamSwatter v1
"""
from fastapi import APIRouter
from app.api.v1.endpoints import scams

api_router = APIRouter()

# Include scam-related endpoints
api_router.include_router(scams.router, prefix="/scams", tags=["scams"])

# Health check endpoint
@api_router.get("/health")
def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "service": "ScamSwatter API"}

"""
Aggregates all /api route modules into a single router.
"""

from fastapi import APIRouter

# Existing API routes
from app.api.routes import (
    alerts,
    file_logs,
    processes,
    response_actions,
    scan,
    settings,
    simulate,
    status,
    correlation,
)

# Authentication routes
from app.auth import routes as auth

api_router = APIRouter()

# -------------------------------
# Monitoring APIs
# -------------------------------

api_router.include_router(status.router)
api_router.include_router(processes.router)
api_router.include_router(alerts.router)
api_router.include_router(file_logs.router)
api_router.include_router(settings.router)
api_router.include_router(simulate.router)
api_router.include_router(response_actions.router)
api_router.include_router(scan.router)
api_router.include_router(correlation.router)

# -------------------------------
# Authentication APIs
# -------------------------------

api_router.include_router(auth.router)
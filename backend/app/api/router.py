"""Aggregates all /api route modules into a single router."""

from fastapi import APIRouter

from app.api.routes import alerts, file_logs, processes, response_actions, scan, settings, simulate, status

api_router = APIRouter()

api_router.include_router(status.router)
api_router.include_router(processes.router)
api_router.include_router(alerts.router)
api_router.include_router(file_logs.router)
api_router.include_router(settings.router)
api_router.include_router(simulate.router)
api_router.include_router(response_actions.router)
api_router.include_router(scan.router)

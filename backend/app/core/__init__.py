"""Core application configuration, lifespan, and FastAPI factory."""

from app.core.app import app, create_app

__all__ = ["app", "create_app"]

"""
Application-wide constants and paths.

Centralizes configuration values used across monitoring, response, and database layers.
"""

import os

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------
# SQLite file is created relative to the process working directory (backend/).
DATABASE_URL: str = "sqlite:///./sentinelx.db"

# ---------------------------------------------------------------------------
# Response / quarantine
# ---------------------------------------------------------------------------
# Quarantine directory lives at the project root (one level above backend/).
_BACKEND_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
PROJECT_ROOT = os.path.abspath(os.path.join(_BACKEND_ROOT, ".."))
QUARANTINE_DIR: str = os.path.join(PROJECT_ROOT, "quarantine")

# ---------------------------------------------------------------------------
# FastAPI metadata (unchanged from original main.py)
# ---------------------------------------------------------------------------
API_TITLE = "SentinelX EDR API"
API_DESCRIPTION = "Real-time AI Threat Detection & Response API"
API_VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# CORS (hackathon defaults — preserved for frontend compatibility)
# ---------------------------------------------------------------------------
CORS_ALLOW_ORIGINS = ["*"]
CORS_ALLOW_CREDENTIALS = True
CORS_ALLOW_METHODS = ["*"]
CORS_ALLOW_HEADERS = ["*"]

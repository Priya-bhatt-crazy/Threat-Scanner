"""
SentinelX backend entry point.

Run from the backend directory:
    python main.py

The FastAPI app is defined in app.core.app; this module re-exports it as `app`
so uvicorn can load `main:app` unchanged.
"""

import os

import uvicorn

from app.core.app import app

__all__ = ["app"]

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        reload_dirs=[os.path.dirname(__file__)],
    )

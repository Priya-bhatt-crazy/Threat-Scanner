"""
Backward-compatibility shim.

Legacy code may `import database` — all symbols are re-exported from app.database.
"""

from app.database.models import Alert, Base, Setting
from app.database.session import SessionLocal, engine, get_db, init_db

__all__ = [
    "Alert",
    "Setting",
    "Base",
    "SessionLocal",
    "engine",
    "get_db",
    "init_db",
    "DATABASE_URL",
]

# Preserve module-level DATABASE_URL for any external references
from app.core.config import DATABASE_URL  # noqa: E402

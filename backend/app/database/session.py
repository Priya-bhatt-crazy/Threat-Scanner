"""
Database engine, session factory, and lifecycle helpers.
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.config import DATABASE_URL
from app.database.models import Base, Setting

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db() -> None:
    """Create tables and seed default settings if they do not exist."""
    Base.metadata.create_all(bind=engine)

    db = SessionLocal()
    try:
        default_settings = [
            {"key": "auto_respond", "value": "true"},
            {"key": "auto_respond_threshold", "value": "85.0"},
            {"key": "watchdog_path", "value": "./watch_folder"},
        ]
        for s in default_settings:
            exists = db.query(Setting).filter(Setting.key == s["key"]).first()
            if not exists:
                setting = Setting(key=s["key"], value=s["value"])
                db.add(setting)
            elif s["key"] == "watchdog_path" and exists.value == ".":
                # Migrate old '.' value to './watch_folder' to prevent dev feedback loops
                exists.value = s["value"]
        db.commit()
    finally:
        db.close()


def get_db():
    """FastAPI dependency that yields a database session per request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

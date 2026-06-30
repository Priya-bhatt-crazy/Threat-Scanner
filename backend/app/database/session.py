"""
Database engine, session factory, and lifecycle helpers.
"""

from passlib.context import CryptContext
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.config import DATABASE_URL
from app.database.models import Base, Setting, User
from app.auth.security import hash_password

# ---------------------------------------------------------
# Database Engine
# ---------------------------------------------------------

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)

# ---------------------------------------------------------
# Password Hashing
# ---------------------------------------------------------

pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
)


# ---------------------------------------------------------
# Initialize Database
# ---------------------------------------------------------

def init_db() -> None:
    """
    Create database tables and seed default settings and users.
    """

    Base.metadata.create_all(bind=engine)

    db = SessionLocal()

    try:

        # -----------------------------
        # Default Settings
        # -----------------------------

        default_settings = [
            {"key": "auto_respond", "value": "true"},
            {"key": "auto_respond_threshold", "value": "85.0"},
            {"key": "watchdog_path", "value": "./watch_folder"},
        ]

        for setting_data in default_settings:

            setting = (
                db.query(Setting)
                .filter(Setting.key == setting_data["key"])
                .first()
            )

            if not setting:

                db.add(
                    Setting(
                        key=setting_data["key"],
                        value=setting_data["value"],
                    )
                )

            elif (
                setting_data["key"] == "watchdog_path"
                and setting.value == "."
            ):
                setting.value = "./watch_folder"

        # -----------------------------
        # Default Users
        # -----------------------------

        default_users = [

            {
                "username": "admin",
                "password": "admin123",
                "role": "ADMIN",
            },

            {
                "username": "analyst",
                "password": "analyst123",
                "role": "ANALYST",
            },

            {
                "username": "viewer",
                "password": "viewer123",
                "role": "VIEWER",
            },

        ]

        for user_data in default_users:

            exists = (
                db.query(User)
                .filter(User.username == user_data["username"])
                .first()
            )

            if not exists:
                print(user_data["username"])
                print(user_data["password"])
                print(len(user_data["password"]))
                db.add(

                    User(

                        username=user_data["username"],

                        password=hash_password(
                            user_data["password"]
                        ),

                        role=user_data["role"],

                    )

                )

        db.commit()

    finally:

        db.close()


# ---------------------------------------------------------
# Database Dependency
# ---------------------------------------------------------

def get_db():
    """
    FastAPI dependency that provides a database session.
    """

    db = SessionLocal()

    try:
        yield db

    finally:
        db.close()
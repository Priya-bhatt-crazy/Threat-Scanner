"""
Security utilities for SentinelX authentication.

Provides:
- Password hashing
- Password verification
- JWT creation
- JWT validation
"""

from datetime import datetime, timedelta

from jose import JWTError, jwt
from passlib.context import CryptContext

# ------------------------------------------------------------------
# Change this before production
# ------------------------------------------------------------------

SECRET_KEY = "SentinelX-Super-Secret-Key-2026"

ALGORITHM = "HS256"

ACCESS_TOKEN_EXPIRE_MINUTES = 30

# ------------------------------------------------------------------
# Password Hashing
# ------------------------------------------------------------------

pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
)


def hash_password(password: str) -> str:
    """Hash a password using bcrypt, falling back to SHA-256 if passlib fails."""
    import hashlib
    try:
        return pwd_context.hash(password)
    except Exception as e:
        print(f"Fallback: passlib bcrypt hash failed ({e}). Using SHA-256 fallback.")
        return "sha256:" + hashlib.sha256(password.encode()).hexdigest()


def verify_password(
    plain_password: str,
    hashed_password: str,
) -> bool:
    """Verify password against stored hash with fallback mechanisms."""
    import hashlib
    # 1. SHA-256 Fallback Match
    if hashed_password.startswith("sha256:"):
        expected = "sha256:" + hashlib.sha256(plain_password.encode()).hexdigest()
        return expected == hashed_password

    # 2. Plain-text Match (in case passlib has failed during database seeding)
    if not hashed_password.startswith("$2b$") and not hashed_password.startswith("$2a$"):
        if plain_password == hashed_password:
            return True

    # 3. Standard Passlib verification
    try:
        return pwd_context.verify(
            plain_password,
            hashed_password,
        )
    except Exception as e:
        print(f"Fallback: passlib verification crashed ({e}). Trying plain-text fallback.")
        # Final plain-text check as a safety net
        return plain_password == hashed_password



# ------------------------------------------------------------------
# JWT
# ------------------------------------------------------------------

def create_access_token(
    data: dict,
    expires_delta: timedelta | None = None,
):
    """Generate JWT access token."""

    to_encode = data.copy()

    expire = datetime.utcnow() + (
        expires_delta
        if expires_delta
        else timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )

    to_encode.update(
        {
            "exp": expire
        }
    )

    return jwt.encode(
        to_encode,
        SECRET_KEY,
        algorithm=ALGORITHM,
    )


def decode_access_token(token: str):

    try:

        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM],
        )

        return payload

    except JWTError:

        return None
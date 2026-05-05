"""Authentication utilities – JWT tokens, password hashing, RBAC dependencies."""

import os
from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext

from app.models import UserInDB, UserRole

# ── Configuration ───────────────────────────────────────────────
# In production, SECRET_KEY must be provided through an environment variable.
SECRET_KEY = os.getenv("SECRET_KEY", "dev-only-change-me")
ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))

# ── Password hashing ───────────────────────────────────────────
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Return True if the plain password matches the stored hash."""
    return pwd_context.verify(plain_password, hashed_password)


def hash_password(password: str) -> str:
    """Return a bcrypt hash of the given password."""
    return pwd_context.hash(password)


# ── JWT helpers ─────────────────────────────────────────────────


def create_access_token(subject: str, role: str, expires_delta: timedelta | None = None) -> str:
    """Create a signed JWT containing the username and role."""
    expire = datetime.now(timezone.utc) + (
        expires_delta if expires_delta else timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode = {"sub": subject, "role": role, "exp": expire}
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


# ── FastAPI dependency: current user ────────────────────────────
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def _get_current_user(token: Annotated[str, Depends(oauth2_scheme)]) -> UserInDB:
    """Decode the JWT and return the corresponding UserInDB, or raise 401."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str | None = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    from app.store import user_store  # deferred to avoid circular imports

    user = user_store.get_by_username(username)
    if user is None:
        raise credentials_exception
    return user


# Typed dependency alias – routes use `current_user: CurrentUser`
CurrentUser = Annotated[UserInDB, Depends(_get_current_user)]


# ── RBAC helpers ────────────────────────────────────────────────

# Role hierarchy: ADMIN > ANALYST > VIEWER
_ROLE_RANK = {UserRole.VIEWER: 0, UserRole.ANALYST: 1, UserRole.ADMIN: 2}


def require_role(minimum_role: UserRole):
    """Return a FastAPI dependency that enforces a minimum role level.

    Usage in a route:
        @app.get("/admin-only", dependencies=[Depends(require_role(UserRole.ADMIN))])
    Or as a parameter:
        _auth: None = Depends(require_role(UserRole.ANALYST))
    """
    def _check(current_user: CurrentUser) -> None:
        if _ROLE_RANK[current_user.role] < _ROLE_RANK[minimum_role]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires role '{minimum_role.value}' or higher",
            )
    return _check

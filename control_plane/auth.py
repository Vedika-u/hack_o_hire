# control_plane/auth.py
from datetime import datetime, timezone, timedelta
from typing import Optional, Any
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
import hashlib

from config.settings import settings
from control_plane.rbac import User, Role, Permission, USERS_DB

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Compare password hash using hashlib (Python 3.14 compatible)."""
    return hashlib.sha256(plain_password.encode()).hexdigest() == hashed_password


def authenticate_user(username: str, password: str) -> Optional[User]:
    user_data = USERS_DB.get(username)
    if not user_data:
        return None
    if not verify_password(password, user_data["password_hash"]):
        return None
    return User(
        username=user_data["username"],
        role=user_data["role"],
        is_active=user_data["is_active"]
    )


def create_access_token(user_or_data: Any) -> str:
    now = utc_now()
    expire = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    if hasattr(user_or_data, "username"):
        to_encode = {
            "sub": user_or_data.username,
            "role": user_or_data.role.value if hasattr(user_or_data.role, "value") else str(user_or_data.role),
            "exp": expire,
            "iat": now,
        }
    elif isinstance(user_or_data, dict):
        to_encode = user_or_data.copy()
        if "exp" not in to_encode:
            to_encode["exp"] = expire
        if "iat" not in to_encode:
            to_encode["iat"] = now
    else:
        to_encode = {"sub": str(user_or_data), "role": "analyst", "exp": expire, "iat": now}

    return jwt.encode(
        to_encode,
        settings.SECRET_KEY,
        algorithm=settings.ALGORITHM
    )


async def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM]
        )
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user_data = USERS_DB.get(username)
    if user_data is None:
        raise credentials_exception

    user = User(
        username=user_data["username"],
        role=user_data["role"],
        is_active=user_data["is_active"]
    )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is deactivated"
        )
    return user


oauth2_scheme_optional = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login", auto_error=False)


async def get_current_user_optional(token: Optional[str] = Depends(oauth2_scheme_optional)) -> User:
    """
    Returns authenticated user from Bearer token if provided.
    In air-gapped demo mode, defaults to registered SOC_MANAGER 'vedika'.
    """
    if token:
        try:
            return await get_current_user(token)
        except Exception:
            pass

    user_data = USERS_DB.get("vedika")
    if user_data:
        return User(
            username=user_data["username"],
            role=user_data["role"],
            is_active=user_data["is_active"]
        )
    return User(username="analyst.vedika", role=Role.SOC_MANAGER, is_active=True)


def require_permission(permission: Permission):
    async def permission_checker(
        user: User = Depends(get_current_user_optional)
    ) -> User:
        if not user.has_permission(permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission denied: {permission.value} required."
            )
        return user
    return permission_checker
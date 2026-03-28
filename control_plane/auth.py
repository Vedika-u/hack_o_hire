# control_plane/auth.py
from datetime import datetime, timezone, timedelta
from typing import Optional
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


def create_access_token(user: User) -> str:
    now = utc_now()
    expire = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode = {
        "sub": user.username,
        "role": user.role.value,
        "exp": expire,
        "iat": now,
    }
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


def require_permission(permission: Permission):
    async def permission_checker(
        user: User = Depends(get_current_user)
    ) -> User:
        if not user.has_permission(permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission denied: {permission.value} required."
            )
        return user
    return permission_checker
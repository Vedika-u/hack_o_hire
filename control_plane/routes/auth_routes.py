# control_plane/routes/auth_routes.py
"""
Authentication endpoints.
Login and get JWT token.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel
from control_plane.auth import authenticate_user, create_access_token

router = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


@router.post("/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    Login with username and password.
    Returns JWT token to use in all other requests.

    Test users:
      analyst1 / password123
      senior1  / password123
      manager1 / password123
      admin1   / password123
    """
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = create_access_token(user)
    return Token(access_token=access_token)
"""
TrustGuard v2.0 — Auth API Routes v1
Backward compatible with v1.0 endpoints.
Standards: Part 3 §26, §27
"""

from __future__ import annotations

import jwt as pyjwt

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from config.settings import get_settings
from database.session import get_db
from repositories.user_repo import UserRepository
from schemas.auth import LoginRequest, RefreshRequest, RegisterRequest
from services.auth_service import AuthError, AuthService
from utils.jwt_utils import create_access_token, create_refresh_token

router = APIRouter(prefix="/portal/auth", tags=["Auth"])


def _auth_service(db: Session = Depends(get_db)) -> AuthService:
    return AuthService(UserRepository(db))


@router.post(
    "/register",
    status_code=201,
    summary="Register new user",
    description="Create a new user account. Password must be at least 8 characters.",
)
def register(body: RegisterRequest, request: Request, service: AuthService = Depends(_auth_service)):
    try:
        result = service.register(body.email, body.password)
        return {"message": result["message"]}
    except AuthError as e:
        raise HTTPException(status_code=409, detail=str(e.description))


@router.post(
    "/login",
    summary="User login",
    description="Obtain JWT access token and refresh token.",
)
def login(body: LoginRequest, request: Request, service: AuthService = Depends(_auth_service)):
    try:
        result = service.login(body.email, body.password)
        return {
            "access_token": result["access_token"],
            "refresh_token": result["refresh_token"],
            "token_type": result["token_type"],
        }
    except AuthError as e:
        raise HTTPException(status_code=401, detail=str(e.description))


@router.post(
    "/refresh",
    summary="Refresh access token",
    description="Exchange a valid refresh token for a new access token.",
)
def refresh_token(body: RefreshRequest, db: Session = Depends(get_db)):
    settings = get_settings()
    try:
        payload = pyjwt.decode(body.refresh_token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
    except pyjwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Refresh token has expired. Please log in again.")
    except pyjwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid refresh token.")

    if payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Invalid token type.")

    user_id = payload.get("sub")
    user = UserRepository(db).get_by_id(user_id)
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or account disabled.")

    return {
        "access_token": create_access_token(user.id, user.role),
        "refresh_token": create_refresh_token(user.id),
        "token_type": "bearer",
    }

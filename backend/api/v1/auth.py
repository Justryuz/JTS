"""
TrustGuard v2.0 — Auth API Routes v1
Backward compatible with v1.0 endpoints.
Standards: Part 3 §26, §27
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from database.session import get_db
from repositories.user_repo import UserRepository
from schemas.auth import LoginRequest, RegisterRequest, TokenResponse
from schemas.common import StandardResponse
from services.auth_service import AuthError, AuthService

router = APIRouter(prefix="/portal/auth", tags=["Auth"])


def _auth_service(db: Session = Depends(get_db)) -> AuthService:
    return AuthService(UserRepository(db))


@router.post(
    "/register",
    status_code=201,
    summary="Daftar pengguna baru",
    description="Buat akaun pengguna baru. Kata laluan mesti sekurang-kurangnya 8 aksara, mengandungi huruf besar dan nombor.",
)
def register(body: RegisterRequest, request: Request, service: AuthService = Depends(_auth_service)):
    try:
        result = service.register(body.email, body.password)
        return {"message": result["message"]}
    except AuthError as e:
        raise HTTPException(status_code=409, detail=str(e.description))


@router.post(
    "/login",
    summary="Log masuk pengguna",
    description="Dapatkan JWT access token dan refresh token.",
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

"""
TrustGuard v2.0 — JWT Utilities
Access token (short-lived) + Refresh token (long-lived).
Standards: Part 3 §30
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from config.constants import ErrorCode
from config.settings import get_settings

bearer_scheme = HTTPBearer()


def create_access_token(user_id: str, role: str) -> str:
    settings = get_settings()
    payload = {
        "sub": user_id,
        "role": role,
        "type": "access",
        "exp": datetime.now(timezone.utc) + timedelta(minutes=settings.jwt_access_expire_minutes),
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def create_refresh_token(user_id: str) -> str:
    settings = get_settings()
    payload = {
        "sub": user_id,
        "type": "refresh",
        "exp": datetime.now(timezone.utc) + timedelta(days=settings.jwt_refresh_expire_days),
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def decode_token(token: str) -> dict:
    settings = get_settings()
    try:
        return jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": ErrorCode.TOKEN_EXPIRED, "title": "Token Expired",
                    "description": "JWT token has expired.",
                    "recommendation": "Log in again to obtain a new token.",
                    "reference": "RFC 7519"},
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": ErrorCode.TOKEN_INVALID, "title": "Token Invalid",
                    "description": "JWT token is invalid or has been tampered with.",
                    "recommendation": "Ensure the token is sent correctly in the Authorization header.",
                    "reference": "RFC 7519"},
        )


def verify_jwt(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
) -> dict:
    """FastAPI dependency — returns decoded JWT payload."""
    return decode_token(credentials.credentials)


def get_current_user_id(payload: dict = Depends(verify_jwt)) -> str:
    return payload["sub"]


def get_current_role(payload: dict = Depends(verify_jwt)) -> str:
    return payload.get("role", "readonly")

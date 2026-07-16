"""
TrustGuard v2.0 — Auth Service
Business logic for registration, login, and token management.
This class has NO dependency on FastAPI — fully testable in isolation.
Standards: Part 3 §30, Clean Architecture
"""

from __future__ import annotations

from passlib.context import CryptContext

from config.constants import ErrorCode
from config.settings import get_settings
from repositories.user_repo import UserRepository
from utils.jwt_utils import create_access_token, create_refresh_token

_pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class AuthError(Exception):
    def __init__(self, code: str, title: str, description: str, recommendation: str = "", reference: str = "") -> None:
        self.code = code
        self.title = title
        self.description = description
        self.recommendation = recommendation
        self.reference = reference
        super().__init__(title)


class AuthService:
    def __init__(self, user_repo: UserRepository) -> None:
        self._repo = user_repo
        self._settings = get_settings()

    def register(self, email: str, password: str) -> dict:
        if self._repo.exists_by_email(email):
            raise AuthError(
                code=ErrorCode.EMAIL_ALREADY_REGISTERED,
                title="Email Already Registered",
                description=f"Email {email} is already registered.",
                recommendation="Use a different email or log in.",
            )
        password_hash = _pwd_context.hash(password)
        user = self._repo.create(email=email, password_hash=password_hash)
        return {"message": "User registered successfully", "user_id": user.id}

    def login(self, email: str, password: str) -> dict:
        user = self._repo.get_by_email(email)
        if not user or not _pwd_context.verify(password, user.password_hash):
            raise AuthError(
                code=ErrorCode.INVALID_CREDENTIALS,
                title="Invalid Credentials",
                description="Invalid email or password.",
                recommendation="Check your email and password.",
                reference="OWASP ASVS 2.1",
            )
        if not user.is_active:
            raise AuthError(
                code=ErrorCode.INSUFFICIENT_PERMISSION,
                title="Account Disabled",
                description="Your account has been deactivated.",
                recommendation="Contact your system administrator.",
            )
        access_token = create_access_token(user.id, user.role)
        refresh_token = create_refresh_token(user.id)
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "expires_in": self._settings.jwt_access_expire_minutes * 60,
        }

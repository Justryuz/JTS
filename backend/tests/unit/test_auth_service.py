"""
TrustGuard v2.0 — Unit Tests: Auth Service
Tests: register, login, duplicate email, wrong password.
Standards: Part 4 §37, DoD §41
"""

from __future__ import annotations

import pytest
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from unittest.mock import MagicMock, patch
from services.auth_service import AuthService, AuthError
from config.constants import ErrorCode


def _make_service(user=None, exists=False):
    repo = MagicMock()
    repo.get_by_email.return_value = user
    repo.exists_by_email.return_value = exists
    repo.create.return_value = MagicMock(id="user-123")
    return AuthService(repo)


def _make_user(email="test@example.com", active=True):
    user = MagicMock()
    user.id = "user-123"
    user.email = email
    user.password_hash = "<mocked-hash>"
    user.role = "developer"
    user.is_active = active
    return user


# ── Register ──────────────────────────────────────────────────────────────────

def test_register_success():
    with patch("services.auth_service._pwd_context") as mock_pwd:
        mock_pwd.hash.return_value = "<hashed>"
        service = _make_service(exists=False)
        result = service.register("new@example.com", "Password1")
    assert result["message"] == "User registered successfully"


def test_register_duplicate_email():
    service = _make_service(exists=True)
    with pytest.raises(AuthError) as exc:
        service.register("dup@example.com", "Password1")
    assert exc.value.code == ErrorCode.EMAIL_ALREADY_REGISTERED


# ── Login ─────────────────────────────────────────────────────────────────────

def test_login_success():
    user = _make_user()
    with patch("services.auth_service._pwd_context") as mock_pwd:
        mock_pwd.verify.return_value = True
        service = _make_service(user=user)
        result = service.login("test@example.com", "Password1")
    assert "access_token" in result
    assert "refresh_token" in result
    assert result["token_type"] == "bearer"


def test_login_wrong_password():
    user = _make_user()
    with patch("services.auth_service._pwd_context") as mock_pwd:
        mock_pwd.verify.return_value = False
        service = _make_service(user=user)
        with pytest.raises(AuthError) as exc:
            service.login("test@example.com", "WrongPass1")
    assert exc.value.code == ErrorCode.INVALID_CREDENTIALS


def test_login_user_not_found():
    service = _make_service(user=None)
    with pytest.raises(AuthError) as exc:
        service.login("notfound@example.com", "Password1")
    assert exc.value.code == ErrorCode.INVALID_CREDENTIALS


def test_login_inactive_user():
    user = _make_user(active=False)
    with patch("services.auth_service._pwd_context") as mock_pwd:
        mock_pwd.verify.return_value = True
        service = _make_service(user=user)
        with pytest.raises(AuthError) as exc:
            service.login("test@example.com", "Password1")
    assert exc.value.code == ErrorCode.INSUFFICIENT_PERMISSION

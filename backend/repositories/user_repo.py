"""
TrustGuard v2.0 — User Repository
All database access for User model goes through this class.
Business logic must NOT access the database directly.
Standards: Part 3 §36, Repository Pattern
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from models.user import User
from utils.hashing import sha256_hash


class UserRepository:
    def __init__(self, db: Session) -> None:
        self._db = db

    def get_by_email(self, email: str) -> User | None:
        return self._db.query(User).filter(User.email == email).first()

    def get_by_id(self, user_id: str) -> User | None:
        return self._db.query(User).filter(User.id == user_id).first()

    def create(self, email: str, password_hash: str, role: str = "developer") -> User:
        user = User(email=email, password_hash=password_hash, role=role)
        self._db.add(user)
        self._db.commit()
        self._db.refresh(user)
        return user

    def exists_by_email(self, email: str) -> bool:
        return self._db.query(User).filter(User.email == email).count() > 0

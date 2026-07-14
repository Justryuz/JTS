"""
TrustGuard v2.0 — Database Session Management
Supports SQLite (development) and PostgreSQL (production).
Standards: Repository Pattern, Connection Pooling
"""

from __future__ import annotations

import os
from collections.abc import Generator

from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import Session, sessionmaker

from config.settings import get_settings


def _build_engine():
    settings = get_settings()
    db_url = settings.database_url

    # Ensure storage/database directory exists for SQLite
    if db_url.startswith("sqlite"):
        db_path = db_url.replace("sqlite:///", "").replace("sqlite://", "")
        os.makedirs(os.path.dirname(db_path) if os.path.dirname(db_path) else ".", exist_ok=True)
        engine = create_engine(
            db_url,
            connect_args={"check_same_thread": False},
            echo=settings.db_echo,
        )
        # Enable foreign keys. WAL mode is skipped on network/NTFS mounts (WSL)
        @event.listens_for(engine, "connect")
        def set_wal_mode(dbapi_conn, _):
            try:
                dbapi_conn.execute("PRAGMA journal_mode=WAL")
            except Exception:
                pass  # WAL not supported on NTFS/network mounts (WSL /mnt/c/)
            dbapi_conn.execute("PRAGMA foreign_keys=ON")
    else:
        engine = create_engine(
            db_url,
            pool_size=settings.db_pool_size,
            max_overflow=settings.db_max_overflow,
            echo=settings.db_echo,
            pool_pre_ping=True,
        )
    return engine


engine = _build_engine()

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency — yields a database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def run_migrations() -> None:
    """Apply lightweight schema migrations for SQLite compatibility."""
    from models.base import Base
    Base.metadata.create_all(bind=engine)

    if not engine.url.drivername.startswith("sqlite"):
        return

    migrations = [
        # api_keys
        ("api_keys", "is_verified", "ALTER TABLE api_keys ADD COLUMN is_verified BOOLEAN DEFAULT 0"),
        ("api_keys", "verification_token", "ALTER TABLE api_keys ADD COLUMN verification_token TEXT"),
        ("api_keys", "verification_method", "ALTER TABLE api_keys ADD COLUMN verification_method TEXT DEFAULT 'http_file'"),
        ("api_keys", "verified_at", "ALTER TABLE api_keys ADD COLUMN verified_at DATETIME"),
        ("api_keys", "role", "ALTER TABLE api_keys ADD COLUMN role TEXT DEFAULT 'developer'"),
        # users
        ("users", "role", "ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'developer'"),
        ("users", "is_active", "ALTER TABLE users ADD COLUMN is_active BOOLEAN DEFAULT 1"),
        # scan_jobs
        ("scan_jobs", "result_json", "ALTER TABLE scan_jobs ADD COLUMN result_json TEXT"),
    ]

    with engine.connect() as conn:
        for table, column, sql in migrations:
            try:
                result = conn.execute(text(f"PRAGMA table_info({table})"))
                existing = {row[1] for row in result.fetchall()}
                if column not in existing:
                    conn.execute(text(sql))
                    conn.commit()
            except Exception:
                pass

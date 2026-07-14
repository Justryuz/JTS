"""
TrustGuard v2.0 — Application Factory
This file ONLY registers middleware and routers.
All business logic lives in services/, engines/, scanners/.
Standards: Clean Architecture, Part 2 §12
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

# Ensure backend/ is on sys.path when running directly
_BASE_DIR = Path(__file__).parent
sys.path.insert(0, str(_BASE_DIR))

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

from config.settings import get_settings
from database.session import run_migrations
from middleware.audit_log import AuditLogMiddleware
from middleware.rate_limit import RateLimitMiddleware
from middleware.request_id import RequestIDMiddleware
from middleware.security_headers import SecurityHeadersMiddleware

# ── Logging setup ─────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
)

settings = get_settings()

# ── Run DB migrations on startup ──────────────────────────────────────────────
run_migrations()

# ── App factory ───────────────────────────────────────────────────────────────
tags_metadata = [
    {"name": "Auth", "description": "Pendaftaran dan log masuk pengguna."},
    {"name": "Portal", "description": "Pengurusan API key, log, dan statistik."},
    {"name": "Shield", "description": "Gateway imbasan prompt AI."},
    {"name": "Scan", "description": "Imbasan kod, repo, URL, dan ZIP."},
    {"name": "Compliance", "description": "Skor pematuhan dan laporan audit PDF."},
    {"name": "Admin", "description": "Kemaskini enjin dan model."},
    {"name": "Health", "description": "Status sistem."},
]

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description=(
        "TrustGuard v2.0 — Enterprise AI Security Platform. "
        "Melindungi aplikasi AI daripada Prompt Injection, Jailbreak, CVE/CWE, dan ancaman OWASP LLM Top 10."
    ),
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    openapi_tags=tags_metadata,
)

# ── Middleware stack (outer → inner) ──────────────────────────────────────────
app.add_middleware(AuditLogMiddleware)
app.add_middleware(RateLimitMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=settings.cors_allow_credentials,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(RequestIDMiddleware)

# ── Routers ───────────────────────────────────────────────────────────────────
from api.v1.auth import router as auth_router
from api.v1.gateway import router as gateway_router
from api.v1.portal import router as portal_router
from api.v1.scan import router as scan_router
from api.v1.admin import router as admin_router
from api.v1.report import router as report_router

app.include_router(auth_router)
app.include_router(gateway_router)
app.include_router(portal_router)
app.include_router(scan_router)
app.include_router(admin_router)
app.include_router(report_router)

# ── Frontend static pages ─────────────────────────────────────────────────────
_FRONTEND_DIR = _BASE_DIR.parent / "frontend"
_ALLOWED_PAGES = {"index.html", "portal.html"}


def _serve(page: str) -> FileResponse:
    # CWE-22: whitelist only known pages — never accept user-controlled path segments
    if page not in _ALLOWED_PAGES:
        raise HTTPException(status_code=404, detail="Page not found")
    file_path = _FRONTEND_DIR / page
    if not file_path.is_file():
        raise HTTPException(status_code=404, detail="Page not found")
    return FileResponse(str(file_path))


@app.get("/", include_in_schema=False)
def serve_landing():
    return _serve("index.html")


@app.get("/index.html", include_in_schema=False)
def serve_landing_index():
    return _serve("index.html")


@app.get("/portal", include_in_schema=False)
@app.get("/portal/", include_in_schema=False)
@app.get("/portal.html", include_in_schema=False)
def serve_portal():
    return _serve("portal.html")


# ── Health check ──────────────────────────────────────────────────────────────
@app.get("/health", tags=["Health"], summary="Semak kesihatan servis")
def health():
    from engines import ml_engine
    return {
        "status": "ok",
        "engine": "ACTIVE",
        "version": settings.app_version,
        "ml_available": ml_engine.is_available(),
    }


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=settings.debug)

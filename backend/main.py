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
from fastapi.responses import FileResponse, HTMLResponse

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


def _warmup_ml_models() -> None:
    """Pre-load all ML models in background so first scan request is fast."""
    import threading
    def _load():
        try:
            from engines import ml_engine
            ml_engine._load_injection_model()
            ml_engine._load_injection_v2_model()
            ml_engine._load_toxic_model()
            ml_engine._load_toxic_bert_model()
            ml_engine._load_code_model()
            logging.getLogger(__name__).info("ML models warmed up successfully.")
        except Exception as e:
            logging.getLogger(__name__).warning(f"ML model warm-up failed: {e}")
    threading.Thread(target=_load, daemon=True).start()


_warmup_ml_models()
# ── App factory ───────────────────────────────────────────────────────────────
tags_metadata = [
    {
        "name": "Auth",
        "description": (
            "Register and authenticate users. All portal endpoints require a JWT Bearer token "
            "obtained from `/portal/auth/login`.\n\n"
            "**Password policy:** minimum 8 characters."
        ),
    },
    {
        "name": "Portal",
        "description": (
            "Manage API keys, view security logs, and check statistics.\n\n"
            "All endpoints require `Authorization: Bearer <token>` header.\n\n"
            "- Generate API keys per domain\n"
            "- View real-time prompt scan logs with `source_page` tracking\n"
            "- Get threat statistics and compliance scores"
        ),
    },
    {
        "name": "Shield",
        "description": (
            "Core gateway endpoint. Route every user prompt through `/api/v1/shield` "
            "before it reaches your AI model.\n\n"
            "**Required headers:**\n"
            "- `X-API-Key: aisec_live_xxx`\n"
            "- `X-Origin-Domain: yourdomain.com`\n\n"
            "**Detection engine:** Hybrid (Rule-based 39 OWASP patterns + ML models)\n\n"
            "**source_page tracking:** Pass `source_page` in body or rely on automatic HTTP `Referer` header fallback."
        ),
    },
    {
        "name": "Scan",
        "description": (
            "Security scanning tools for source code, GitHub repositories, live URLs, and ZIP uploads.\n\n"
            "**Required headers:** `X-API-Key` and `X-Origin-Domain`\n\n"
            "| Endpoint | Target | Engine |\n"
            "|---|---|---|\n"
            "| `/scan/code` | Source code string | Hybrid (Rule + ML) |\n"
            "| `/scan/repo` | GitHub public repo | Aggregator |\n"
            "| `/scan/url` | Live website | DAST |\n"
            "| `/scan/upload` | ZIP project file | Aggregator |\n\n"
            "Repo and ZIP scans run as **background jobs** — poll `/scan/status/{job_id}` for results."
        ),
    },
    {
        "name": "Compliance",
        "description": (
            "PDF audit report generation aligned with Malaysian and international standards.\n\n"
            "Standards covered: OWASP Top 10, OWASP LLM Top 10, CWE/SANS Top 25, "
            "NACSA, JPDP/PDPA 2010, MCMC CMA 1998, AIGE, MY-AI Standards."
        ),
    },
    {
        "name": "Admin",
        "description": (
            "Update OWASP rule patterns and refresh HuggingFace ML models.\n\n"
            "Requires JWT. Models re-download on next scan request after refresh."
        ),
    },
    {
        "name": "Health",
        "description": "System health check. Returns API status, engine state, ML model availability, and version.",
    },
]

app = FastAPI(
    title="TrustGuard",
    version=settings.app_version,
    description=(
        "## Enterprise AI Security Gateway\n\n"
        "TrustGuard is a centralised security layer protecting LLM models and AI applications "
        "from **Prompt Injection**, **Jailbreak**, **CVE/CWE vulnerabilities**, and **OWASP LLM Top 10** threats.\n\n"
        "### Quick Start\n\n"
        "1. Register an account → `POST /portal/auth/register`\n"
        "2. Login → `POST /portal/auth/login` → get `access_token`\n"
        "3. Generate API Key → `POST /portal/api-key/generate`\n"
        "4. Route prompts → `POST /api/v1/shield` with `X-API-Key` header\n\n"
        "### Standards\n\n"
        "OWASP Top 10 · OWASP LLM Top 10 · CWE/SANS Top 25 · NACSA · JPDP/PDPA 2010 · MCMC CMA 1998 · AIGE · MY-AI Standards"
    ),
    docs_url=None,
    redoc_url=None,
    openapi_url="/openapi.json",
    openapi_tags=tags_metadata,
    contact={"name": "TrustGuard Support", "url": "http://localhost:8000"},
    license_info={"name": "Proprietary"},
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

# ── API Docs (Scalar) ─────────────────────────────────────────────────────────
@app.get("/docs", include_in_schema=False)
def scalar_docs():
    html = """
<!DOCTYPE html>
<html>
<head>
    <title>TrustGuard API Docs</title>
    <meta charset="utf-8"/>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>body { margin: 0; }</style>
</head>
<body>
    <script
        id="api-reference"
        data-url="/openapi.json"
        data-configuration='{
            "theme": "purple",
            "darkMode": true,
            "layout": "sidebar",
            "defaultHttpClient": {"targetKey": "python", "clientKey": "requests"},
            "hiddenClients": [],
            "favicon": "/favicon.ico",
            "metadata": {"title": "TrustGuard API Docs"}
        }'
    ></script>
    <script src="https://cdn.jsdelivr.net/npm/@scalar/api-reference"></script>
</body>
</html>
"""
    return HTMLResponse(html)



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
@app.get("/health", tags=["Health"], summary="Check service health")
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

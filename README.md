# TrustGuard v2.0 — Enterprise AI Security Gateway

> A centralised security layer protecting LLM models and AI applications from cyber attacks, prompt injection, jailbreak, and code vulnerabilities.

---

## Objective

TrustGuard is built to address the increasingly critical AI security needs in Malaysia and globally. The platform acts as a **centralised defence layer** between users and AI models, ensuring every interaction is scanned, logged, and evaluated against international and local security standards.

**Key objectives:**
- Protect LLM models from Prompt Injection & Jailbreak (OWASP LLM Top 10)
- Detect CVE/CWE vulnerabilities in AI-generated source code
- Ensure compliance with Malaysian regulations (JPDP, NACSA, MCMC, AIGE)
- Provide audit security reports submittable to authorities

---

## Development Info

| Field | Details |
|---|---|
| Version | 2.0.0 |
| Backend Language | Python 3.12 |
| Framework | FastAPI |
| Database | SQLite (migratable to PostgreSQL) |
| ML Engine | HuggingFace Transformers |
| Frontend | HTML + Tailwind CSS |
| Environment | WSL (Ubuntu) — run from Linux filesystem |
| Development Location | Sungai Buloh, Selangor, Malaysia |

---

## System Components (v2.0 — Clean Architecture)

```
JTS/
├── backend/
│   ├── main.py                      # App factory — middleware + routers only
│   ├── requirements.txt
│   ├── .env                         # Environment config (DO NOT commit)
│   ├── config/
│   │   ├── settings.py              # Pydantic BaseSettings — all config from .env
│   │   └── constants.py             # Enums: AttackType, ErrorCode (TG-XXXX), Severity
│   ├── models/
│   │   ├── base.py                  # DeclarativeBase, TimestampMixin, UUIDPrimaryKeyMixin
│   │   ├── user.py                  # User model (RBAC: admin/analyst/developer/auditor)
│   │   ├── api_key.py               # ApiKey model
│   │   └── log.py                   # PromptLog, AuditLog, ScanJob
│   ├── schemas/
│   │   ├── common.py                # StandardResponse, ErrorResponse
│   │   ├── auth.py                  # RegisterRequest, LoginRequest (min 8 chars)
│   │   ├── gateway.py               # ShieldRequest, ResponseFirewallRequest
│   │   └── scan.py                  # CodeScanRequest, RepoScanRequest, UrlScanRequest
│   ├── services/
│   │   ├── auth_service.py          # AuthService — no FastAPI dependency
│   │   ├── shield_service.py        # ShieldService with TTLCache
│   │   └── api_key_service.py       # ApiKeyService
│   ├── repositories/
│   │   ├── user_repo.py
│   │   ├── api_key_repo.py
│   │   └── log_repo.py              # Append-only AuditLog, ScanJob CRUD
│   ├── middleware/
│   │   ├── request_id.py            # X-Request-ID header
│   │   ├── security_headers.py      # CSP, HSTS, X-Frame-Options
│   │   ├── rate_limit.py            # Sliding window per-IP
│   │   └── audit_log.py             # JSON structured logging
│   ├── engines/
│   │   ├── rule_engine.py           # Rule-based (39 OWASP patterns)
│   │   ├── ml_engine.py             # HuggingFace ML models
│   │   └── hybrid_engine.py         # Hybrid (Rule → ML)
│   ├── scanners/
│   │   ├── cve_scanner.py           # CVE/CWE + NACSA/JPDP/MCMC scanner
│   │   ├── secret_scanner.py        # Secret & API key exposure scanner
│   │   ├── dependency_scanner.py    # Supply chain / dependency scanner
│   │   └── aggregator.py            # Project-level result aggregator
│   ├── ingest/
│   │   ├── github_ingest.py         # GitHub repo clone & scan
│   │   ├── zip_ingest.py            # ZIP upload extract & scan
│   │   └── url_ingest.py            # Live URL DAST scanner
│   ├── api/v1/
│   │   ├── auth.py                  # /portal/auth/register, /login
│   │   ├── portal.py                # /portal/stats, /logs, /api-keys, /generate
│   │   ├── gateway.py               # /api/v1/shield
│   │   ├── scan.py                  # /api/v1/scan/code|repo|url|upload
│   │   ├── admin.py                 # /admin/update
│   │   └── report.py                # /portal/report/pdf
│   ├── utils/
│   │   ├── hashing.py
│   │   ├── jwt_utils.py             # Access + refresh tokens
│   │   ├── cache.py                 # TTLCache
│   │   └── domain_verify.py
│   ├── database/
│   │   └── session.py               # SQLite/PostgreSQL, WAL mode, auto-migration
│   ├── compliance/
│   │   └── scorer.py
│   ├── reports/
│   │   └── pdf_generator.py
│   ├── engine/                      # Legacy (kept for backward compatibility)
│   │   └── updater.py
│   └── tests/
│       ├── unit/
│       │   ├── test_rule_engine.py  # 39 parametrized tests
│       │   └── test_auth_service.py # 6 tests
│       └── security/
│           └── test_security.py     # SSRF, path traversal, injection tests
└── frontend/
    ├── index.html                   # Landing page
    └── portal.html                  # Management portal
```

---

## AI Models Used

| Model | Source | Function |
|---|---|---|
| `deepset/deberta-v3-base-injection` | HuggingFace | Detect Prompt Injection |
| `martin-ha/toxic-comment-model` | HuggingFace | Detect toxic content / Jailbreak |
| Rule-based Regex Engine | Custom | 39 OWASP LLM01/LLM02 patterns |

All models run **fully offline** after first download. No data is sent to third parties.

> Model cache is stored at `~/.cache/huggingface/hub/`. Use the `/admin/update` endpoint to refresh models to the latest version.

---

## Standards & Compliance

| Standard | Scope |
|---|---|
| OWASP Top 10 (2021) | Web application security |
| OWASP LLM Top 10 | AI/LLM model security |
| CWE/SANS Top 25 | Source code vulnerabilities |
| NACSA AI Security Framework | National AI security |
| JPDP / PDPA 2010 | Personal data protection |
| MCMC CMA 1998 | Communications & multimedia |
| AIGE | National AI ethics |
| MY-AI Standards (SIRIM/JSM) | Malaysian AI technical standards |

---

## API Documentation

### Base URL
```
http://localhost:8000
```

Interactive documentation (Swagger UI): `http://localhost:8000/docs`

---

### Auth Endpoints

#### `POST /portal/auth/register`
Register a new user account. Password minimum 8 characters.

```json
// Request
{ "email": "user@example.com", "password": "Password8" }

// Response 201
{ "message": "User registered successfully" }

// Response 409 — email already registered
{ "detail": "Emel user@example.com telah didaftarkan." }
```

#### `POST /portal/auth/login`
Log in and retrieve JWT tokens.

```json
// Request
{ "email": "user@example.com", "password": "Password8" }

// Response 200
{ "access_token": "eyJ...", "refresh_token": "eyJ...", "token_type": "bearer" }

// Response 401 — invalid credentials
{ "detail": "Emel atau kata laluan tidak betul." }
```

---

### Portal Endpoints (Requires JWT)

Header: `Authorization: Bearer <token>`

#### `POST /portal/api-key/generate`
Generate a new API Key for a domain. Key is shown **once only**.

```json
// Request
{ "allowed_domain": "mywebsite.com" }

// Response 201
{
  "api_key": "aisec_live_xxxxxxxxxxxx",
  "allowed_domain": "mywebsite.com",
  "warning": "Copy this key now. It will NOT be shown again."
}
```

#### `GET /portal/api-keys`
List all API keys owned by the user. Returns array directly.

#### `GET /portal/api-key/{key_id}`
Check API key status and get domain verification instructions.

#### `POST /portal/api-key/{key_id}/verify`
Verify domain ownership and trigger auto-scan.

```json
// Request
{
  "target_url": "https://mywebsite.com",
  "repo_url": "https://github.com/user/repo",
  "branch": "main"
}
```

#### `DELETE /portal/api-key/{key_id}`
Revoke an API key.

#### `GET /portal/stats`
Prompt scan statistics. Returns flat JSON.

```json
{ "total_requests": 100, "total_blocked": 12, "engine_status": "ACTIVE" }
```

#### `GET /portal/logs`
Real-time security logs (latest 100). Returns array directly.

#### `GET /portal/compliance/{domain}`
Compliance score for a specific domain.

#### `POST /portal/report/pdf`
Generate a PDF audit report.

```json
// Request
{ "code": "<source code>", "filename": "app.py" }
// Response: PDF file download
```

#### `POST /admin/update`
Update OWASP rule patterns and/or refresh ML models. Requires JWT.

```json
// Request
{ "update_rules": true, "update_models": true }

// Response
{
  "success": true,
  "rules_updated": true,
  "models_refreshed": ["deepset/deberta-v3-base-injection", "martin-ha/toxic-comment-model"],
  "errors": [],
  "timestamp": "2025-01-01T00:00:00+00:00",
  "note": "Models will re-download on next scan request."
}
```

---

### Public Gateway Endpoints (Requires API Key)

Headers: `X-API-Key: aisec_live_xxx` and `X-Origin-Domain: domain.com`

#### `POST /api/v1/shield`
Scan an AI prompt for threats.

```json
// Request
{ "prompt": "user prompt text" }

// Response — Safe
{ "status": "ALLOWED" }

// Response — Blocked
{ "status": "BLOCKED", "reason": "PROMPT_INJECTION" }
```

#### `POST /api/v1/scan/code`
Scan source code for CVE/CWE vulnerabilities.

```json
// Request
{ "code": "<source code>", "filename": "app.py", "engine_mode": "hybrid" }

// Response
{
  "total_issues": 3,
  "severity_breakdown": { "critical": 1, "high": 1, "medium": 1, "low": 0 },
  "vulnerabilities": [...],
  "compliance_flags": [...],
  "compliance_score": { "overall": 72.5, "grade": "B", "breakdown": {...} }
}
```

#### `POST /api/v1/scan/repo`
Scan an entire GitHub repository for CVE/CWE, secrets, and dependency issues.

```json
// Request
{ "repo_url": "https://github.com/user/repo", "branch": "main" }
```

Limits: Repository must be public, size < 200MB, < 500 files.

#### `POST /api/v1/scan/url`
Scan a live website for security issues (basic DAST).

```json
// Request
{ "url": "https://target-website.com" }
```

Checks: Exposed paths, security headers, error leak, CORS, SSL/TLS.

#### `POST /api/v1/scan/upload`
Upload a ZIP project file for scanning.

```
// Request: multipart/form-data
field: file (ZIP)
```

Limits: ZIP size < 200MB after extraction, < 500 files.

---

### System Endpoint

#### `GET /health`

```json
{
  "status": "ok",
  "engine": "ACTIVE",
  "version": "2.0.0",
  "ml_available": true
}
```

---

## Installation & Setup

> **Important:** Run from WSL (Linux filesystem), not directly from Windows. SQLite WAL mode does not work on NTFS (`/mnt/c/`).

```bash
# 1. Open WSL terminal, navigate to directory
cd /mnt/c/Users/fahmi/Downloads/JTS/backend

# 2. Create virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure .env
#    JWT_SECRET is already set — change if needed
#    Use Linux path for DATABASE_URL: sqlite:////tmp/trustguard/aisec.db

# 5. Run server
python main.py
```

Open `http://localhost:8000` in browser.

### WSL / Windows Notes

| Issue | Solution |
|---|---|
| SQLite WAL error on `/mnt/c/` | Use `DATABASE_URL=sqlite:////tmp/trustguard/aisec.db` |
| Server using old code after edit | Delete `__pycache__` and restart |
| Python 3.13 (Windows) vs 3.12 (WSL) | Always run inside WSL venv |

```bash
# Clear cache if server is using old code
find . -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null
python main.py
```

---

## Integration Guide

External systems can integrate in 3 steps:

1. Register an account at the portal → Generate an API Key for your domain
2. Send every user prompt to `/api/v1/shield` before it reaches your AI model
3. Only `ALLOWED` prompts are forwarded to your AI model

```python
import requests

response = requests.post(
    "http://localhost:8000/api/v1/shield",
    headers={
        "X-API-Key": "aisec_live_xxxx",
        "X-Origin-Domain": "mywebsite.com"
    },
    json={"prompt": user_input}
)

if response.json()["status"] == "BLOCKED":
    return "Your request cannot be processed."
```

---

## What's New in v2.0

| Area | v1.0 | v2.0 |
|---|---|---|
| Structure | 700-line monolith `main.py` | Clean Architecture — config, models, schemas, services, repositories |
| Auth | Inline in `main.py` | Separate `AuthService`, testable without FastAPI |
| Middleware | None | RequestID, SecurityHeaders, RateLimit, AuditLog |
| Error codes | Random strings | TG-XXXX series (TG-1001 to TG-9001) |
| Database | SQLite only | SQLite + PostgreSQL, WAL mode, auto-migration |
| Tests | None | 63 tests — unit, auth, security |
| Password validation | No clear limit | Minimum 8 characters |
| Response format | Inconsistent | Flat JSON for all portal endpoints (backward compatible) |

---

## License & Credits

Built with passion from **Sungai Buloh, Selangor, Malaysia**.

Standards reference: OWASP, NACSA, JPDP, MCMC, AIGE, MY-AI Standards (SIRIM/JSM).

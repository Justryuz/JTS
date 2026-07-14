# TrustGuard v2.0 — Enterprise AI Security Gateway

> Sistem keselamatan berpusat untuk melindungi model LLM dan aplikasi AI daripada serangan siber, prompt injection, jailbreak, dan kelemahan kod.

---

## Objektif

TrustGuard dibina untuk menjawab keperluan keselamatan AI yang semakin kritikal di Malaysia dan global. Platform ini bertindak sebagai **lapisan pertahanan berpusat** antara pengguna dan model AI, memastikan setiap interaksi diimbas, dilog, dan dinilai mengikut standard keselamatan antarabangsa dan tempatan.

**Matlamat utama:**
- Melindungi model LLM daripada Prompt Injection & Jailbreak (OWASP LLM Top 10)
- Mengesan kelemahan CVE/CWE dalam kod sumber yang dijanakan oleh AI
- Memastikan pematuhan kepada perundangan Malaysia (JPDP, NACSA, MCMC, AIGE)
- Menyediakan laporan audit keselamatan yang boleh dikemukakan kepada pihak berkuasa

---

## Maklumat Pembangunan

| Perkara | Butiran |
|---|---|
| Versi | 2.0.0 |
| Bahasa Backend | Python 3.12 |
| Framework | FastAPI |
| Database | SQLite (boleh migrate ke PostgreSQL) |
| ML Engine | HuggingFace Transformers |
| Frontend | HTML + Tailwind CSS |
| Persekitaran | WSL (Ubuntu) — jalankan dari Linux filesystem |
| Lokasi Pembangunan | Sungai Buloh, Selangor, Malaysia |

---

## Komponen Sistem (v2.0 — Clean Architecture)

```
JTS/
├── backend/
│   ├── main.py                      # App factory — middleware + routers sahaja
│   ├── requirements.txt
│   ├── .env                         # Konfigurasi persekitaran (JANGAN commit)
│   ├── config/
│   │   ├── settings.py              # Pydantic BaseSettings — semua config dari .env
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
│   │   ├── auth_service.py          # AuthService — tiada FastAPI dependency
│   │   ├── shield_service.py        # ShieldService dengan TTLCache
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
│   │   ├── rule_engine.py           # Rule-based (39 pattern OWASP)
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
│   ├── engine/                      # Legacy (dikekalkan untuk backward compat)
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

## Model AI Digunakan

| Model | Sumber | Fungsi |
|---|---|---|
| `deepset/deberta-v3-base-injection` | HuggingFace | Mengesan Prompt Injection |
| `martin-ha/toxic-comment-model` | HuggingFace | Mengesan kandungan toksik / Jailbreak |
| Rule-based Regex Engine | Custom | 39 pattern OWASP LLM01/LLM02 |

Semua model berjalan **sepenuhnya offline** selepas download pertama. Tiada data dihantar ke pihak ketiga.

> Model cache disimpan di `~/.cache/huggingface/hub/`. Guna endpoint `/admin/update` untuk refresh model ke versi terkini.

---

## Standard & Pematuhan

| Standard | Skop |
|---|---|
| OWASP Top 10 (2021) | Keselamatan aplikasi web |
| OWASP LLM Top 10 | Keselamatan model AI/LLM |
| CWE/SANS Top 25 | Kelemahan kod sumber |
| NACSA AI Security Framework | Keselamatan AI kebangsaan |
| JPDP / PDPA 2010 | Perlindungan data peribadi |
| MCMC CMA 1998 | Komunikasi & multimedia |
| AIGE | Etika AI kebangsaan |
| MY-AI Standards (SIRIM/JSM) | Standard teknikal AI Malaysia |

---

## API Documentation

### Base URL
```
http://localhost:8000
```

Dokumentasi interaktif (Swagger UI): `http://localhost:8000/docs`

---

### Auth Endpoints

#### `POST /portal/auth/register`
Daftar akaun pengguna baru. Kata laluan minimum 8 aksara.

```json
// Request
{ "email": "user@example.com", "password": "kataLaluan8" }

// Response 201
{ "message": "User registered successfully" }

// Response 409 — email sudah didaftarkan
{ "detail": "Emel user@example.com telah didaftarkan." }
```

#### `POST /portal/auth/login`
Log masuk dan dapatkan JWT token.

```json
// Request
{ "email": "user@example.com", "password": "kataLaluan8" }

// Response 200
{ "access_token": "eyJ...", "refresh_token": "eyJ...", "token_type": "bearer" }

// Response 401 — kelayakan tidak sah
{ "detail": "Emel atau kata laluan tidak betul." }
```

---

### Portal Endpoints (Memerlukan JWT)

Header: `Authorization: Bearer <token>`

#### `POST /portal/api-key/generate`
Jana API Key baru untuk domain. Key dipaparkan **sekali sahaja**.

```json
// Request
{ "allowed_domain": "lamanweb.com" }

// Response 201
{
  "api_key": "aisec_live_xxxxxxxxxxxx",
  "allowed_domain": "lamanweb.com",
  "warning": "Copy this key now. It will NOT be shown again."
}
```

#### `GET /portal/api-keys`
Senarai semua API key milik pengguna. Return array terus.

#### `GET /portal/api-key/{key_id}`
Semak status API key dan dapatkan arahan domain verification.

#### `POST /portal/api-key/{key_id}/verify`
Verify domain ownership dan trigger auto-scan.

```json
// Request
{
  "target_url": "https://lamanweb.com",
  "repo_url": "https://github.com/user/repo",
  "branch": "main"
}
```

#### `DELETE /portal/api-key/{key_id}`
Revoke API key.

#### `GET /portal/stats`
Statistik imbasan prompt. Return flat JSON.

```json
{ "total_requests": 100, "total_blocked": 12, "engine_status": "ACTIVE" }
```

#### `GET /portal/logs`
Log keselamatan real-time (100 terkini). Return array terus.

#### `GET /portal/compliance/{domain}`
Skor pematuhan untuk domain tertentu.

#### `POST /portal/report/pdf`
Jana laporan audit PDF.

```json
// Request
{ "code": "<kod sumber>", "filename": "app.py" }
// Response: PDF file download
```

#### `POST /admin/update`
Kemaskini rule patterns OWASP dan/atau refresh ML models. Memerlukan JWT.

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

### Public Gateway Endpoints (Memerlukan API Key)

Header: `X-API-Key: aisec_live_xxx` dan `X-Origin-Domain: domain.com`

#### `POST /api/v1/shield`
Imbas prompt AI untuk ancaman.

```json
// Request
{ "prompt": "teks prompt pengguna" }

// Response — Selamat
{ "status": "ALLOWED" }

// Response — Disekat
{ "status": "BLOCKED", "reason": "PROMPT_INJECTION" }
```

#### `POST /api/v1/scan/code`
Imbas kod sumber untuk CVE/CWE.

```json
// Request
{ "code": "<kod sumber>", "filename": "app.py", "engine_mode": "hybrid" }

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
Scan keseluruhan repo GitHub untuk CVE/CWE, secrets, dan dependency issues.

```json
// Request
{ "repo_url": "https://github.com/user/repo", "branch": "main" }
```

Had: Repo mesti public, saiz < 200MB, < 500 fail.

#### `POST /api/v1/scan/url`
Scan laman web hidup untuk isu keselamatan (DAST asas).

```json
// Request
{ "url": "https://target-website.com" }
```

Semakan: Exposed paths, security headers, error leak, CORS, SSL/TLS.

#### `POST /api/v1/scan/upload`
Upload fail ZIP projek untuk di-scan.

```
// Request: multipart/form-data
field: file (ZIP)
```

Had: Saiz ZIP < 200MB selepas extract, < 500 fail.

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

## Cara Pasang & Jalankan

> **Penting:** Jalankan dari WSL (Linux filesystem), bukan terus dari Windows. SQLite WAL mode tidak berfungsi pada NTFS (`/mnt/c/`).

```bash
# 1. Buka WSL terminal, masuk direktori
cd /mnt/c/Users/fahmi/Downloads/JTS/backend

# 2. Buat virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Salin dan edit fail .env
# JWT_SECRET sudah ada dalam .env — tukar jika perlu
# DATABASE_URL gunakan path Linux: sqlite:////tmp/trustguard/aisec.db

# 5. Jalankan server
python main.py
```

Buka `http://localhost:8000` dalam browser.

### Nota WSL / Windows

| Isu | Penyelesaian |
|---|---|
| SQLite WAL error pada `/mnt/c/` | Guna `DATABASE_URL=sqlite:////tmp/trustguard/aisec.db` |
| Server guna kod lama selepas edit | Delete `__pycache__` dan restart server |
| Python 3.13 (Windows) vs 3.12 (WSL) | Pastikan jalankan dalam WSL venv |

```bash
# Delete cache jika server guna kod lama
find . -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null
python main.py
```

---

## Cara Integrasi (Webhook / API)

Sistem luar boleh bersambung dengan 3 langkah:

1. Daftar akaun di portal → Jana API Key untuk domain anda
2. Hantar setiap prompt pengguna ke `/api/v1/shield` sebelum diproses oleh model AI
3. Prompt yang `ALLOWED` sahaja dibenarkan sampai ke model AI anda

```python
import requests

response = requests.post(
    "http://localhost:8000/api/v1/shield",
    headers={
        "X-API-Key": "aisec_live_xxxx",
        "X-Origin-Domain": "lamanweb.com"
    },
    json={"prompt": user_input}
)

if response.json()["status"] == "BLOCKED":
    return "Permintaan anda tidak dapat diproses."
```

---

## Perubahan v2.0 (daripada v1.0)

| Bahagian | v1.0 | v2.0 |
|---|---|---|
| Struktur | Monolith 700-baris `main.py` | Clean Architecture — config, models, schemas, services, repositories |
| Auth | Inline dalam `main.py` | `AuthService` berasingan, boleh diuji tanpa FastAPI |
| Middleware | Tiada | RequestID, SecurityHeaders, RateLimit, AuditLog |
| Error codes | String rawak | TG-XXXX series (TG-1001 hingga TG-9001) |
| Database | SQLite sahaja | SQLite + PostgreSQL, WAL mode, auto-migration |
| Tests | Tiada | 63 tests — unit, auth, security |
| Password validator | Tiada had jelas | Minimum 8 aksara (validator huruf besar dibuang) |
| Response format | Tidak konsisten | Flat JSON untuk semua portal endpoints (backward compatible) |

---

## Lesen & Kredit

Dibina dengan penuh semangat dari **Sungai Buloh, Selangor, Malaysia**.

Rujukan standard: OWASP, NACSA, JPDP, MCMC, AIGE, MY-AI Standards (SIRIM/JSM).

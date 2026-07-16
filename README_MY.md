# TrustGuard v2.0 — Gerbang Keselamatan AI Perusahaan

> Lapisan keselamatan berpusat untuk melindungi model LLM dan aplikasi AI daripada serangan siber, prompt injection, jailbreak, dan kelemahan kod.

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
| Pangkalan Data | SQLite (boleh migrate ke PostgreSQL) |
| Enjin ML | HuggingFace Transformers |
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
│   │   ├── user.py                  # Model User (RBAC: admin/analyst/developer/auditor)
│   │   ├── api_key.py               # Model ApiKey
│   │   └── log.py                   # PromptLog, AuditLog, ScanJob
│   ├── schemas/
│   │   ├── common.py                # StandardResponse, ErrorResponse
│   │   ├── auth.py                  # RegisterRequest, LoginRequest (min 8 aksara)
│   │   ├── gateway.py               # ShieldRequest, ResponseFirewallRequest
│   │   └── scan.py                  # CodeScanRequest, RepoScanRequest, UrlScanRequest
│   ├── services/
│   │   ├── auth_service.py          # AuthService — tiada kebergantungan FastAPI
│   │   ├── shield_service.py        # ShieldService dengan TTLCache
│   │   └── api_key_service.py       # ApiKeyService
│   ├── repositories/
│   │   ├── user_repo.py
│   │   ├── api_key_repo.py
│   │   └── log_repo.py              # AuditLog append-only, ScanJob CRUD
│   ├── middleware/
│   │   ├── request_id.py            # Header X-Request-ID
│   │   ├── security_headers.py      # CSP, HSTS, X-Frame-Options
│   │   ├── rate_limit.py            # Sliding window per-IP
│   │   └── audit_log.py             # Pengelogan berstruktur JSON
│   ├── engines/
│   │   ├── rule_engine.py           # Berasaskan peraturan (39 pattern OWASP)
│   │   ├── ml_engine.py             # Model ML HuggingFace
│   │   └── hybrid_engine.py         # Hibrid (Peraturan → ML)
│   ├── scanners/
│   │   ├── cve_scanner.py           # Pengimbas CVE/CWE + NACSA/JPDP/MCMC
│   │   ├── secret_scanner.py        # Pengimbas pendedahan rahsia & API key
│   │   ├── dependency_scanner.py    # Pengimbas rantaian bekalan / dependency
│   │   └── aggregator.py            # Pengagregat keputusan peringkat projek
│   ├── ingest/
│   │   ├── github_ingest.py         # Klon & imbas repo GitHub
│   │   ├── zip_ingest.py            # Ekstrak & imbas upload ZIP
│   │   └── url_ingest.py            # Pengimbas DAST URL langsung
│   ├── api/v1/
│   │   ├── auth.py                  # /portal/auth/register, /login
│   │   ├── portal.py                # /portal/stats, /logs, /api-keys, /generate
│   │   ├── gateway.py               # /api/v1/shield
│   │   ├── scan.py                  # /api/v1/scan/code|repo|url|upload
│   │   ├── admin.py                 # /admin/update
│   │   └── report.py                # /portal/report/pdf
│   ├── utils/
│   │   ├── hashing.py
│   │   ├── jwt_utils.py             # Token akses + refresh
│   │   ├── cache.py                 # TTLCache
│   │   └── domain_verify.py
│   ├── database/
│   │   └── session.py               # SQLite/PostgreSQL, mod WAL, auto-migrasi
│   ├── compliance/
│   │   └── scorer.py
│   ├── reports/
│   │   └── pdf_generator.py
│   ├── engine/                      # Warisan (dikekalkan untuk keserasian ke belakang)
│   │   └── updater.py
│   └── tests/
│       ├── unit/
│       │   ├── test_rule_engine.py  # 39 ujian berparameter
│       │   └── test_auth_service.py # 6 ujian
│       └── security/
│           └── test_security.py     # Ujian SSRF, path traversal, injection
└── frontend/
    ├── index.html                   # Laman pendaratan
    └── portal.html                  # Portal pengurusan
```

---

## Model AI Digunakan

| Model | Sumber | Fungsi |
|---|---|---|
| `deepset/deberta-v3-base-injection` | HuggingFace | Mengesan Prompt Injection |
| `martin-ha/toxic-comment-model` | HuggingFace | Mengesan kandungan toksik / Jailbreak |
| Enjin Regex Berasaskan Peraturan | Tersuai | 39 pattern OWASP LLM01/LLM02 |

Semua model berjalan **sepenuhnya offline** selepas muat turun pertama. Tiada data dihantar ke pihak ketiga.

> Cache model disimpan di `~/.cache/huggingface/hub/`. Guna endpoint `/admin/update` untuk refresh model ke versi terkini.

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

## Dokumentasi API

### URL Asas
```
http://localhost:8000
```

Dokumentasi interaktif (Swagger UI): `http://localhost:8000/docs`

---

### Endpoint Pengesahan

#### `POST /portal/auth/register`
Daftar akaun pengguna baru. Kata laluan minimum 8 aksara.

```json
// Permintaan
{ "email": "pengguna@contoh.com", "password": "KataLaluan8" }

// Respons 201
{ "message": "User registered successfully" }

// Respons 409 — emel sudah didaftarkan
{ "detail": "Emel pengguna@contoh.com telah didaftarkan." }
```

#### `POST /portal/auth/login`
Log masuk dan dapatkan token JWT.

```json
// Permintaan
{ "email": "pengguna@contoh.com", "password": "KataLaluan8" }

// Respons 200
{ "access_token": "eyJ...", "refresh_token": "eyJ...", "token_type": "bearer" }

// Respons 401 — kelayakan tidak sah
{ "detail": "Emel atau kata laluan tidak betul." }
```

---

### Endpoint Portal (Memerlukan JWT)

Header: `Authorization: Bearer <token>`

#### `POST /portal/api-key/generate`
Jana API Key baru untuk domain. Key dipaparkan **sekali sahaja**.

```json
// Permintaan
{ "allowed_domain": "lamanweb.com" }

// Respons 201
{
  "api_key": "aisec_live_xxxxxxxxxxxx",
  "allowed_domain": "lamanweb.com",
  "warning": "Copy this key now. It will NOT be shown again."
}
```

#### `GET /portal/api-keys`
Senarai semua API key milik pengguna. Return array terus.

#### `GET /portal/api-key/{key_id}`
Semak status API key dan dapatkan arahan pengesahan domain.

#### `POST /portal/api-key/{key_id}/verify`
Sahkan pemilikan domain dan picu auto-scan.

```json
// Permintaan
{
  "target_url": "https://lamanweb.com",
  "repo_url": "https://github.com/pengguna/repo",
  "branch": "main"
}
```

#### `DELETE /portal/api-key/{key_id}`
Batalkan API key.

#### `GET /portal/stats`
Statistik imbasan prompt. Return flat JSON.

```json
{ "total_requests": 100, "total_blocked": 12, "engine_status": "ACTIVE" }
```

#### `GET /portal/logs`
Log keselamatan masa nyata (100 terkini). Return array terus.

#### `GET /portal/compliance/{domain}`
Skor pematuhan untuk domain tertentu.

#### `POST /portal/report/pdf`
Jana laporan audit PDF.

```json
// Permintaan
{ "code": "<kod sumber>", "filename": "app.py" }
// Respons: Muat turun fail PDF
```

#### `POST /admin/update`
Kemaskini pattern peraturan OWASP dan/atau refresh model ML. Memerlukan JWT.

```json
// Permintaan
{ "update_rules": true, "update_models": true }

// Respons
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

### Endpoint Gerbang Awam (Memerlukan API Key)

Header: `X-API-Key: aisec_live_xxx` dan `X-Origin-Domain: domain.com`

#### `POST /api/v1/shield`
Imbas prompt AI untuk ancaman.

```json
// Permintaan
{ "prompt": "teks prompt pengguna" }

// Respons — Selamat
{ "status": "ALLOWED" }

// Respons — Disekat
{ "status": "BLOCKED", "reason": "PROMPT_INJECTION" }
```

#### `POST /api/v1/scan/code`
Imbas kod sumber untuk kelemahan CVE/CWE.

```json
// Permintaan
{ "code": "<kod sumber>", "filename": "app.py", "engine_mode": "hybrid" }

// Respons
{
  "total_issues": 3,
  "severity_breakdown": { "critical": 1, "high": 1, "medium": 1, "low": 0 },
  "vulnerabilities": [...],
  "compliance_flags": [...],
  "compliance_score": { "overall": 72.5, "grade": "B", "breakdown": {...} }
}
```

#### `POST /api/v1/scan/repo`
Imbas keseluruhan repo GitHub untuk CVE/CWE, rahsia, dan isu dependency.

```json
// Permintaan
{ "repo_url": "https://github.com/pengguna/repo", "branch": "main" }
```

Had: Repo mesti awam, saiz < 200MB, < 500 fail.

#### `POST /api/v1/scan/url`
Imbas laman web langsung untuk isu keselamatan (DAST asas).

```json
// Permintaan
{ "url": "https://laman-sasaran.com" }
```

Semakan: Laluan terdedah, header keselamatan, kebocoran ralat, CORS, SSL/TLS.

#### `POST /api/v1/scan/upload`
Muat naik fail ZIP projek untuk diimbas.

```
// Permintaan: multipart/form-data
medan: file (ZIP)
```

Had: Saiz ZIP < 200MB selepas ekstrak, < 500 fail.

---

### Endpoint Sistem

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

> **Penting:** Jalankan dari WSL (Linux filesystem), bukan terus dari Windows. Mod WAL SQLite tidak berfungsi pada NTFS (`/mnt/c/`).

```bash
# 1. Buka terminal WSL, masuk ke direktori
cd /mnt/c/Users/fahmi/Downloads/JTS/backend

# 2. Buat persekitaran maya
python3 -m venv venv
source venv/bin/activate

# 3. Pasang kebergantungan
pip install -r requirements.txt

# 4. Konfigurasi .env
#    JWT_SECRET sudah ada — tukar jika perlu
#    Gunakan laluan Linux untuk DATABASE_URL: sqlite:////tmp/trustguard/aisec.db

# 5. Jalankan pelayan
python main.py
```

Buka `http://localhost:8000` dalam pelayar.

### Nota WSL / Windows

| Isu | Penyelesaian |
|---|---|
| Ralat WAL SQLite pada `/mnt/c/` | Guna `DATABASE_URL=sqlite:////tmp/trustguard/aisec.db` |
| Pelayan guna kod lama selepas edit | Padam `__pycache__` dan mulakan semula |
| Python 3.13 (Windows) vs 3.12 (WSL) | Sentiasa jalankan dalam WSL venv |

```bash
# Padam cache jika pelayan guna kod lama
find . -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null
python main.py
```

---

## Panduan Integrasi

Sistem luar boleh bersambung dengan 3 langkah:

1. Daftar akaun di portal → Jana API Key untuk domain anda
2. Hantar setiap prompt pengguna ke `/api/v1/shield` sebelum diproses oleh model AI
3. Hanya prompt yang `ALLOWED` dibenarkan sampai ke model AI anda

```python
import requests

respons = requests.post(
    "http://localhost:8000/api/v1/shield",
    headers={
        "X-API-Key": "aisec_live_xxxx",
        "X-Origin-Domain": "lamanweb.com"
    },
    json={"prompt": input_pengguna}
)

if respons.json()["status"] == "BLOCKED":
    return "Permintaan anda tidak dapat diproses."
```

---

## Perubahan v2.0

| Bahagian | v1.0 | v2.0 |
|---|---|---|
| Struktur | Monolith 700-baris `main.py` | Clean Architecture — config, models, schemas, services, repositories |
| Pengesahan | Sebaris dalam `main.py` | `AuthService` berasingan, boleh diuji tanpa FastAPI |
| Middleware | Tiada | RequestID, SecurityHeaders, RateLimit, AuditLog |
| Kod ralat | String rawak | Siri TG-XXXX (TG-1001 hingga TG-9001) |
| Pangkalan data | SQLite sahaja | SQLite + PostgreSQL, mod WAL, auto-migrasi |
| Ujian | Tiada | 63 ujian — unit, auth, keselamatan |
| Pengesahan kata laluan | Tiada had jelas | Minimum 8 aksara |
| Format respons | Tidak konsisten | Flat JSON untuk semua endpoint portal (serasi ke belakang) |

---

## Lesen & Kredit

Made with ❤️ from Sungai Buloh, Malaysia**.

Rujukan standard: OWASP, NACSA, JPDP, MCMC, AIGE, MY-AI Standards (SIRIM/JSM).

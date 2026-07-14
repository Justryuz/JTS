# JustGuard — AI Security Gateway

> Sistem keselamatan berpusat untuk melindungi model LLM dan aplikasi AI daripada serangan siber, prompt injection, jailbreak, dan kelemahan kod.

---

## Objektif

JustGuard dibina untuk menjawab keperluan keselamatan AI yang semakin kritikal di Malaysia dan global. Platform ini bertindak sebagai **lapisan pertahanan berpusat** antara pengguna dan model AI, memastikan setiap interaksi diimbas, dilog, dan dinilai mengikut standard keselamatan antarabangsa dan tempatan.

**Matlamat utama:**
- Melindungi model LLM daripada Prompt Injection & Jailbreak (OWASP LLM Top 10)
- Mengesan kelemahan CVE/CWE dalam kod sumber yang dijanakan oleh AI
- Memastikan pematuhan kepada perundangan Malaysia (JPDP, NACSA, MCMC, AIGE)
- Menyediakan laporan audit keselamatan yang boleh dikemukakan kepada pihak berkuasa

---

## Maklumat Pembangunan

| Perkara | Butiran |
|---|---|
| Versi | 1.0.0 |
| Bahasa Backend | Python 3.12 |
| Framework | FastAPI |
| Database | SQLite (boleh migrate ke PostgreSQL) |
| ML Engine | HuggingFace Transformers |
| Frontend | HTML + Tailwind CSS |
| Lokasi Pembangunan | Sungai Buloh, Selangor, Malaysia |

---

## Komponen Sistem

```
JTS/
├── backend/
│   ├── main.py                  # FastAPI server utama
│   ├── requirements.txt
│   ├── engine/
│   │   ├── rule_engine.py       # Pilihan 1: Rule-based (39 pattern OWASP)
│   │   ├── ml_engine.py         # Pilihan 2: HuggingFace ML models
│   │   ├── hybrid_engine.py     # Pilihan 3: Hybrid (Rule → ML)
│   │   ├── cve_scanner.py       # CVE/CWE + NACSA/JPDP/MCMC scanner
│   │   ├── secret_scanner.py    # Secret & API key exposure scanner
│   │   ├── dependency_scanner.py# Supply chain / dependency scanner
│   │   ├── aggregator.py        # Project-level result aggregator
│   │   ├── updater.py           # Engine auto-update (rules + models)
│   │   └── ingest/
│   │       ├── github_ingest.py # GitHub repo clone & scan
│   │       ├── zip_ingest.py    # ZIP upload extract & scan
│   │       └── url_ingest.py    # Live URL DAST scanner
│   ├── compliance/
│   │   └── scorer.py            # Compliance scoring engine
│   └── reports/
│       └── pdf_generator.py     # PDF audit report generator
└── frontend/
    ├── index.html               # Landing page
    └── portal.html              # Management portal
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
Daftar akaun pengguna baru.

```json
// Request
{ "email": "user@example.com", "password": "kata_laluan" }

// Response 201
{ "message": "User registered successfully" }
```

#### `POST /portal/auth/login`
Log masuk dan dapatkan JWT token.

```json
// Request
{ "email": "user@example.com", "password": "kata_laluan" }

// Response 200
{ "access_token": "eyJ...", "token_type": "bearer" }
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
Senarai semua API key milik pengguna.

#### `DELETE /portal/api-key/{key_id}`
Revoke API key.

#### `GET /portal/stats`
Statistik imbasan prompt.

```json
{ "total_requests": 100, "total_blocked": 12, "engine_status": "ACTIVE" }
```

#### `GET /portal/logs`
Log keselamatan real-time (100 terkini).

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
Kemaskini rule patterns OWASP terkini dan/atau refresh ML models dari HuggingFace. Memerlukan JWT.

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

// Response
{
  "scan_type": "github_repo",
  "target": "https://github.com/user/repo",
  "total_files_scanned": 42,
  "total_issues": 15,
  "severity_breakdown": { "critical": 2, "high": 5, "medium": 6, "low": 2 },
  "issues_by_file": { "src/api/auth.js": [...] },
  "compliance_score": { "overall": 68.0, "grade": "C", "breakdown": {...} },
  "scan_duration_seconds": 8.4,
  "timestamp": "2026-07-14T00:00:00+00:00"
}
```

Had: Repo mesti public, saiz < 200MB, < 500 fail.

#### `POST /api/v1/scan/url`
Scan laman web hidup untuk isu keselamatan (DAST asas).

```json
// Request
{ "url": "https://target-website.com" }

// Response
{
  "scan_type": "live_url",
  "target": "https://target-website.com",
  "total_issues": 4,
  "severity_breakdown": { "critical": 0, "high": 2, "medium": 2, "low": 0 },
  "issues_by_file": { "live_url": [...] },
  "compliance_score": { "overall": 60.0, "grade": "C" },
  "scan_duration_seconds": 12.1
}
```

Semakan: Exposed paths, security headers, error leak, CORS, SSL/TLS.

#### `POST /api/v1/scan/upload`
Upload fail ZIP projek untuk di-scan.

```
// Request: multipart/form-data
field: file (ZIP)

// Response: sama format dengan /api/v1/scan/repo
```

Had: Saiz ZIP < 200MB selepas extract, < 500 fail.

---

### System Endpoint

#### `GET /health`
Semak status sistem.

```json
{
  "status": "ok",
  "engine": "ACTIVE",
  "version": "1.0.0",
  "ml_available": true
}
```

---

## Cara Pasang & Jalankan

```bash
# 1. Clone / masuk direktori
cd /mnt/c/Users/fahmi/Downloads/JTS/backend

# 2. Buat virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Set JWT secret
export JWT_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")

# 5. Jalankan server
python main.py
```

Buka `http://localhost:8000` dalam browser.

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

## Lesen & Kredit

Dibina dengan penuh semangat dari **Sungai Buloh, Selangor, Malaysia**.

Rujukan standard: OWASP, NACSA, JPDP, MCMC, AIGE, MY-AI Standards (SIRIM/JSM).

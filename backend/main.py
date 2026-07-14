"""
AI Security Gateway & Management Portal
Backend API Server + Detection Engine
OWASP-compliant FastAPI application
"""

from __future__ import annotations

import hashlib
import os
import re
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

import jwt
from fastapi import Depends, FastAPI, File, Header, HTTPException, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, RedirectResponse, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from passlib.context import CryptContext
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import Boolean, Column, DateTime, String, Text, create_engine, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

import httpx
from engine import rule_engine, hybrid_engine, cve_scanner, updater
from engine.ingest import github_ingest, zip_ingest, url_ingest
from compliance import scorer
from reports import pdf_generator

# ---------------------------------------------------------------------------
# CONFIG
# ---------------------------------------------------------------------------
DATABASE_URL = "sqlite:///./aisec.db"
JWT_SECRET = os.getenv("JWT_SECRET")
if not JWT_SECRET:
    raise RuntimeError("JWT_SECRET environment variable is not set. Run: set JWT_SECRET=<strong-random-secret>")
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_MINUTES = 60

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
bearer_scheme = HTTPBearer()

# ---------------------------------------------------------------------------
# DATABASE MODELS
# ---------------------------------------------------------------------------
class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    email = Column(String, unique=True, nullable=False, index=True)
    password_hash = Column(String, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class ApiKey(Base):
    __tablename__ = "api_keys"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, nullable=False)
    api_key_hash = Column(String, nullable=False, index=True)  # SHA-256
    allowed_domain = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    verification_token = Column(String, nullable=True)
    verification_method = Column(String, default="http_file")
    verified_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class SecurityLog(Base):
    __tablename__ = "security_logs"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    api_key_id = Column(String, nullable=False)
    source_domain = Column(String, nullable=False)
    input_text = Column(Text, nullable=False)
    status = Column(String, nullable=False)          # ALLOWED | BLOCKED
    attack_type = Column(String, default="NONE")     # NONE | PROMPT_INJECTION | JAILBREAK
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


Base.metadata.create_all(bind=engine)

# Perform lightweight schema migration for new ApiKey verification fields
with engine.connect() as conn:
    result = conn.execute(text("PRAGMA table_info(api_keys)"))
    columns = {row[1] for row in result.fetchall()}
    if "is_verified" not in columns:
        conn.execute(text("ALTER TABLE api_keys ADD COLUMN is_verified BOOLEAN DEFAULT 0"))
    if "verification_token" not in columns:
        conn.execute(text("ALTER TABLE api_keys ADD COLUMN verification_token TEXT"))
    if "verification_method" not in columns:
        conn.execute(text("ALTER TABLE api_keys ADD COLUMN verification_method TEXT DEFAULT 'http_file'"))
    if "verified_at" not in columns:
        conn.execute(text("ALTER TABLE api_keys ADD COLUMN verified_at DATETIME"))

# ---------------------------------------------------------------------------
# DETECTION ENGINE (Heuristic / Rule-Based)
# ---------------------------------------------------------------------------
PROMPT_INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?previous\s+instructions?",
    r"disregard\s+(all\s+)?previous\s+instructions?",
    r"forget\s+(your\s+)?(system\s+prompt|instructions?|context)",
    r"override\s+(system|instructions?|prompt)",
    r"bypass\s+(safety|filter|restriction|guideline)",
    r"reveal\s+(your\s+)?(system\s+prompt|instructions?|prompt)",
    r"print\s+(your\s+)?(system\s+prompt|instructions?)",
    r"what\s+(are|were)\s+your\s+(original\s+)?instructions?",
    r"show\s+me\s+your\s+(system\s+)?prompt",
]

JAILBREAK_PATTERNS = [
    r"you\s+are\s+now\s+in\s+DAN\s+mode",
    r"do\s+anything\s+now",
    r"DAN\s+mode\s+(enabled|activated|on)",
    r"act\s+as\s+(a\s+)?(developer|AI|assistant)\s+with\s+no\s+restrictions?",
    r"you\s+have\s+no\s+(restrictions?|limitations?|rules?|guidelines?)",
    r"pretend\s+(you\s+are|to\s+be)\s+(an?\s+)?(evil|unrestricted|unfiltered)",
    r"system\s+override",
    r"jailbreak",
    r"developer\s+mode\s+(enabled|on|activated)",
    r"enable\s+developer\s+mode",
    r"you\s+are\s+now\s+(free|unrestricted|unfiltered)",
    r"remove\s+(all\s+)?(your\s+)?(restrictions?|limitations?|filters?)",
    r"(sudo|root)\s+(mode|access|override)",
]


def detect_attack(text: str) -> tuple[str, str]:
    """
    Returns (status, attack_type).
    status: ALLOWED | BLOCKED
    attack_type: NONE | PROMPT_INJECTION | JAILBREAK
    """
    normalized = text.lower().strip()

    for pattern in PROMPT_INJECTION_PATTERNS:
        if re.search(pattern, normalized, re.IGNORECASE):
            return "BLOCKED", "PROMPT_INJECTION"

    for pattern in JAILBREAK_PATTERNS:
        if re.search(pattern, normalized, re.IGNORECASE):
            return "BLOCKED", "JAILBREAK"

    return "ALLOWED", "NONE"


# ---------------------------------------------------------------------------
# HELPERS
# ---------------------------------------------------------------------------
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def sha256_hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def build_verification_instructions(domain: str, token: str) -> str:
    return (
        f"Simpan token ini di https://{domain}/.well-known/trustguard.txt\n"
        f"Kandungan fail mesti sama dengan token berikut:\n{token}"
    )


def build_scan_summary(report: dict) -> dict:
    if report is None:
        return {
            "overview": "Tiada laporan tersedia.",
            "grade": "F",
            "issues_found": 0,
            "critical": 0,
            "high": 0,
            "recommendations": ["Tiada data scan tersedia."],
        }
    if "error" in report:
        return {
            "overview": f"Scan gagal: {report['error']}",
            "grade": "F",
            "issues_found": 0,
            "critical": 0,
            "high": 0,
            "recommendations": ["Betulkan isu scan dan cuba semula."],
        }

    total = report.get("total_issues", 0)
    high = report.get("severity_breakdown", {}).get("high", 0)
    critical = report.get("severity_breakdown", {}).get("critical", 0)
    grade = report.get("compliance_score", {}).get("grade", "F")
    message = "Tiada isu utama ditemui. Web anda kelihatan kukuh." if total == 0 else (
        "Perlukan perhatian segera: isu kritikal ditemui." if critical > 0 else (
            "Beberapa isu keselamatan ditemui; semak dan betulkan segera." if high > 0 else "Isu sederhana ditemi: pembaikan disarankan."))

    recommendations = []
    if critical > 0:
        recommendations.append("Segera semak isu kritikal dan perbaiki konfigurasi keselamatan.")
    if high > 0:
        recommendations.append("Tingkatkan response headers dan semak sebarang endpoint terbuka.")
    if total == 0:
        recommendations.append("Teruskan pemantauan berkala dan kemaskini dependencies.")
    else:
        recommendations.append("Gunakan laporan terperinci untuk memperbaiki setiap kelemahan.")

    return {
        "overview": message,
        "grade": grade,
        "issues_found": total,
        "critical": critical,
        "high": high,
        "recommendations": recommendations,
    }


def verify_domain_file(target_url: str, token: str) -> bool:
    try:
        response = httpx.get(target_url, timeout=15, follow_redirects=True)
        if response.status_code != 200:
            return False
        return response.text.strip() == token.strip()
    except Exception:
        return False


def run_auto_scan_for_key(api_key: ApiKey, body: VerifyDomainRequest) -> dict:
    domain = api_key.allowed_domain
    target_url = body.target_url or f"https://{domain}"
    result = {"verified_domain": domain, "target_url": target_url}
    result["live_scan"] = url_ingest.scan_live_url(target_url)

    if body.repo_url:
        result["repo_scan"] = github_ingest.scan_github_repo(body.repo_url, body.branch)

    result["summary"] = {
        "live_scan": build_scan_summary(result["live_scan"]),
        **({"repo_scan": build_scan_summary(result["repo_scan"])} if body.repo_url else {}),
    }
    return result


def create_jwt(user_id: str) -> str:
    payload = {
        "sub": user_id,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=JWT_EXPIRE_MINUTES),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def verify_jwt(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)) -> str:
    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload["sub"]
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


# ---------------------------------------------------------------------------
# PYDANTIC SCHEMAS
# ---------------------------------------------------------------------------
class RegisterRequest(BaseModel):
    email: str
    password: str

    @field_validator('email')
    @classmethod
    def validate_email(cls, v):
        if '@' not in v or '.' not in v.split('@')[-1]:
            raise ValueError('Format email tidak sah')
        return v.lower().strip()


class LoginRequest(BaseModel):
    email: str
    password: str

    @field_validator('email')
    @classmethod
    def validate_email(cls, v):
        return v.lower().strip()


class GenerateKeyRequest(BaseModel):
    allowed_domain: str


class RepoScanRequest(BaseModel):
    repo_url: str
    branch: str = "main"


class UrlScanRequest(BaseModel):
    url: str


class ShieldRequest(BaseModel):
    prompt: str
    engine_mode: str = "hybrid"  # rule | ml | hybrid


class CodeScanRequest(BaseModel):
    code: str
    filename: str = "unknown"
    engine_mode: str = "hybrid"  # rule | ml | hybrid


class VerifyDomainRequest(BaseModel):
    method: str = "http_file"
    target_url: Optional[str] = None
    repo_url: Optional[str] = None
    branch: str = "main"


# ---------------------------------------------------------------------------
# FASTAPI APP
# ---------------------------------------------------------------------------
FRONTEND_DIR = os.path.join(os.path.dirname(__file__), "..", "frontend")

tags_metadata = [
    {
        "name": "Auth",
        "description": "Endpoint pendaftaran dan log masuk untuk menguruskan akses portal.",
    },
    {
        "name": "Portal",
        "description": "Pengurusan kunci API, log keselamatan, dan statistik pengguna.",
    },
    {
        "name": "Shield",
        "description": "Gateway awam untuk menapis dan mengesahkan prompt AI sebelum diproses.",
    },
    {
        "name": "Scan",
        "description": "Imbasan repo, URL, ZIP dan kod untuk kelemahan serta isu keselamatan.",
    },
    {
        "name": "Compliance",
        "description": "Skor pematuhan dan laporan audit untuk domain dan kod sumber.",
    },
    {
        "name": "Admin",
        "description": "Alat pentadbir untuk mengemaskini peraturan dan model pengesanan.",
    },
    {
        "name": "Health",
        "description": "Semakan kesihatan aplikasi dan ketersediaan enjin.",
    },
]

app = FastAPI(
    title="TrustGuard AI Security Gateway",
    description=(
        "TrustGuard AI adalah platform keselamatan berpusat untuk melindungi aplikasi AI daripada Prompt Injection, "
        "Jailbreak, dan kelemahan kod. Gunakan /docs untuk melihat semua endpoint API dengan info lengkap dan contoh penggunaan."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    openapi_tags=tags_metadata,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Restrict to specific origins in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def _serve_frontend_page(page_name: str) -> FileResponse:
    page_path = os.path.join(FRONTEND_DIR, page_name)
    if not os.path.exists(page_path):
        raise HTTPException(status_code=404, detail="Page not found")
    return FileResponse(page_path)


# Serve landing page
@app.get("/", include_in_schema=False)
def serve_landing():
    return _serve_frontend_page("index.html")


@app.get("/index.html", include_in_schema=False)
def serve_landing_index():
    return _serve_frontend_page("index.html")


# Serve portal dashboard
@app.get("/portal", include_in_schema=False)
def serve_portal():
    return _serve_frontend_page("portal.html")


@app.get("/portal/", include_in_schema=False)
def serve_portal_slash():
    return _serve_frontend_page("portal.html")


@app.get("/portal.html", include_in_schema=False)
def serve_portal_html():
    return _serve_frontend_page("portal.html")


# --- Auth Endpoints ---

@app.post(
    "/portal/auth/register",
    status_code=201,
    tags=["Auth"],
    summary="Daftar pengguna baru",
    description="Buat akaun pengguna baru untuk portal TrustGuard AI. Emel akan dinormalisasikan dan kata laluan dihash dengan selamat.",
)
def register(body: RegisterRequest, db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == body.email).first():
        raise HTTPException(status_code=409, detail="Email already registered")
    user = User(email=body.email, password_hash=pwd_context.hash(body.password))
    db.add(user)
    db.commit()
    return {"message": "User registered successfully"}


@app.post(
    "/portal/auth/login",
    tags=["Auth"],
    summary="Log masuk pengguna",
    description="Dapatkan token JWT untuk pengguna berdaftar supaya boleh mengakses endpoint portal yang dilindungi.",
)
def login(body: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == body.email).first()
    if not user or not pwd_context.verify(body.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return {"access_token": create_jwt(user.id), "token_type": "bearer"}


# --- Portal Endpoints (JWT Protected) ---

@app.post(
    "/portal/api-key/generate",
    status_code=201,
    tags=["Portal"],
    summary="Jana API Key baru",
    description="Jana kunci API terikat kepada domain untuk digunakan oleh aplikasi anda apabila memanggil TrustGuard AI shield gateway.",
)
def generate_api_key(
    body: GenerateKeyRequest,
    user_id: str = Depends(verify_jwt),
    db: Session = Depends(get_db),
):
    # Generate plain key — shown ONCE only
    plain_key = f"aisec_live_{secrets.token_hex(24)}"
    key_hash = sha256_hash(plain_key)
    verification_token = secrets.token_urlsafe(16)

    api_key = ApiKey(
        user_id=user_id,
        api_key_hash=key_hash,
        allowed_domain=body.allowed_domain.lower().strip(),
        verification_token=verification_token,
        verification_method="http_file",
    )
    db.add(api_key)
    db.commit()

    return {
        "api_key": plain_key,
        "allowed_domain": api_key.allowed_domain,
        "verification_method": api_key.verification_method,
        "verification_token": verification_token,
        "verification_instructions": build_verification_instructions(api_key.allowed_domain, verification_token),
        "warning": "Copy this key now. It will NOT be shown again.",
    }


@app.get(
    "/portal/api-keys",
    tags=["Portal"],
    summary="Senarai kunci API",
    description="Dapatkan semua kunci API aktif yang telah dijana untuk pengguna yang sedang log masuk.",
)
def list_api_keys(user_id: str = Depends(verify_jwt), db: Session = Depends(get_db)):
    keys = db.query(ApiKey).filter(ApiKey.user_id == user_id).all()
    return [
        {
            "id": k.id,
            "allowed_domain": k.allowed_domain,
            "is_active": k.is_active,
            "is_verified": k.is_verified,
            "verification_method": k.verification_method,
            "created_at": k.created_at,
            "verified_at": k.verified_at,
        }
        for k in keys
    ]


@app.post(
    "/portal/api-key/{key_id}/verify",
    tags=["Portal"],
    summary="Verify domain ownership and trigger auto-scan",
    description="Sahkan pemilikan domain menggunakan fail verification, kemudian jalankan auto-scan live web dan optional repo scan.",
)
def verify_api_key_domain(
    key_id: str,
    body: VerifyDomainRequest,
    user_id: str = Depends(verify_jwt),
    db: Session = Depends(get_db),
):
    api_key = db.query(ApiKey).filter(ApiKey.id == key_id, ApiKey.user_id == user_id, ApiKey.is_active.is_(True)).first()
    if not api_key:
        raise HTTPException(status_code=404, detail="API key not found")
    if api_key.is_verified:
        raise HTTPException(status_code=400, detail="Domain already verified")
    if api_key.verification_method != "http_file":
        raise HTTPException(status_code=400, detail="Unsupported verification method")

    domain = api_key.allowed_domain
    target_url = body.target_url.strip() if body.target_url else f"https://{domain}"
    verification_file_url = target_url.rstrip("/") + "/.well-known/trustguard.txt"

    if not verify_domain_file(verification_file_url, api_key.verification_token or ""):
        raise HTTPException(
            status_code=400,
            detail=(
                "Verification failed. Pastikan fail trustguard.txt mengandungi token yang diberikan "
                "dan boleh dicapai dari URL tersebut."
            ),
        )

    api_key.is_verified = True
    api_key.verified_at = datetime.now(timezone.utc)
    db.commit()

    return run_auto_scan_for_key(api_key, body)


@app.get(
    "/portal/api-key/{key_id}",
    tags=["Portal"],
    summary="Dapatkan status API key",
    description="Lihat sama ada domain sudah verified dan ambil arahan verification yang diperlukan.",
)
def get_api_key_status(
    key_id: str,
    user_id: str = Depends(verify_jwt),
    db: Session = Depends(get_db),
):
    api_key = db.query(ApiKey).filter(ApiKey.id == key_id, ApiKey.user_id == user_id).first()
    if not api_key:
        raise HTTPException(status_code=404, detail="API key not found")

    return {
        "id": api_key.id,
        "allowed_domain": api_key.allowed_domain,
        "is_active": api_key.is_active,
        "is_verified": api_key.is_verified,
        "verification_method": api_key.verification_method,
        "verified_at": api_key.verified_at,
        "verification_instructions": build_verification_instructions(api_key.allowed_domain, api_key.verification_token or ""),
    }


@app.delete(
    "/portal/api-key/{key_id}",
    tags=["Portal"],
    summary="Nyahaktifkan kunci API",
    description="Tamatkan akses satu kunci API supaya ia tidak lagi boleh digunakan untuk memanggil endpoint TrustGuard.",
)
def revoke_api_key(
    key_id: str,
    user_id: str = Depends(verify_jwt),
    db: Session = Depends(get_db),
):
    key = db.query(ApiKey).filter(ApiKey.id == key_id, ApiKey.user_id == user_id).first()
    if not key:
        raise HTTPException(status_code=404, detail="API key not found")
    key.is_active = False
    db.commit()
    return {"message": "API key revoked"}


@app.get(
    "/portal/logs",
    tags=["Portal"],
    summary="Dapatkan log keselamatan",
    description="Tunjukkan log semua permintaan yang melalui TrustGuard AI untuk kunci API pengguna dan status keselamatan mereka.",
)
def get_logs(
    user_id: str = Depends(verify_jwt),
    db: Session = Depends(get_db),
    limit: int = 100,
):
    # Fetch logs for keys belonging to this user
    user_key_ids = [k.id for k in db.query(ApiKey).filter(ApiKey.user_id == user_id).all()]
    logs = (
        db.query(SecurityLog)
        .filter(SecurityLog.api_key_id.in_(user_key_ids))
        .order_by(SecurityLog.created_at.desc())
        .limit(limit)
        .all()
    )
    return [
        {
            "id": l.id,
            "source_domain": l.source_domain,
            "input_text": l.input_text,
            "status": l.status,
            "attack_type": l.attack_type,
            "created_at": l.created_at,
        }
        for l in logs
    ]


@app.get(
    "/portal/stats",
    tags=["Portal"],
    summary="Statistik penggunaan",
    description="Paparkan ringkasan jumlah permintaan dan berapa banyak yang diblok bagi pengguna portal TrustGuard.",
)
def get_stats(user_id: str = Depends(verify_jwt), db: Session = Depends(get_db)):
    user_key_ids = [k.id for k in db.query(ApiKey).filter(ApiKey.user_id == user_id).all()]
    total = db.query(SecurityLog).filter(SecurityLog.api_key_id.in_(user_key_ids)).count()
    blocked = (
        db.query(SecurityLog)
        .filter(SecurityLog.api_key_id.in_(user_key_ids), SecurityLog.status == "BLOCKED")
        .count()
    )
    return {"total_requests": total, "total_blocked": blocked, "engine_status": "ACTIVE"}


# --- Public Shield Gateway ---

@app.post(
    "/api/v1/shield",
    tags=["Shield"],
    summary="Shield prompt AI",
    description=(
        "Panggilan utama untuk menghantar prompt ke TrustGuard AI sebelum ia dihantar ke model LLM. "
        "Endpoint ini akan mengesahkan API key, domain asal dan menapis prompt untuk Prompt Injection atau Jailbreak."
    ),
)
def shield(
    body: ShieldRequest,
    x_api_key: str = Header(..., alias="X-API-Key"),
    x_origin_domain: str = Header(..., alias="X-Origin-Domain"),
    db: Session = Depends(get_db),
):
    # OWASP BOLA Mitigation: validate key hash + domain binding
    key_hash = sha256_hash(x_api_key)
    api_key_record = (
        db.query(ApiKey)
        .filter(ApiKey.api_key_hash == key_hash, ApiKey.is_active.is_(True))
        .first()
    )

    if not api_key_record:
        raise HTTPException(status_code=401, detail="Invalid or inactive API key")

    # Domain validation — prevent cross-domain key abuse
    if api_key_record.allowed_domain != x_origin_domain.lower().strip():
        raise HTTPException(status_code=403, detail="Domain not authorized for this API key")

    # Run Detection Engine based on requested mode
    mode = (body.engine_mode or "hybrid").strip().lower()
    if mode == "rule":
        rule_result = rule_engine.scan(body.prompt)
        detection_status = rule_result.status
        attack_type = rule_result.attack_type
    elif mode == "ml":
        result = hybrid_engine.scan(body.prompt, use_ml=True)
        detection_status = result.status
        attack_type = result.attack_type
    else:
        result = hybrid_engine.scan(body.prompt, use_ml=hybrid_engine.ml_engine.is_available())
        detection_status = result.status
        attack_type = result.attack_type

    # Record transaction
    log = SecurityLog(
        api_key_id=api_key_record.id,
        source_domain=x_origin_domain,
        input_text=body.prompt[:500],  # Truncate to prevent DB bloat
        status=detection_status,
        attack_type=attack_type,
    )
    db.add(log)
    db.commit()

    if detection_status == "BLOCKED":
        return {"status": "BLOCKED", "reason": attack_type}

    return {"status": "ALLOWED"}


# --- Scan Endpoints (Repo / URL / ZIP) ---

def _validate_api_key(x_api_key: str, x_origin_domain: str, db: Session) -> ApiKey:
    key_hash = sha256_hash(x_api_key)
    record = db.query(ApiKey).filter(ApiKey.api_key_hash == key_hash, ApiKey.is_active.is_(True)).first()
    if not record:
        raise HTTPException(status_code=401, detail="Invalid or inactive API key")
    if record.allowed_domain != x_origin_domain.lower().strip():
        raise HTTPException(status_code=403, detail="Domain not authorized")
    return record


@app.post(
    "/api/v1/scan/repo",
    tags=["Scan"],
    summary="Imbas repo GitHub",
    description="Imbas repositori GitHub untuk kelemahan kod dan konfigurasi tanpa perlu muat turun keseluruhan projek secara manual.",
)
def scan_repo(
    body: RepoScanRequest,
    x_api_key: str = Header(..., alias="X-API-Key"),
    x_origin_domain: str = Header(..., alias="X-Origin-Domain"),
    db: Session = Depends(get_db),
):
    _validate_api_key(x_api_key, x_origin_domain, db)
    result = github_ingest.scan_github_repo(body.repo_url, body.branch)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result


@app.post(
    "/api/v1/scan/url",
    tags=["Scan"],
    summary="Imbas laman web secara langsung",
    description="Imbas URL langsung untuk mencari masalah DAST, kelemahan HTML/JS, dan isu keselamatan pada API yang diakses.",
)
def scan_url(
    body: UrlScanRequest,
    x_api_key: str = Header(..., alias="X-API-Key"),
    x_origin_domain: str = Header(..., alias="X-Origin-Domain"),
    db: Session = Depends(get_db),
):
    _validate_api_key(x_api_key, x_origin_domain, db)
    result = url_ingest.scan_live_url(body.url)
    return result


@app.post(
    "/api/v1/scan/upload",
    tags=["Scan"],
    summary="Imbas muat naik ZIP",
    description="Terima ZIP kod dan imbas kandungan untuk kelemahan keselamatan, kebocoran rahsia, dan isu pematuhan.",
)
async def scan_upload(
    x_api_key: str = Header(..., alias="X-API-Key"),
    x_origin_domain: str = Header(..., alias="X-Origin-Domain"),
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    _validate_api_key(x_api_key, x_origin_domain, db)
    file_bytes = await file.read()
    result = zip_ingest.scan_zip_upload(file_bytes)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result


# --- Code Scan Endpoint ---

@app.post(
    "/api/v1/scan/code",
    tags=["Scan"],
    summary="Imbas kod sumber",
    description="Imbas blok kod atau fail untuk kelemahan CWE/CVE dan beri skor pematuhan automatik.",
)
def scan_code(
    body: CodeScanRequest,
    x_api_key: str = Header(..., alias="X-API-Key"),
    x_origin_domain: str = Header(..., alias="X-Origin-Domain"),
    db: Session = Depends(get_db),
):
    # Validate API key + domain
    key_hash = sha256_hash(x_api_key)
    api_key_record = (
        db.query(ApiKey)
        .filter(ApiKey.api_key_hash == key_hash, ApiKey.is_active.is_(True))
        .first()
    )
    if not api_key_record:
        raise HTTPException(status_code=401, detail="Invalid or inactive API key")
    if api_key_record.allowed_domain != x_origin_domain.lower().strip():
        raise HTTPException(status_code=403, detail="Domain not authorized")

    # CVE/CWE scan
    scan_result = cve_scanner.scan_code(body.code, body.filename)

    # Compliance score
    compliance = scorer.calculate(scan_result)

    return {
        "domain": x_origin_domain,
        "filename": body.filename,
        "total_issues": scan_result.total_issues,
        "severity_breakdown": {
            "critical": scan_result.critical,
            "high": scan_result.high,
            "medium": scan_result.medium,
            "low": scan_result.low,
        },
        "vulnerabilities": [
            {
                "cwe_id": v.cwe_id,
                "cve_ref": v.cve_ref,
                "title": v.title,
                "severity": v.severity,
                "description": v.description,
                "line_hint": v.line_hint,
                "owasp_ref": v.owasp_ref,
            }
            for v in scan_result.vulnerabilities
        ],
        "compliance_flags": scan_result.compliance_flags,
        "compliance_score": {
            "overall": compliance.overall,
            "grade": compliance.grade,
            "breakdown": compliance.breakdown,
        },
    }


# --- Compliance Score Endpoint ---

@app.get(
    "/portal/compliance/{domain}",
    tags=["Compliance"],
    summary="Skor pematuhan domain",
    description="Dapatkan penilaian keselamatan dan pematuhan bagi domain tertentu berdasarkan log aktiviti dan ancaman yang dikesan.",
)
def get_compliance(
    domain: str,
    user_id: str = Depends(verify_jwt),
    db: Session = Depends(get_db),
):
    # Ambil semua log untuk domain ini
    user_key_ids = [k.id for k in db.query(ApiKey).filter(ApiKey.user_id == user_id).all()]
    logs = (
        db.query(SecurityLog)
        .filter(SecurityLog.api_key_id.in_(user_key_ids), SecurityLog.source_domain == domain)
        .all()
    )
    total = len(logs)
    blocked = sum(1 for l in logs if l.status == "BLOCKED")

    # Skor asas berdasarkan kadar ancaman
    threat_rate = (blocked / total * 100) if total > 0 else 0
    base_score = max(0, 100 - (threat_rate * 2))

    return {
        "domain": domain,
        "total_scans": total,
        "blocked": blocked,
        "threat_rate": round(threat_rate, 2),
        "prompt_safety_score": round(base_score, 2),
        "grade": "A" if base_score >= 90 else "B" if base_score >= 75 else "C" if base_score >= 60 else "D" if base_score >= 40 else "F",
    }


# --- PDF Report Endpoint ---

@app.post(
    "/portal/report/pdf",
    tags=["Compliance"],
    summary="Hasilkan laporan PDF audit",
    description="Buat laporan audit keselamatan dalam format PDF untuk dokumen pematuhan dan penilaian pihak ketiga.",
)
def generate_pdf_report(
    body: CodeScanRequest,
    user_id: str = Depends(verify_jwt),
    db: Session = Depends(get_db),
):
    scan_result = cve_scanner.scan_code(body.code, body.filename)
    compliance = scorer.calculate(scan_result)

    user_key_ids = [k.id for k in db.query(ApiKey).filter(ApiKey.user_id == user_id).all()]
    total = db.query(SecurityLog).filter(SecurityLog.api_key_id.in_(user_key_ids)).count()
    blocked = (
        db.query(SecurityLog)
        .filter(SecurityLog.api_key_id.in_(user_key_ids), SecurityLog.status == "BLOCKED")
        .count()
    )

    try:
        pdf_bytes = pdf_generator.generate(
            domain=body.filename,
            scan_result=scan_result,
            compliance_score=compliance,
            prompt_stats={"total_requests": total, "total_blocked": blocked},
        )
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=audit-report-{body.filename}.pdf"},
        )
    except RuntimeError as e:
        raise HTTPException(status_code=501, detail=str(e))


# --- Engine Update Endpoint ---

class UpdateRequest(BaseModel):
    update_rules: bool = True
    update_models: bool = True


@app.post(
    "/admin/update",
    tags=["Admin"],
    summary="Kemas kini enjin keselamatan",
    description=(
        "Perbaharui peraturan atau model ML TrustGuard AI untuk mengekalkan ketepatan dan perlindungan terhadap ancaman terbaru."
    ),
)
def update_engine(
    body: UpdateRequest,
    user_id: str = Depends(verify_jwt),
):
    result = updater.run_update(
        update_rules_flag=body.update_rules,
        update_models_flag=body.update_models,
    )
    return {
        "success": result.success,
        "rules_updated": result.rules_updated,
        "models_refreshed": result.models_refreshed,
        "errors": result.errors,
        "timestamp": result.timestamp,
        "note": "Models will re-download on next scan request.",
    }


# --- Health Check ---

@app.get(
    "/health",
    tags=["Health"],
    summary="Semak kesihatan servis",
    description=(
        "Semak status TrustGuard AI, sama ada enjin beroperasi, dan versi aplikasi yang sedang berjalan."
    ),
)
def health():
    return {
        "status": "ok",
        "engine": "ACTIVE",
        "version": "1.0.0",
        "ml_available": hybrid_engine.ml_engine.is_available(),
    }


# ---------------------------------------------------------------------------
# ENTRY POINT
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)

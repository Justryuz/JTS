"""
TrustGuard v2.0 — Constants & Enumerations
Static values that do not change per environment.
"""

from __future__ import annotations

from enum import Enum


class AttackType(str, Enum):
    NONE = "NONE"
    PROMPT_INJECTION = "PROMPT_INJECTION"
    JAILBREAK = "JAILBREAK"
    TOXIC = "TOXIC"
    ENCODING_ATTACK = "ENCODING_ATTACK"
    ROLE_OVERRIDE = "ROLE_OVERRIDE"
    CONTEXT_POISONING = "CONTEXT_POISONING"


class ScanStatus(str, Enum):
    ALLOWED = "ALLOWED"
    BLOCKED = "BLOCKED"


class ScanJobStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class UserRole(str, Enum):
    ADMIN = "admin"
    SECURITY_ANALYST = "security_analyst"
    DEVELOPER = "developer"
    AUDITOR = "auditor"
    READONLY = "readonly"


class EngineMode(str, Enum):
    RULE = "rule"
    ML = "ml"
    HYBRID = "hybrid"


class ScanType(str, Enum):
    GITHUB_REPO = "github_repo"
    ZIP_UPLOAD = "zip_upload"
    LIVE_URL = "live_url"
    CODE = "code"
    SEO_POISON = "seo_poison"


# ── Error Codes ───────────────────────────────────────────────────────────────

class ErrorCode(str, Enum):
    # Auth (1000)
    INVALID_CREDENTIALS = "TG-1001"
    TOKEN_EXPIRED = "TG-1002"
    TOKEN_INVALID = "TG-1003"
    INSUFFICIENT_PERMISSION = "TG-1004"
    EMAIL_ALREADY_REGISTERED = "TG-1005"

    # API Key & Domain (2000)
    INVALID_API_KEY = "TG-2001"
    DOMAIN_NOT_AUTHORIZED = "TG-2002"
    API_KEY_REVOKED = "TG-2003"
    DOMAIN_ALREADY_VERIFIED = "TG-2004"
    API_KEY_NOT_FOUND = "TG-2005"
    DOMAIN_VERIFICATION_FAILED = "TG-2006"

    # Prompt Security (3000)
    PROMPT_INJECTION_DETECTED = "TG-3001"
    JAILBREAK_DETECTED = "TG-3002"
    PROMPT_TOO_LONG = "TG-3003"
    ENCODING_ATTACK_DETECTED = "TG-3004"

    # Scan (4000)
    REPO_TOO_LARGE = "TG-4001"
    REPO_CLONE_FAILED = "TG-4002"
    ZIP_INVALID = "TG-4003"
    ZIP_TOO_LARGE = "TG-4004"
    URL_NOT_SAFE = "TG-4005"
    SCAN_TIMEOUT = "TG-4006"
    TOO_MANY_FILES = "TG-4007"

    # Compliance (5000)
    COMPLIANCE_FAILED = "TG-5001"

    # System (6000)
    RATE_LIMIT_EXCEEDED = "TG-6001"
    REQUEST_TOO_LARGE = "TG-6002"

    # Internal (9000)
    INTERNAL_ERROR = "TG-9001"


# ── OWASP / Compliance References ────────────────────────────────────────────

OWASP_REFERENCES = {
    AttackType.PROMPT_INJECTION: "OWASP LLM01:2025",
    AttackType.JAILBREAK: "OWASP LLM02:2025",
    AttackType.ROLE_OVERRIDE: "OWASP LLM01:2025",
    AttackType.ENCODING_ATTACK: "OWASP LLM01:2025",
    AttackType.CONTEXT_POISONING: "OWASP LLM01:2025",
}

MITRE_ATLAS_REFERENCES = {
    AttackType.PROMPT_INJECTION: "AML.T0051",
    AttackType.JAILBREAK: "AML.T0054",
    AttackType.ROLE_OVERRIDE: "AML.T0054",
    AttackType.ENCODING_ATTACK: "AML.T0051",
    AttackType.CONTEXT_POISONING: "AML.T0051.001",
}

ALLOWED_SCAN_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx",
    ".php", ".java", ".rb", ".go", ".cs",
    ".cpp", ".c", ".h", ".rs", ".kt",
}

SKIP_DIRS = {
    "node_modules", ".git", "venv", "dist",
    "build", "__pycache__", ".next", "vendor",
    ".tox", ".mypy_cache", ".ruff_cache",
}

ALLOWED_REPO_HOSTS = {"github.com", "gitlab.com", "bitbucket.org"}

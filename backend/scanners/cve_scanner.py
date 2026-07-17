"""
CVE/CWE Scanner — Analisis Kod Sumber
Mengesan kelemahan keselamatan dalam kod yang dihantar oleh sistem bersambung
Pematuhan: OWASP Top 10, CWE/SANS Top 25, NACSA, CSM
"""

import logging
import re
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class Vulnerability:
    cwe_id: str        # contoh: CWE-89
    cve_ref: str       # contoh: CVE-2021-XXXX atau N/A
    title: str
    severity: str      # CRITICAL | HIGH | MEDIUM | LOW | INFO
    description: str
    line_hint: str     # baris kod yang mencetuskan
    owasp_ref: str     # contoh: A03:2021


@dataclass
class ScanResult:
    total_issues: int
    critical: int
    high: int
    medium: int
    low: int
    vulnerabilities: list = field(default_factory=list)
    compliance_flags: list = field(default_factory=list)


# ── CVE/CWE Rule Definitions ─────────────────────────────────────────────────

CVE_CWE_RULES = [
    # CWE-89: SQL Injection (OWASP A03)
    {
        "cwe_id": "CWE-89",
        "cve_ref": "CVE-2021-44228-like",
        "title": "SQL Injection",
        "severity": "CRITICAL",
        "owasp_ref": "A03:2021",
        "description": "Input pengguna digabungkan terus ke dalam query SQL tanpa sanitasi.",
        "patterns": [
            r"(execute|exec|query|cursor\.execute)\s*\(\s*[\"'].*?\+",
            r"(execute|exec|query|cursor\.execute)\s*\(\s*f[\"'].*?\{",
            r"SELECT\s+.+\s+FROM\s+.+\s+WHERE\s+.+\s*=\s*[\"']?\s*\+",
            r"(\"|\').*?(OR|AND)\s+[\"']?\d+[\"']?\s*=\s*[\"']?\d",
        ],
    },
    # CWE-79: XSS (OWASP A03)
    {
        "cwe_id": "CWE-79",
        "cve_ref": "N/A",
        "title": "Cross-Site Scripting (XSS)",
        "severity": "HIGH",
        "owasp_ref": "A03:2021",
        "description": "Output tidak di-escape boleh membenarkan skrip berbahaya dijalankan dalam browser.",
        "patterns": [
            r"innerHTML\s*=\s*(?!.*escHtml|.*sanitize|.*DOMPurify)",
            r"document\.write\s*\(",
            r"eval\s*\(\s*(request|input|param|query|body)",
            r"dangerouslySetInnerHTML",
        ],
    },
    # CWE-798: Hardcoded Credentials (OWASP A07)
    {
        "cwe_id": "CWE-798",
        "cve_ref": "N/A",
        "title": "Hardcoded Credentials",
        "severity": "CRITICAL",
        "owasp_ref": "A07:2021",
        "description": "Kata laluan, token atau kunci API ditulis terus dalam kod sumber.",
        "patterns": [
            r"(password|passwd|pwd|secret|api_key|apikey|token)\s*=\s*[\"'][^\"']{4,}[\"']",
            r"(Authorization|Bearer)\s*[=:]\s*[\"'][A-Za-z0-9+/=]{20,}",
            r"(aws_access_key|aws_secret|private_key)\s*=\s*[\"'][^\"']+[\"']",
        ],
    },
    # CWE-22: Path Traversal (OWASP A01)
    {
        "cwe_id": "CWE-22",
        "cve_ref": "N/A",
        "title": "Path Traversal",
        "severity": "HIGH",
        "owasp_ref": "A01:2021",
        "description": "Input pengguna digunakan dalam operasi fail tanpa pengesahan laluan.",
        "patterns": [
            r"open\s*\(\s*(request|input|param|query|body|user)",
            r"\.\./|\.\.\\",
            r"(readFile|writeFile|unlink)\s*\(\s*(req\.|request\.|input)",
        ],
    },
    # CWE-78: OS Command Injection (OWASP A03)
    {
        "cwe_id": "CWE-78",
        "cve_ref": "N/A",
        "title": "OS Command Injection",
        "severity": "CRITICAL",
        "owasp_ref": "A03:2021",
        "description": "Input pengguna dimasukkan ke dalam arahan sistem operasi.",
        "patterns": [
            r"(os\.system|subprocess\.call|subprocess\.run|exec|shell_exec|popen)\s*\(\s*(.*?(request|input|param|query|user))",
            r"(os\.system|subprocess\.call)\s*\(\s*f[\"']",
        ],
    },
    # CWE-502: Insecure Deserialization (OWASP A08)
    {
        "cwe_id": "CWE-502",
        "cve_ref": "N/A",
        "title": "Insecure Deserialization",
        "severity": "HIGH",
        "owasp_ref": "A08:2021",
        "description": "Data tidak dipercayai dideserialize tanpa pengesahan.",
        "patterns": [
            r"pickle\.loads?\s*\(",
            r"yaml\.load\s*\([^,)]+\)",   # tanpa Loader=yaml.SafeLoader
            r"unserialize\s*\(\s*(request|input|\$_)",
        ],
    },
    # CWE-306: Missing Authentication (OWASP A07)
    {
        "cwe_id": "CWE-306",
        "cve_ref": "N/A",
        "title": "Missing Authentication",
        "severity": "HIGH",
        "owasp_ref": "A07:2021",
        "description": "Endpoint sensitif tidak mempunyai pengesahan pengguna.",
        "patterns": [
            r"@app\.(get|post|put|delete)\s*\([\"']/admin",
            r"@app\.(get|post|put|delete)\s*\([\"']/api.*(delete|update|create|admin)",
        ],
    },
    # CWE-200: Sensitive Data Exposure (OWASP A02)
    {
        "cwe_id": "CWE-200",
        "cve_ref": "N/A",
        "title": "Sensitive Data Exposure",
        "severity": "MEDIUM",
        "owasp_ref": "A02:2021",
        "description": "Data sensitif seperti maklumat peribadi atau kewangan terdedah.",
        "patterns": [
            r"(print|console\.log|logger\.(info|debug))\s*\(.*?(password|token|secret|credit_card|ic_number|passport)",
            r"return\s+.*?(password_hash|secret_key|private_key)",
        ],
    },
    # CWE-311: Missing Encryption (OWASP A02) — JPDP compliance
    {
        "cwe_id": "CWE-311",
        "cve_ref": "N/A",
        "title": "Missing Encryption for Sensitive Data (JPDP)",
        "severity": "HIGH",
        "owasp_ref": "A02:2021",
        "description": "Data peribadi (PII) disimpan atau dihantar tanpa enkripsi — melanggar JPDP Malaysia.",
        "patterns": [
            r"(ic_number|passport_no|phone_number|email|nama_penuh|full_name)\s*=.{0,50}(db\.|database\.|INSERT|UPDATE)",
            r"http://(?!localhost|127\.0\.0\.1).+\.(my|com|net)",  # HTTP tanpa HTTPS
        ],
    },
    # CWE-20: Improper Input Validation (OWASP A03) — AI/LLM specific
    {
        "cwe_id": "CWE-20",
        "cve_ref": "N/A",
        "title": "Improper Input Validation (AI/LLM)",
        "severity": "MEDIUM",
        "owasp_ref": "A03:2021",
        "description": "Input ke model AI tidak disahkan atau dibersihkan sebelum diproses.",
        "patterns": [
            r"(openai|anthropic|gemini|llm|model)\..*?(complete|generate|chat)\s*\(\s*(request|input|body|user_input)",
            r"prompt\s*=\s*(request|input|body|f[\"'].*?\{)",
        ],
    },
]

# ── NACSA / JPDP / MCMC Compliance Flags ─────────────────────────────────────

COMPLIANCE_RULES = [
    {
        "ref": "JPDP-S.6",
        "title": "Penyimpanan Data Peribadi Tanpa Enkripsi",
        "pattern": r"(nama|name|email|phone|ic|passport|alamat|address)\s*=\s*(Column|Field|models\.)",
        "recommendation": "Enkripkan semua medan PII mengikut Akta PDPA 2010 (JPDP).",
    },
    {
        "ref": "NACSA-AI-3.1",
        "title": "Model AI Tanpa Input Sanitization",
        "pattern": r"(llm|model|ai|gpt|claude|gemini)\.(run|invoke|generate|predict)\s*\(\s*(?!.*sanitize|.*validate|.*shield)",
        "recommendation": "Semua input ke model AI mesti melalui lapisan sanitasi (NACSA AI Security Framework).",
    },
    {
        "ref": "MCMC-CMA-S.233",
        "title": "Logging Maklumat Sensitif",
        "pattern": r"(logging|logger|print)\s*\(.*?(password|token|ic|passport|credit)",
        "recommendation": "Jangan log maklumat sensitif — melanggar CMA 1998 (MCMC).",
    },
    {
        "ref": "AIGE-4.2",
        "title": "AI Output Tanpa Human Oversight",
        "pattern": r"(auto_approve|auto_execute|auto_deploy)\s*=\s*True",
        "recommendation": "Output AI kritikal memerlukan semakan manusia (AIGE Garis Panduan Etika AI).",
    },
]


# ── Scanner Function ──────────────────────────────────────────────────────────

def scan_code(code: str, filename: str = "unknown", use_ml: bool = True) -> ScanResult:
    """
    Scan kod sumber untuk CVE/CWE vulnerabilities dan compliance flags.
    """
    lines = code.splitlines()
    vulnerabilities = []
    compliance_flags = []
    severity_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    # CVE/CWE scan
    for rule in CVE_CWE_RULES:
        for pattern in rule["patterns"]:
            for i, line in enumerate(lines, start=1):
                if re.search(pattern, line, re.IGNORECASE):
                    # Elak duplikasi CWE yang sama pada baris yang sama
                    already = any(
                        v.cwe_id == rule["cwe_id"] and v.line_hint == f"{filename}:{i}"
                        for v in vulnerabilities
                    )
                    if not already:
                        vulnerabilities.append(Vulnerability(
                            cwe_id=rule["cwe_id"],
                            cve_ref=rule["cve_ref"],
                            title=rule["title"],
                            severity=rule["severity"],
                            description=rule["description"],
                            line_hint=f"{filename}:{i} → {line.strip()[:80]}",
                            owasp_ref=rule["owasp_ref"],
                        ))
                        if rule["severity"] in severity_count:
                            severity_count[rule["severity"]] += 1

    # Compliance scan
    for rule in COMPLIANCE_RULES:
        for i, line in enumerate(lines, start=1):
            if re.search(rule["pattern"], line, re.IGNORECASE):
                already = any(f["ref"] == rule["ref"] for f in compliance_flags)
                if not already:
                    compliance_flags.append({
                        "ref": rule["ref"],
                        "title": rule["title"],
                        "recommendation": rule["recommendation"],
                        "line_hint": f"{filename}:{i} → {line.strip()[:80]}",
                    })

    # ML-based insecure code scan (CodeBERT)
    if use_ml:
        try:
            from engines import ml_engine
            if ml_engine.is_available():
                ml_result = ml_engine.scan_code(code)
                if ml_result.status == "BLOCKED":
                    vulnerabilities.append(Vulnerability(
                        cwe_id="CWE-676",
                        cve_ref="N/A",
                        title="Insecure Code Pattern (ML)",
                        severity="HIGH",
                        description=f"CodeBERT detected insecure code pattern (confidence: {ml_result.confidence}).",
                        line_hint=f"{filename} — ML model: {ml_result.model_used}",
                        owasp_ref="A03:2021",
                    ))
                    severity_count["HIGH"] += 1
        except Exception as e:
            logger.warning(f"ML code scan skipped: {e}")

    return ScanResult(
        total_issues=len(vulnerabilities),
        critical=severity_count["CRITICAL"],
        high=severity_count["HIGH"],
        medium=severity_count["MEDIUM"],
        low=severity_count["LOW"],
        vulnerabilities=vulnerabilities,
        compliance_flags=compliance_flags,
    )

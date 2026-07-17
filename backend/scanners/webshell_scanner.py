"""
Webshell Scanner — Detect webshell and backdoor patterns in source files.
Combines patterns from both reference bash scripts.
Supports: .php, .txt, .py, .js, .asp, .aspx, .jsp
"""

import logging
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

SCAN_EXTENSIONS = {".php", ".txt", ".py", ".js", ".asp", ".aspx", ".jsp"}
SKIP_DIRS = {"node_modules", ".git", "venv", "dist", "build", "__pycache__", ".next", "vendor"}
MAX_FILES = 500

# ── Webshell Patterns ─────────────────────────────────────────────────────────

WEBSHELL_PATTERNS = [
    # Code execution
    {
        "id": "WS-001",
        "title": "PHP eval() — Remote Code Execution",
        "severity": "CRITICAL",
        "pattern": r"eval\s*\(",
        "description": "eval() can execute arbitrary PHP code injected by an attacker.",
    },
    {
        "id": "WS-002",
        "title": "base64_decode() with eval — Obfuscated Payload",
        "severity": "CRITICAL",
        "pattern": r"base64(_decode)?\s*\(",
        "description": "base64_decode() is commonly used to obfuscate webshell payloads.",
    },
    {
        "id": "WS-003",
        "title": "shell_exec() — Shell Command Execution",
        "severity": "CRITICAL",
        "pattern": r"shell_exec\s*\(",
        "description": "shell_exec() executes OS commands and returns output — common in webshells.",
    },
    {
        "id": "WS-004",
        "title": "system() — OS Command Execution",
        "severity": "CRITICAL",
        "pattern": r"\bsystem\s*\(",
        "description": "system() executes OS commands — frequently abused in webshells.",
    },
    {
        "id": "WS-005",
        "title": "passthru() — Raw Command Output",
        "severity": "CRITICAL",
        "pattern": r"passthru\s*\(",
        "description": "passthru() executes commands and passes raw output — webshell indicator.",
    },
    {
        "id": "WS-006",
        "title": "exec() — Command Execution",
        "severity": "HIGH",
        "pattern": r"\bexec\s*\(",
        "description": "exec() runs OS commands — commonly found in backdoors.",
    },
    {
        "id": "WS-007",
        "title": "fsockopen() / pfsockopen() — Reverse Shell Socket",
        "severity": "CRITICAL",
        "pattern": r"p?fsockopen\s*\(",
        "description": "fsockopen/pfsockopen open raw TCP sockets — used in reverse shell webshells.",
    },
    {
        "id": "WS-008",
        "title": "assert() — Code Execution via String",
        "severity": "CRITICAL",
        "pattern": r"\bassert\s*\(",
        "description": "assert() can evaluate strings as PHP code — used to bypass eval() detection.",
    },
    # Obfuscation
    {
        "id": "WS-009",
        "title": "Hex-encoded String — Obfuscation",
        "severity": "HIGH",
        "pattern": r"(\\x[0-9a-fA-F]{2}){4,}",
        "description": "Long hex-encoded strings are used to obfuscate malicious payloads.",
    },
    {
        "id": "WS-010",
        "title": "String Concatenation Obfuscation",
        "severity": "MEDIUM",
        "pattern": r'(\."[a-zA-Z_]{2,6}")+',
        "description": "Chained string concatenation is a common PHP obfuscation technique.",
    },
    {
        "id": "WS-011",
        "title": "zlib Compressed Payload",
        "severity": "HIGH",
        "pattern": r"(z|Z)lib.?(decompress)?",
        "description": "zlib decompression used to unpack hidden payloads at runtime.",
    },
    {
        "id": "WS-012",
        "title": "FromBase64String — .NET Obfuscation",
        "severity": "HIGH",
        "pattern": r"FromBase64String\s*\(",
        "description": ".NET base64 decoding used to hide malicious code in ASPX webshells.",
    },
    {
        "id": "WS-013",
        "title": "JavaScript Packer (p,a,c,k,e,r)",
        "severity": "HIGH",
        "pattern": r"function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*r\s*\)",
        "description": "JavaScript packer obfuscation — commonly used to hide malicious JS.",
    },
    # Known backdoor signatures
    {
        "id": "WS-014",
        "title": "Known Backdoor Keyword — Root Shell",
        "severity": "CRITICAL",
        "pattern": r"(ROOT\s*SHELL\s*EXECUTOR|rootshell)",
        "description": "Known root shell backdoor signature detected.",
    },
    {
        "id": "WS-015",
        "title": "Known Backdoor Keyword — Backdoor/Pwnkit",
        "severity": "CRITICAL",
        "pattern": r"(Backdoor|pwnkit|getroot)",
        "description": "Known backdoor or privilege escalation keyword detected.",
    },
    {
        "id": "WS-016",
        "title": "Mass Defacement Function",
        "severity": "CRITICAL",
        "pattern": r"(mass[_ ][a-z]{1,10}|hapus_massal\s*\(|sendcmd\s*\()",
        "description": "Mass defacement or mass deletion function — common in hacktivist webshells.",
    },
    {
        "id": "WS-017",
        "title": "Known Webshell Author Signature",
        "severity": "HIGH",
        "pattern": r"(Mr\.Fn4ticHz|AnonSec|HaxorNoName|Luqman1337|Krw4u|yuuki|Chitoge|Kirisaki|bayangsuluh|gasken)",
        "description": "Known webshell author or group signature found in file.",
    },
    {
        "id": "WS-018",
        "title": "Hardcoded Hash — Backdoor Auth Token",
        "severity": "HIGH",
        "pattern": r"d038b2fa6f229db5",
        "description": "Known backdoor authentication hash detected.",
    },
    # Suspicious functionality
    {
        "id": "WS-019",
        "title": "phpinfo() — Server Information Disclosure",
        "severity": "MEDIUM",
        "pattern": r"phpinfo\s*\(\s*\)",
        "description": "phpinfo() exposes full server configuration — often left by attackers for reconnaissance.",
    },
    {
        "id": "WS-020",
        "title": "php_uname() / getcwd() — System Recon",
        "severity": "MEDIUM",
        "pattern": r"(php_uname\s*\(\s*\)|getcwd\s*\(\s*\))",
        "description": "System recon functions used by webshells to gather environment information.",
    },
    {
        "id": "WS-021",
        "title": "$scandir — Directory Listing",
        "severity": "MEDIUM",
        "pattern": r"\$scandir",
        "description": "Directory scanning variable — used by webshells to enumerate server files.",
    },
    {
        "id": "WS-022",
        "title": "cmd.exe Reference — Windows Shell",
        "severity": "CRITICAL",
        "pattern": r"cmd\.exe",
        "description": "Direct reference to Windows cmd.exe — indicator of Windows-targeting webshell.",
    },
    {
        "id": "WS-023",
        "title": "mail() — Spam/Exfiltration Function",
        "severity": "MEDIUM",
        "pattern": r"\bmail\s*\(",
        "description": "mail() used in webshells for spam sending or data exfiltration.",
    },
    # Spam/SEO injection keywords
    {
        "id": "WS-024",
        "title": "SEO Spam Injection Keywords",
        "severity": "LOW",
        "pattern": r"\b(casino|porn|sexy)\b",
        "description": "SEO spam keywords — indicator of content injection or spam webshell.",
    },
    # Suspicious URL patterns (from script 2)
    {
        "id": "WS-025",
        "title": "Suspicious URL Parameter — cmd/path",
        "severity": "HIGH",
        "pattern": r"(cmd=|path=)",
        "description": "Suspicious GET parameters commonly used by webshell C2 communication.",
    },
    {
        "id": "WS-026",
        "title": "/etc/passwd Reference",
        "severity": "CRITICAL",
        "pattern": r"/etc/passwd",
        "description": "Reference to /etc/passwd — LFI or credential harvesting attempt.",
    },
    {
        "id": "WS-027",
        "title": "ALFA/alfa Webshell Signature",
        "severity": "CRITICAL",
        "pattern": r"\b(alfa|ALFA)\b",
        "description": "ALFA webshell signature — one of the most common PHP webshells.",
    },
    {
        "id": "WS-028",
        "title": "CGI Function — cgi_decodevar/cgi_getvars",
        "severity": "HIGH",
        "pattern": r"cgi_(decodevar|getvars)\s*\(\s*\)",
        "description": "CGI utility functions used in Perl/CGI-based webshells.",
    },
    {
        "id": "WS-029",
        "title": "W3NvbGV2aXNpYm — Known Encoded Payload",
        "severity": "CRITICAL",
        "pattern": r"W3NvbGV2aXNpYm",
        "description": "Known base64-encoded webshell payload fragment detected.",
    },
    {
        "id": "WS-030",
        "title": "Xavier Webshell Signature",
        "severity": "HIGH",
        "pattern": r".*Xavier.*",
        "description": "Xavier webshell author signature detected.",
    },
]


@dataclass
class WebshellFinding:
    file: str
    line_number: int
    line_content: str
    pattern_id: str
    title: str
    severity: str
    description: str


@dataclass
class WebshellScanResult:
    total_files_scanned: int
    total_findings: int
    severity_breakdown: dict
    findings_by_file: dict = field(default_factory=dict)
    scan_duration_seconds: float = 0.0
    timestamp: str = ""


# ── Core scan functions ───────────────────────────────────────────────────────

def scan_content(content: str, filename: str) -> list[WebshellFinding]:
    """Scan a single file's content for webshell patterns."""
    findings = []
    lines = content.splitlines()
    for i, line in enumerate(lines, start=1):
        for rule in WEBSHELL_PATTERNS:
            if re.search(rule["pattern"], line, re.IGNORECASE):
                # Deduplicate: same rule on same line
                already = any(
                    f.pattern_id == rule["id"] and f.line_number == i
                    for f in findings
                )
                if not already:
                    findings.append(WebshellFinding(
                        file=filename,
                        line_number=i,
                        line_content=line.strip()[:120],
                        pattern_id=rule["id"],
                        title=rule["title"],
                        severity=rule["severity"],
                        description=rule["description"],
                    ))
    return findings


def scan_directory(directory: str) -> WebshellScanResult:
    """Scan all supported files in a directory recursively."""
    start = time.time()
    base = Path(directory)

    if not base.is_dir():
        return WebshellScanResult(
            total_files_scanned=0,
            total_findings=0,
            severity_breakdown={"critical": 0, "high": 0, "medium": 0, "low": 0},
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

    files = [
        f for f in base.rglob("*")
        if f.is_file()
        and f.suffix.lower() in SCAN_EXTENSIONS
        and not any(skip in f.parts for skip in SKIP_DIRS)
    ][:MAX_FILES]

    return _run_scan(files, base, start)


def scan_files(file_map: dict[str, str]) -> WebshellScanResult:
    """Scan pre-loaded file contents (used by ZIP ingest)."""
    start = time.time()
    severity_count = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    findings_by_file: dict[str, list] = {}

    for filename, content in file_map.items():
        if Path(filename).suffix.lower() not in SCAN_EXTENSIONS:
            continue
        findings = scan_content(content, filename)
        if findings:
            findings_by_file[filename] = [_finding_to_dict(f) for f in findings]
            for f in findings:
                sev = f.severity.lower()
                if sev in severity_count:
                    severity_count[sev] += 1

    total = sum(severity_count.values())
    return WebshellScanResult(
        total_files_scanned=len(file_map),
        total_findings=total,
        severity_breakdown=severity_count,
        findings_by_file=findings_by_file,
        scan_duration_seconds=round(time.time() - start, 2),
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


def _run_scan(files: list[Path], base: Path, start: float) -> WebshellScanResult:
    severity_count = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    findings_by_file: dict[str, list] = {}

    for f in files:
        try:
            content = f.read_text(errors="ignore")
        except Exception:
            continue
        rel = str(f.relative_to(base))
        findings = scan_content(content, rel)
        if findings:
            findings_by_file[rel] = [_finding_to_dict(fi) for fi in findings]
            for fi in findings:
                sev = fi.severity.lower()
                if sev in severity_count:
                    severity_count[sev] += 1

    total = sum(severity_count.values())
    return WebshellScanResult(
        total_files_scanned=len(files),
        total_findings=total,
        severity_breakdown=severity_count,
        findings_by_file=findings_by_file,
        scan_duration_seconds=round(time.time() - start, 2),
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


def _finding_to_dict(f: WebshellFinding) -> dict:
    return {
        "pattern_id": f.pattern_id,
        "title": f.title,
        "severity": f.severity,
        "line": f.line_number,
        "line_content": f.line_content,
        "description": f.description,
    }

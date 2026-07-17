"""
TrustGuard v2.0 — SEO Poison Scanner
Detects SEO poisoning / spam injection on websites.
Adapted from seo_poison_scanner.py (standalone tool).
"""

from __future__ import annotations

import ipaddress
import re
import socket
import time
import urllib.parse
from datetime import datetime, timezone
from typing import Optional

try:
    import httpx
    _HTTPX = True
except ImportError:
    _HTTPX = False

try:
    from bs4 import BeautifulSoup
    _BS4 = True
except ImportError:
    _BS4 = False


# ---------------------------------------------------------------------------
# Signatures
# ---------------------------------------------------------------------------

SPAM_KEYWORDS = [
    "viagra", "cialis", "casino online", "judi online", "slot online", "toto togel",
    "situs slot", "bandar togel", "replica watches", "louis vuitton replica",
    "essay writing service", "buy backlinks", "payday loans", "canadian pharmacy",
    "порно", "xxx tube", "escort service", "situs judi", "link alternatif slot",
    "agen bola", "poker online terpercaya",
]

SUSPICIOUS_CODE_PATTERNS = [
    r"eval\s*\(\s*base64_decode",
    r"eval\s*\(\s*gzinflate",
    r"eval\s*\(\s*str_rot13",
    r"assert\s*\(\s*\$_(POST|GET|REQUEST)",
    r"preg_replace\s*\(.*\/e['\"]",
    r"create_function\s*\(",
    r"FilesMan|c99shell|r57shell|WSO\s*Shell|b374k",
    r"system\s*\(\s*\$_(POST|GET|REQUEST)",
    r"shell_exec\s*\(\s*\$_(POST|GET|REQUEST)",
]

SUSPICIOUS_REWRITE_PATTERNS = [
    r"HTTP_USER_AGENT.*Googlebot",
    r"RewriteCond.*HTTP_REFERER.*google",
    r"RewriteRule.*base64",
]

UA_NORMAL = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36"
UA_GOOGLEBOT = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"

SIMPLE_EXPLANATIONS = {
    "SPAM_KEYWORD": "Kata kunci spam SEO ditemui pada halaman — laman mungkin telah digodam dan disuntik kandungan spam.",
    "CLOAKING": "Kandungan berbeza dipaparkan kepada Googlebot vs pelawat biasa — tanda SEO poisoning yang kuat.",
    "HIDDEN_CONTENT": "Elemen tersembunyi mengandungi teks — corak biasa SEO poisoning.",
    "LINK_FARM": "Terlalu banyak pautan keluar ke domain luar — mungkin link injection.",
    "SUSPICIOUS_REDIRECT": "Redirect ke domain luar yang tidak berkaitan — mungkin redirect spam/malware.",
    "WEBSHELL_PATTERN": "Corak kod webshell/backdoor dikesan dalam fail — kemungkinan fail telah dijangkiti.",
    "HTACCESS_CLOAKING": "Peraturan rewrite mencurigakan dalam .htaccess — mungkin digunakan untuk cloaking.",
    "ROBOTS_SPAM": "robots.txt mengandungi teks spam — kemungkinan disuntik.",
}


# ---------------------------------------------------------------------------
# SSRF protection (reuse pattern from url_ingest.py)
# ---------------------------------------------------------------------------

def _is_safe_host(hostname: str) -> bool:
    if not hostname:
        return False
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return False
    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0])
        except ValueError:
            return False
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
            return False
    return True


def _validate_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only http/https URLs are allowed")
    if not parsed.hostname or not _is_safe_host(parsed.hostname):
        raise ValueError("URL resolves to a private/internal address — not allowed")
    return url


def _redirect_guard(request: "httpx.Request") -> None:
    if not _is_safe_host(request.url.host):
        raise httpx.RequestError(f"Redirect to unsafe host blocked: {request.url.host}", request=request)


# ---------------------------------------------------------------------------
# External scan
# ---------------------------------------------------------------------------

def _scan_external(base_url: str, max_pages: int) -> list[dict]:
    if not _HTTPX or not _BS4:
        return [{"type": "DEPENDENCY_MISSING", "severity": "HIGH",
                 "description": "httpx or beautifulsoup4 not installed", "location": base_url}]

    findings = []
    visited: set[str] = set()
    queue = [base_url]
    domain = urllib.parse.urlparse(base_url).netloc

    client = httpx.Client(
        timeout=15,
        follow_redirects=True,
        verify=True,
        event_hooks={"request": [_redirect_guard]},
    )

    try:
        while queue and len(visited) < max_pages:
            url = queue.pop(0)
            if url in visited:
                continue
            visited.add(url)

            try:
                resp_normal = client.get(url, headers={"User-Agent": UA_NORMAL})
            except Exception:
                continue

            # Suspicious redirect
            if resp_normal.history:
                final_domain = urllib.parse.urlparse(str(resp_normal.url)).netloc
                if final_domain != domain:
                    chain = " -> ".join([str(r.url) for r in resp_normal.history] + [str(resp_normal.url)])
                    findings.append({"type": "SUSPICIOUS_REDIRECT", "severity": "HIGH",
                                     "location": url, "evidence": chain,
                                     "description": "Redirect to unrelated external domain.",
                                     "simple_explanation": SIMPLE_EXPLANATIONS["SUSPICIOUS_REDIRECT"]})

            soup = BeautifulSoup(resp_normal.text, "html.parser")
            page_text = soup.get_text(" ", strip=True).lower()
            title_text = (soup.title.string or "").lower() if soup.title else ""

            # Spam keywords
            for kw in SPAM_KEYWORDS:
                if kw in page_text or kw in title_text:
                    findings.append({"type": "SPAM_KEYWORD", "severity": "HIGH",
                                     "location": url, "evidence": kw,
                                     "description": f"Spam SEO keyword detected: '{kw}'",
                                     "simple_explanation": SIMPLE_EXPLANATIONS["SPAM_KEYWORD"]})

            # Hidden elements — only flag if spam keywords present inside
            _NAV_TAGS = {"nav", "header", "footer", "ul", "ol", "li", "menu"}
            _NAV_CLASSES = {"nav", "menu", "navbar", "navigation", "sidebar", "dropdown", "mobile", "hamburger"}
            for tag in soup.find_all(style=True):
                style = tag["style"].lower().replace(" ", "")
                if not any(s in style for s in ("display:none", "visibility:hidden", "font-size:0", "opacity:0")):
                    continue
                # Skip nav/menu elements — these are legitimately hidden on mobile
                tag_name = tag.name or ""
                tag_classes = " ".join(tag.get("class", [])).lower()
                if tag_name in _NAV_TAGS or any(c in tag_classes for c in _NAV_CLASSES):
                    continue
                # Only flag if the hidden text actually contains spam keywords
                snippet = tag.get_text(strip=True)
                snippet_lower = snippet.lower()
                matched_kw = next((kw for kw in SPAM_KEYWORDS if kw in snippet_lower), None)
                if matched_kw:
                    findings.append({"type": "HIDDEN_CONTENT", "severity": "HIGH",
                                     "location": url, "evidence": snippet[:120],
                                     "description": f"Hidden element contains spam keyword: '{matched_kw}'",
                                     "simple_explanation": SIMPLE_EXPLANATIONS["HIDDEN_CONTENT"]})

            # Link farm — skip trusted institutional domains, raise threshold
            _TRUSTED_TLDS = (".edu", ".edu.my", ".gov", ".gov.my", ".ac.uk", ".ac.my")
            _is_trusted = any(domain.endswith(t) for t in _TRUSTED_TLDS)
            _link_threshold = 150 if _is_trusted else 80
            foreign = [a.get("href", "") for a in soup.find_all("a", href=True)
                       if a.get("href", "").startswith("http")
                       and urllib.parse.urlparse(a["href"]).netloc not in ("", domain)]
            if len(foreign) > _link_threshold:
                findings.append({"type": "LINK_FARM", "severity": "MEDIUM",
                                  "location": url,
                                  "description": f"{len(foreign)} outbound links to external domains on one page.",
                                  "simple_explanation": SIMPLE_EXPLANATIONS["LINK_FARM"]})

            # Cloaking check — only flag if bot sees 3+ spam keywords that normal UA sees 0
            try:
                resp_bot = client.get(url, headers={"User-Agent": UA_GOOGLEBOT})
                bot_text = BeautifulSoup(resp_bot.text, "html.parser").get_text(" ", strip=True).lower()
                bot_hits = [kw for kw in SPAM_KEYWORDS if kw in bot_text]
                normal_hits = [kw for kw in SPAM_KEYWORDS if kw in page_text]
                if len(bot_hits) >= 3 and len(normal_hits) == 0:
                    findings.append({"type": "CLOAKING", "severity": "HIGH",
                                     "location": url,
                                     "evidence": ", ".join(bot_hits[:5]),
                                     "description": f"Spam keywords visible to Googlebot but not normal visitors: {', '.join(bot_hits[:5])}",
                                     "simple_explanation": SIMPLE_EXPLANATIONS["CLOAKING"]})
            except Exception:
                pass

            # Collect internal links
            for a in soup.find_all("a", href=True):
                href = urllib.parse.urljoin(url, a["href"])
                if urllib.parse.urlparse(href).netloc == domain and href not in visited:
                    queue.append(href)

            time.sleep(0.3)

        # robots.txt
        try:
            robots = client.get(urllib.parse.urljoin(base_url, "/robots.txt"),
                                 headers={"User-Agent": UA_NORMAL})
            if robots.status_code == 200:
                for line in robots.text.splitlines():
                    if any(k in line.lower() for k in ["viagra", "casino", "slot", "judi", "togel"]):
                        findings.append({"type": "ROBOTS_SPAM", "severity": "MEDIUM",
                                          "location": base_url + "/robots.txt",
                                          "evidence": line.strip(),
                                          "description": "robots.txt contains spam text — possibly injected.",
                                          "simple_explanation": SIMPLE_EXPLANATIONS["ROBOTS_SPAM"]})
        except Exception:
            pass

    finally:
        client.close()

    return findings


# ---------------------------------------------------------------------------
# Filesystem scan (for ZIP/repo scans — receives {filename: content} dict)
# ---------------------------------------------------------------------------

def _scan_files(files: dict[str, str]) -> list[dict]:
    """Scan a dict of {filename: content} for SEO poison / webshell patterns."""
    findings = []
    compiled_code = [re.compile(p, re.IGNORECASE) for p in SUSPICIOUS_CODE_PATTERNS]

    for fname, content in files.items():
        ext = fname.lower().rsplit(".", 1)[-1] if "." in fname else ""
        if ext not in ("php", "phtml", "php5", "inc", "js", "htaccess"):
            continue

        # Webshell / obfuscation patterns
        for pat in compiled_code:
            m = pat.search(content)
            if m:
                findings.append({
                    "type": "WEBSHELL_PATTERN", "severity": "HIGH",
                    "location": fname,
                    "evidence": content[max(0, m.start() - 40):m.start() + 80].strip(),
                    "description": f"Suspicious code pattern detected: /{pat.pattern}/",
                    "simple_explanation": SIMPLE_EXPLANATIONS["WEBSHELL_PATTERN"],
                })

        # .htaccess cloaking rules
        if fname.lower() in (".htaccess", "nginx.conf") or fname.lower().endswith(".conf"):
            for pat_str in SUSPICIOUS_REWRITE_PATTERNS:
                m = re.search(pat_str, content, re.IGNORECASE)
                if m:
                    findings.append({
                        "type": "HTACCESS_CLOAKING", "severity": "HIGH",
                        "location": fname, "evidence": m.group(0),
                        "description": "Suspicious rewrite rule (cloaking/spam redirect based on user-agent/referrer).",
                        "simple_explanation": SIMPLE_EXPLANATIONS["HTACCESS_CLOAKING"],
                    })

        # Spam keywords in source
        content_lower = content.lower()
        for kw in SPAM_KEYWORDS:
            if kw in content_lower:
                findings.append({
                    "type": "SPAM_KEYWORD", "severity": "MEDIUM",
                    "location": fname, "evidence": kw,
                    "description": f"Spam keyword found in source file: '{kw}'",
                    "simple_explanation": SIMPLE_EXPLANATIONS["SPAM_KEYWORD"],
                })
                break  # one finding per file is enough

    return findings


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def scan_seo(
    url: Optional[str] = None,
    files: Optional[dict[str, str]] = None,
    max_pages: int = 20,
) -> dict:
    """
    Run SEO poison scan.
    - url: scan external URL (crawl up to max_pages pages)
    - files: scan {filename: content} dict (from ZIP/repo ingest)
    Either or both can be provided.
    """
    start = datetime.now(timezone.utc)
    all_findings: list[dict] = []

    if url:
        try:
            safe_url = _validate_url(url)
        except ValueError as e:
            return {"error": str(e)}
        all_findings += _scan_external(safe_url, max_pages)

    if files:
        all_findings += _scan_files(files)

    severity_map = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in all_findings:
        sev = f.get("severity", "LOW").lower()
        if sev in severity_map:
            severity_map[sev] += 1

    total = len(all_findings)
    penalty = severity_map["critical"] * 15 + severity_map["high"] * 8 + severity_map["medium"] * 3 + severity_map["low"] * 1
    overall = max(0.0, round(100.0 - penalty, 1))

    def _grade(s: float) -> str:
        if s >= 90: return "A"
        if s >= 75: return "B"
        if s >= 60: return "C"
        if s >= 40: return "D"
        return "F"

    duration = round((datetime.now(timezone.utc) - start).total_seconds(), 2)

    return {
        "scan_type": "seo_poison",
        "target": url or "filesystem",
        "total_issues": total,
        "severity_breakdown": severity_map,
        "findings": all_findings,
        "compliance_score": {
            "overall": overall,
            "grade": _grade(overall),
        },
        "scan_duration_seconds": duration,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

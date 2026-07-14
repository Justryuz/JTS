"""
Live URL Scanner — DAST asas untuk semak keselamatan laman web
"""

import logging
import ssl
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx

from engine.aggregator import aggregate_results

logger = logging.getLogger(__name__)

TIMEOUT = 15
REQUEST_DELAY = 1  # max 1 req/saat

EXPOSED_PATHS = [
    "/.env",
    "/.git/config",
    "/admin",
    "/.well-known/security.txt",
    "/wp-config.php",
    "/config.php",
    "/.htaccess",
    "/server-status",
]

REQUIRED_HEADERS = [
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
]

SIMPLE_EXPLANATIONS = {
    "EXPOSED_PATH": "Fail atau folder sensitif boleh diakses oleh sesiapa sahaja di internet. Ini boleh mendedahkan maklumat sulit seperti kata laluan atau konfigurasi server anda.",
    "MISSING_SECURITY_HEADER": "Pelayar web tidak diberitahu cara melindungi pengguna anda. Ini memudahkan penyerang untuk mencuri data atau menipu pengguna anda.",
    "ERROR_LEAK": "Server anda mendedahkan maklumat teknikal dalaman apabila berlaku ralat. Maklumat ini boleh digunakan oleh penggodam untuk menyerang sistem anda.",
    "CORS_WILDCARD": "Laman web anda membenarkan mana-mana website lain baca data dari server anda. Ini bahaya kerana orang jahat boleh curi maklumat pengguna anda dari website lain.",
    "SSL_ISSUE": "Sambungan ke laman web anda tidak selamat atau sijil keselamatan hampir tamat. Maklumat pengguna anda mungkin boleh dicuri semasa penghantaran.",
}


def scan_live_url(url: str) -> dict:
    """Scan laman web hidup untuk isu keselamatan asas (DAST)."""
    start = time.time()
    issues = []

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    client = httpx.Client(timeout=TIMEOUT, follow_redirects=True, verify=False)

    try:
        # 1. Semak exposed paths
        for path in EXPOSED_PATHS:
            try:
                r = client.get(base_url + path)
                time.sleep(REQUEST_DELAY)
                if r.status_code == 200:
                    issues.append({
                        "type": "EXPOSED_PATH",
                        "severity": "HIGH",
                        "path": path,
                        "description": f"Laluan sensitif `{path}` boleh diakses secara awam (HTTP 200).",
                        "recommendation": f"Sekat akses ke `{path}` dalam konfigurasi web server anda.",
                        "simple_explanation": SIMPLE_EXPLANATIONS["EXPOSED_PATH"],
                    })
            except Exception:
                pass

        # 2. Semak security headers
        try:
            r = client.get(base_url)
            time.sleep(REQUEST_DELAY)
            for header in REQUIRED_HEADERS:
                if header not in {k.lower() for k in r.headers}:
                    issues.append({
                        "type": "MISSING_SECURITY_HEADER",
                        "severity": "MEDIUM",
                        "header": header,
                        "description": f"Header keselamatan `{header}` tidak ditemui dalam response.",
                        "recommendation": f"Tambah header `{header}` dalam konfigurasi server anda.",
                        "simple_explanation": SIMPLE_EXPLANATIONS["MISSING_SECURITY_HEADER"],
                    })
        except Exception:
            pass

        # 3. Verbose error leak check
        try:
            r = client.get(base_url + "/__justguard_test_404__")
            time.sleep(REQUEST_DELAY)
            body = r.text.lower()
            leak_keywords = ["traceback", "stack trace", "exception", "at line", "syntax error", "django", "flask", "laravel"]
            for kw in leak_keywords:
                if kw in body:
                    issues.append({
                        "type": "ERROR_LEAK",
                        "severity": "MEDIUM",
                        "description": f"Server mendedahkan maklumat teknikal dalam error page (keyword: '{kw}').",
                        "recommendation": "Matikan debug mode dan sembunyikan error details dalam production.",
                        "simple_explanation": SIMPLE_EXPLANATIONS["ERROR_LEAK"],
                    })
                    break
        except Exception:
            pass

        # 4. CORS check
        try:
            r = client.get(base_url, headers={"Origin": "https://evil-test.justguard.my"})
            time.sleep(REQUEST_DELAY)
            acao = r.headers.get("access-control-allow-origin", "")
            if acao == "*" or "evil-test.justguard.my" in acao:
                issues.append({
                    "type": "CORS_WILDCARD",
                    "severity": "HIGH",
                    "cwe": "CWE-942",
                    "description": f"CORS header `Access-Control-Allow-Origin: {acao}` terlalu longgar.",
                    "recommendation": "Hadkan CORS kepada domain yang dibenarkan sahaja.",
                    "simple_explanation": SIMPLE_EXPLANATIONS["CORS_WILDCARD"],
                })
        except Exception:
            pass

        # 5. SSL/TLS check
        if parsed.scheme == "https":
            try:
                ctx = ssl.create_default_context()
                with ctx.wrap_socket(
                    __import__("socket").create_connection((parsed.netloc, 443), timeout=TIMEOUT),
                    server_hostname=parsed.netloc,
                ) as s:
                    cert = s.getpeercert()
                    expiry_str = cert.get("notAfter", "")
                    if expiry_str:
                        expiry = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                        days_left = (expiry - datetime.now(timezone.utc)).days
                        if days_left < 30:
                            issues.append({
                                "type": "SSL_ISSUE",
                                "severity": "HIGH",
                                "description": f"Sijil SSL akan tamat dalam {days_left} hari ({expiry_str}).",
                                "recommendation": "Perbaharui sijil SSL sebelum tamat tempoh.",
                                "simple_explanation": SIMPLE_EXPLANATIONS["SSL_ISSUE"],
                            })
            except ssl.SSLError as e:
                issues.append({
                    "type": "SSL_ISSUE",
                    "severity": "HIGH",
                    "description": f"Ralat SSL: {str(e)[:100]}",
                    "recommendation": "Semak konfigurasi SSL/TLS server anda.",
                    "simple_explanation": SIMPLE_EXPLANATIONS["SSL_ISSUE"],
                })
            except Exception:
                pass
        else:
            issues.append({
                "type": "SSL_ISSUE",
                "severity": "HIGH",
                "description": "Laman web menggunakan HTTP tanpa enkripsi.",
                "recommendation": "Pasang sijil SSL dan redirect semua traffic ke HTTPS.",
                "simple_explanation": SIMPLE_EXPLANATIONS["SSL_ISSUE"],
            })

    finally:
        client.close()

    # Format sebagai aggregate result
    severity_map = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for issue in issues:
        sev = issue.get("severity", "LOW").upper()
        if sev in severity_map:
            severity_map[sev] += 1

    return {
        "scan_type": "live_url",
        "target": url,
        "total_files_scanned": 0,
        "total_issues": len(issues),
        "severity_breakdown": {"critical": severity_map["CRITICAL"], "high": severity_map["HIGH"], "medium": severity_map["MEDIUM"], "low": severity_map["LOW"]},
        "issues_by_file": {"live_url": issues},
        "compliance_score": {"overall": max(0, 100 - len(issues) * 10), "grade": _grade(max(0, 100 - len(issues) * 10)), "breakdown": {}},
        "scan_duration_seconds": round(time.time() - start, 2),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def _grade(score: float) -> str:
    if score >= 90: return "A"
    if score >= 75: return "B"
    if score >= 60: return "C"
    if score >= 40: return "D"
    return "F"

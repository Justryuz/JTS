"""
Aggregator — Gabung semua scan results ke project-level report
"""

from datetime import datetime, timezone

from compliance import scorer

SIMPLE_EXPLANATIONS = {
    "CWE-89": "Kod anda membenarkan penggodam masukkan arahan SQL berbahaya. Ini boleh menyebabkan semua data dalam database anda dicuri atau dipadam.",
    "CWE-79": "Laman web anda boleh digunakan untuk serang pengguna lain dengan kod JavaScript berbahaya yang disuntik oleh penggodam.",
    "CWE-798": "Kata laluan atau kunci rahsia ditulis terus dalam kod. Sesiapa yang baca kod ini boleh akses sistem anda.",
    "CWE-22": "Penggodam boleh akses fail di luar folder yang sepatutnya, termasuk fail sistem yang sensitif.",
    "CWE-78": "Input pengguna boleh digunakan untuk jalankan arahan berbahaya dalam server anda.",
    "CWE-502": "Data yang tidak dipercayai boleh digunakan untuk jalankan kod berbahaya semasa proses deserialization.",
    "CWE-306": "Bahagian sensitif sistem anda boleh diakses tanpa log masuk.",
    "CWE-200": "Maklumat sensitif seperti kata laluan atau token terdedah dalam log atau response.",
    "CWE-311": "Data peribadi pengguna disimpan atau dihantar tanpa enkripsi — melanggar undang-undang JPDP Malaysia.",
    "CWE-20": "Input ke model AI tidak disemak, membolehkan serangan prompt injection.",
}


def aggregate_results(file_results: list[dict], scan_type: str, target: str, duration: float) -> dict:
    """Gabung semua file scan results ke satu project-level report."""
    issues_by_file = {}
    severity_count = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    all_compliance_flags = []

    for fr in file_results:
        filename = fr["filename"]
        file_issues = []

        # CVE/CWE results
        cve_result = fr.get("cve_result")
        if cve_result:
            for v in cve_result.vulnerabilities:
                sev = v.severity.lower()
                if sev in severity_count:
                    severity_count[sev] += 1

                issue = {
                    "line": v.line_hint,
                    "severity": v.severity,
                    "type": v.cwe_id,
                    "cwe": v.cwe_id,
                    "title": v.title,
                    "description": v.description,
                    "owasp_ref": v.owasp_ref,
                    "recommendation": f"Semak dokumentasi {v.cwe_id} untuk panduan pembetulan.",
                }
                if sev in ("critical", "high"):
                    issue["simple_explanation"] = SIMPLE_EXPLANATIONS.get(v.cwe_id, "Kelemahan keselamatan kritikal ditemui. Sila betulkan sebelum deploy.")
                file_issues.append(issue)

            for flag in cve_result.compliance_flags:
                all_compliance_flags.append(flag)

        # Secret findings
        for secret in fr.get("secrets", []):
            severity_count["critical"] += 1
            file_issues.append({
                "line": secret.get("line_hint", ""),
                "severity": "CRITICAL",
                "type": secret["type"],
                "description": secret["description"],
                "recommendation": secret["recommendation"],
                "simple_explanation": secret.get("simple_explanation", ""),
            })

        # Dependency issues
        for dep in fr.get("dep_issues", []):
            sev = dep.get("severity", "low").lower()
            if sev in severity_count:
                severity_count[sev] += 1
            file_issues.append({
                "line": dep.get("filename", ""),
                "severity": dep.get("severity", "LOW"),
                "type": dep["type"],
                "description": dep["description"],
                "recommendation": dep["recommendation"],
                "simple_explanation": dep.get("simple_explanation", ""),
            })

        if file_issues:
            issues_by_file[filename] = file_issues

    total_issues = sum(severity_count.values())
    total_files = sum(1 for fr in file_results if fr["filename"] != "__dependencies__")

    # Compliance score berdasarkan severity
    penalty = severity_count["critical"] * 15 + severity_count["high"] * 8 + severity_count["medium"] * 3 + severity_count["low"] * 1
    overall = max(0.0, round(100.0 - penalty, 1))
    grade = _grade(overall)

    return {
        "scan_type": scan_type,
        "target": target,
        "total_files_scanned": total_files,
        "total_issues": total_issues,
        "severity_breakdown": severity_count,
        "issues_by_file": issues_by_file,
        "compliance_score": {
            "overall": overall,
            "grade": grade,
            "breakdown": {
                "critical_issues": severity_count["critical"],
                "high_issues": severity_count["high"],
                "compliance_flags": len(all_compliance_flags),
            },
        },
        "compliance_flags": all_compliance_flags,
        "scan_duration_seconds": duration,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def _grade(score: float) -> str:
    if score >= 90: return "A"
    if score >= 75: return "B"
    if score >= 60: return "C"
    if score >= 40: return "D"
    return "F"

"""
Compliance Scorer
Mengira skor pematuhan berdasarkan OWASP Top 10, NACSA, JPDP, MCMC, AIGE
"""

from dataclasses import dataclass, field
from engine.cve_scanner import ScanResult


@dataclass
class ComplianceScore:
    overall: float              # 0 - 100
    grade: str                  # A, B, C, D, F
    owasp_score: float
    nacsa_score: float
    jpdp_score: float
    mcmc_score: float
    aige_score: float
    breakdown: dict = field(default_factory=dict)
    recommendations: list = field(default_factory=list)


def calculate(scan_result: ScanResult) -> ComplianceScore:
    """
    Kira skor compliance berdasarkan hasil CVE/CWE scan.
    Setiap isu menolak mata dari skor penuh (100).
    """
    deductions = {
        "owasp": 0.0,
        "nacsa": 0.0,
        "jpdp": 0.0,
        "mcmc": 0.0,
        "aige": 0.0,
    }

    recommendations = []

    # Tolak mata berdasarkan severity
    severity_penalty = {
        "CRITICAL": 20.0,
        "HIGH": 10.0,
        "MEDIUM": 5.0,
        "LOW": 2.0,
    }

    for vuln in scan_result.vulnerabilities:
        penalty = severity_penalty.get(vuln.severity, 2.0)

        # Map CWE ke framework
        if vuln.owasp_ref:
            deductions["owasp"] = min(100, deductions["owasp"] + penalty)
        if vuln.cwe_id in ("CWE-20", "CWE-798"):
            deductions["nacsa"] = min(100, deductions["nacsa"] + penalty)
        if vuln.cwe_id in ("CWE-311", "CWE-200"):
            deductions["jpdp"] = min(100, deductions["jpdp"] + penalty)

        recommendations.append(
            f"[{vuln.severity}] {vuln.cwe_id} — {vuln.title}: {vuln.description}"
        )

    # Compliance flags
    for flag in scan_result.compliance_flags:
        ref = flag["ref"]
        if ref.startswith("JPDP"):
            deductions["jpdp"] = min(100, deductions["jpdp"] + 15)
        elif ref.startswith("NACSA"):
            deductions["nacsa"] = min(100, deductions["nacsa"] + 15)
        elif ref.startswith("MCMC"):
            deductions["mcmc"] = min(100, deductions["mcmc"] + 10)
        elif ref.startswith("AIGE"):
            deductions["aige"] = min(100, deductions["aige"] + 10)
        recommendations.append(f"[{ref}] {flag['title']}: {flag['recommendation']}")

    # Kira skor individu
    owasp_score = max(0.0, 100 - deductions["owasp"])
    nacsa_score = max(0.0, 100 - deductions["nacsa"])
    jpdp_score = max(0.0, 100 - deductions["jpdp"])
    mcmc_score = max(0.0, 100 - deductions["mcmc"])
    aige_score = max(0.0, 100 - deductions["aige"])

    # Wajaran: OWASP 35%, NACSA 25%, JPDP 20%, MCMC 10%, AIGE 10%
    overall = (
        owasp_score * 0.35 +
        nacsa_score * 0.25 +
        jpdp_score * 0.20 +
        mcmc_score * 0.10 +
        aige_score * 0.10
    )

    # Gred
    if overall >= 90:
        grade = "A"
    elif overall >= 75:
        grade = "B"
    elif overall >= 60:
        grade = "C"
    elif overall >= 40:
        grade = "D"
    else:
        grade = "F"

    return ComplianceScore(
        overall=round(overall, 2),
        grade=grade,
        owasp_score=round(owasp_score, 2),
        nacsa_score=round(nacsa_score, 2),
        jpdp_score=round(jpdp_score, 2),
        mcmc_score=round(mcmc_score, 2),
        aige_score=round(aige_score, 2),
        breakdown={
            "OWASP Top 10": owasp_score,
            "NACSA AI Security": nacsa_score,
            "JPDP / PDPA 2010": jpdp_score,
            "MCMC CMA 1998": mcmc_score,
            "AIGE Etika AI": aige_score,
        },
        recommendations=recommendations[:20],  # hadkan 20 teratas
    )

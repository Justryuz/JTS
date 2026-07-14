"""
Dependency & Supply Chain Scanner
Semak package.json dan requirements.txt untuk isu versi
"""

import json
import re


def scan_dependencies(files: dict[str, str]) -> list[dict]:
    """Scan package.json dan requirements.txt untuk isu dependency."""
    issues = []

    for filename, content in files.items():
        if filename.endswith("package.json"):
            issues.extend(_scan_package_json(content, filename))
        elif filename.endswith("requirements.txt"):
            issues.extend(_scan_requirements_txt(content, filename))

    return issues


def _scan_package_json(content: str, filename: str) -> list[dict]:
    issues = []
    try:
        data = json.loads(content)
        for section in ("dependencies", "devDependencies"):
            for pkg, version in data.get(section, {}).items():
                if version in ("*", "latest", ""):
                    issues.append({
                        "type": "UNPINNED_DEPENDENCY",
                        "severity": "LOW",
                        "filename": filename,
                        "description": f"Package `{pkg}` dalam {section} tiada versi tetap (`{version}`). Boleh menyebabkan breaking changes atau supply chain attack.",
                        "recommendation": f"Tetapkan versi spesifik, contoh: `\"{pkg}\": \"^1.2.3\"`",
                        "simple_explanation": f"Package `{pkg}` tidak ditetapkan versinya. Ini bermakna versi terbaru (yang mungkin ada bug atau kod jahat) akan dipasang secara automatik.",
                    })
    except (json.JSONDecodeError, Exception):
        pass
    return issues


def _scan_requirements_txt(content: str, filename: str) -> list[dict]:
    issues = []
    for i, line in enumerate(content.splitlines(), start=1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Tiada version pin (tiada ==, >=, ~=, !=)
        if re.match(r"^[A-Za-z0-9_\-\[\]]+$", line):
            issues.append({
                "type": "UNPINNED_DEPENDENCY",
                "severity": "LOW",
                "filename": f"{filename}:{i}",
                "description": f"Package `{line}` tiada versi ditetapkan dalam requirements.txt.",
                "recommendation": f"Tetapkan versi spesifik, contoh: `{line}==1.2.3`",
                "simple_explanation": f"Package `{line}` tidak ditetapkan versinya dan versi terbaru akan dipasang secara automatik.",
            })
    return issues

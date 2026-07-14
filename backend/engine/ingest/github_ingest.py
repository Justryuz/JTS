"""
GitHub Repo Ingestion — Clone & scan keseluruhan repo
"""

import logging
import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from engine import cve_scanner
from engine.secret_scanner import scan_secrets
from engine.dependency_scanner import scan_dependencies
from engine.aggregator import aggregate_results

logger = logging.getLogger(__name__)

ALLOWED_EXTENSIONS = {".py", ".js", ".ts", ".jsx", ".tsx", ".php", ".java", ".rb", ".go"}
SKIP_DIRS = {"node_modules", ".git", "venv", "dist", "build", "__pycache__", ".next", "vendor"}
MAX_REPO_SIZE_MB = 200
MAX_FILES = 500
SCAN_TIMEOUT = 60

ALLOWED_HOSTS = {"github.com", "gitlab.com", "bitbucket.org"}


def _validate_repo_url(repo_url: str) -> None:
    """Validate repo_url untuk elak git argument injection & SSRF ke host luar allowlist."""
    if repo_url.startswith("-"):
        raise ValueError("URL tidak sah")
    if not re.match(r"^https://([\w.-]+)/[\w.-]+/[\w.-]+(\.git)?/?$", repo_url):
        raise ValueError("Format repo URL tidak sah. Guna format: https://github.com/user/repo")
    host = repo_url.split("/")[2]
    if host not in ALLOWED_HOSTS:
        raise ValueError(f"Host '{host}' tidak dibenarkan")


def _validate_branch(branch: str) -> None:
    """Validate nama branch — elak argument injection melalui --branch flag."""
    if not branch or branch.startswith("-"):
        raise ValueError("Nama branch tidak sah")
    if not re.match(r"^[\w./-]{1,100}$", branch):
        raise ValueError("Nama branch tidak sah")


def scan_github_repo(repo_url: str, branch: str = "main") -> dict:
    """Clone repo GitHub dan scan semua fail kod untuk CVE/CWE, secrets, dan dependencies."""
    try:
        _validate_repo_url(repo_url)
        _validate_branch(branch)
    except ValueError as e:
        return {"error": str(e)}

    tmp_dir = tempfile.mkdtemp(prefix="TrustGuard_")
    start = time.time()

    try:
        # Clone repo — "--" memastikan git treat repo_url sebagai positional arg,
        # bukan flag, walaupun validation di atas dah block kebanyakan kes
        try:
            subprocess.run(
                ["git", "clone", "--depth=1", "--branch", branch, "--", repo_url, tmp_dir],
                timeout=SCAN_TIMEOUT,
                capture_output=True,
                check=True,
            )
        except subprocess.CalledProcessError:
            # Retry dengan branch default
            shutil.rmtree(tmp_dir, ignore_errors=True)
            tmp_dir = tempfile.mkdtemp(prefix="TrustGuard_")
            subprocess.run(
                ["git", "clone", "--depth=1", "--", repo_url, tmp_dir],
                timeout=SCAN_TIMEOUT,
                capture_output=True,
                check=True,
            )

        # Semak saiz repo
        total_size_mb = sum(
            f.stat().st_size for f in Path(tmp_dir).rglob("*") if f.is_file()
        ) / (1024 * 1024)
        if total_size_mb > MAX_REPO_SIZE_MB:
            return {"error": f"Repo terlalu besar ({total_size_mb:.0f}MB). Had: {MAX_REPO_SIZE_MB}MB."}

        # Kumpul fail
        files = _collect_files(tmp_dir)
        if len(files) > MAX_FILES:
            return {"error": f"Repo mempunyai terlalu banyak fail ({len(files)}). Had: {MAX_FILES} fail."}

        file_contents = {rel: Path(tmp_dir, rel).read_text(errors="ignore") for rel in files}
        file_results = _scan_files(file_contents)

        return aggregate_results(
            file_results=file_results,
            scan_type="github_repo",
            target=repo_url,
            duration=round(time.time() - start, 2),
        )

    except subprocess.TimeoutExpired:
        return {"error": "Scan tamat masa (timeout 60s). Cuba repo yang lebih kecil."}
    except subprocess.CalledProcessError as e:
        logger.error(f"Git clone failed: {e.stderr}")
        return {"error": "Gagal clone repo. Pastikan URL betul dan repo adalah public."}
    except Exception as e:
        logger.error(f"github_ingest error: {e}")
        return {"error": "Ralat semasa scan. Sila cuba lagi."}
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def _collect_files(base_dir: str) -> list[str]:
    """Kumpul semua fail dengan extension yang dibenarkan, skip folder tertentu."""
    result = []
    base = Path(base_dir)
    for f in base.rglob("*"):
        if not f.is_file():
            continue
        if any(skip in f.parts for skip in SKIP_DIRS):
            continue
        if f.suffix.lower() in ALLOWED_EXTENSIONS or f.name in ("package.json", "requirements.txt"):
            result.append(str(f.relative_to(base)))
    return result


def _scan_files(file_contents: dict[str, str]) -> list[dict]:
    """Scan setiap fail dan kumpul semua result."""
    results = []
    for filename, content in file_contents.items():
        scan = cve_scanner.scan_code(content, filename)
        secrets = scan_secrets(content, filename)
        results.append({
            "filename": filename,
            "cve_result": scan,
            "secrets": secrets,
        })
    dep_issues = scan_dependencies(file_contents)
    if dep_issues:
        results.append({"filename": "__dependencies__", "cve_result": None, "secrets": [], "dep_issues": dep_issues})
    return results
"""
ZIP Upload Ingestion — Extract & scan fail dari ZIP yang diupload
"""

import io
import logging
import shutil
import tempfile
import time
import zipfile
from pathlib import Path

from engine import cve_scanner
from engine.secret_scanner import scan_secrets
from engine.dependency_scanner import scan_dependencies
from engine.aggregator import aggregate_results

logger = logging.getLogger(__name__)

ALLOWED_EXTENSIONS = {".py", ".js", ".ts", ".jsx", ".tsx", ".php", ".java", ".rb", ".go"}
SKIP_DIRS = {"node_modules", ".git", "venv", "dist", "build", "__pycache__", ".next", "vendor"}
MAX_EXTRACTED_MB = 200
MAX_FILES = 500
SCAN_TIMEOUT = 60


def scan_zip_upload(file_bytes: bytes) -> dict:
    """Extract ZIP dan scan semua fail kod untuk CVE/CWE, secrets, dan dependencies."""
    tmp_dir = tempfile.mkdtemp(prefix="TrustGuard_zip_")
    start = time.time()

    try:
        # Validate ZIP
        if not zipfile.is_zipfile(io.BytesIO(file_bytes)):
            return {"error": "Fail bukan format ZIP yang sah."}

        with zipfile.ZipFile(io.BytesIO(file_bytes)) as zf:
            # Zip bomb check
            total_size = sum(i.file_size for i in zf.infolist())
            if total_size > MAX_EXTRACTED_MB * 1024 * 1024:
                return {"error": f"ZIP terlalu besar selepas extract ({total_size // (1024*1024)}MB). Had: {MAX_EXTRACTED_MB}MB."}

            # Path traversal check dalam ZIP
            for member in zf.namelist():
                if ".." in member or member.startswith("/"):
                    return {"error": "ZIP mengandungi laluan berbahaya (path traversal)."}

            zf.extractall(tmp_dir)

        # Kumpul fail
        base = Path(tmp_dir)
        files = []
        for f in base.rglob("*"):
            if not f.is_file():
                continue
            if any(skip in f.parts for skip in SKIP_DIRS):
                continue
            if f.suffix.lower() in ALLOWED_EXTENSIONS or f.name in ("package.json", "requirements.txt"):
                files.append(str(f.relative_to(base)))

        if len(files) > MAX_FILES:
            return {"error": f"ZIP mengandungi terlalu banyak fail ({len(files)}). Had: {MAX_FILES}."}

        file_contents = {rel: Path(tmp_dir, rel).read_text(errors="ignore") for rel in files}

        # Scan
        results = []
        for filename, content in file_contents.items():
            scan = cve_scanner.scan_code(content, filename)
            secrets = scan_secrets(content, filename)
            results.append({"filename": filename, "cve_result": scan, "secrets": secrets})

        dep_issues = scan_dependencies(file_contents)
        if dep_issues:
            results.append({"filename": "__dependencies__", "cve_result": None, "secrets": [], "dep_issues": dep_issues})

        return aggregate_results(
            file_results=results,
            scan_type="zip_upload",
            target=f"upload.zip ({len(file_contents)} files)",
            duration=round(time.time() - start, 2),
        )

    except zipfile.BadZipFile:
        return {"error": "Fail ZIP rosak atau tidak sah."}
    except Exception as e:
        logger.error(f"zip_ingest error: {e}")
        return {"error": "Ralat semasa scan ZIP. Sila cuba lagi."}
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

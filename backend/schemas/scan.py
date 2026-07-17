"""
TrustGuard v2.0 — Scan Schemas
Input validation for code, repo, URL, and ZIP scans.
Standards: Part 3 §28
"""

from __future__ import annotations

import re

from pydantic import BaseModel, Field, field_validator

from config.constants import EngineMode, ALLOWED_REPO_HOSTS


class CodeScanRequest(BaseModel):
    code: str = Field(min_length=1, max_length=500_000)
    filename: str = Field(default="unknown", max_length=255)
    engine_mode: EngineMode = EngineMode.HYBRID

    @field_validator("filename")
    @classmethod
    def validate_filename(cls, v: str) -> str:
        if not re.match(r"^[\w\-. ]+\.[a-zA-Z]{1,10}$", v) and v != "unknown":
            raise ValueError("Format filename tidak sah")
        return v


class RepoScanRequest(BaseModel):
    repo_url: str = Field(max_length=500)
    branch: str = Field(default="main", max_length=100)

    @field_validator("repo_url")
    @classmethod
    def validate_repo_url(cls, v: str) -> str:
        if not re.match(r"^https://[\w.-]+/[\w.\-]+/[\w.\-]+(\.git)?/?$", v):
            raise ValueError("Format repo URL tidak sah")
        host = v.split("/")[2]
        if host not in ALLOWED_REPO_HOSTS:
            raise ValueError(f"Host '{host}' tidak dibenarkan")
        return v

    @field_validator("branch")
    @classmethod
    def validate_branch(cls, v: str) -> str:
        if not re.match(r"^[\w./-]{1,100}$", v):
            raise ValueError("Nama branch tidak sah")
        return v


class UrlScanRequest(BaseModel):
    url: str = Field(max_length=2048)

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        v = v.strip()
        if not v.startswith(("http://", "https://")):
            v = "https://" + v
        return v


class ScanJobResponse(BaseModel):
    job_id: str
    status: str
    message: str


class GenerateKeyRequest(BaseModel):
    allowed_domain: str = Field(max_length=253)

    @field_validator("allowed_domain")
    @classmethod
    def validate_domain(cls, v: str) -> str:
        v = v.lower().strip()
        if not re.match(r"^[a-z0-9][a-z0-9\-\.]{0,251}[a-z0-9]$", v):
            raise ValueError("Format domain tidak sah")
        return v


class VerifyDomainRequest(BaseModel):
    method: str = "http_file"
    target_url: str | None = Field(default=None, max_length=2048)
    repo_url: str | None = Field(default=None, max_length=500)
    branch: str = Field(default="main", max_length=100)


class WebshellScanRequest(BaseModel):
    code: str = Field(min_length=1, max_length=500_000)
    filename: str = Field(default="unknown", max_length=255)

    @field_validator("filename")
    @classmethod
    def validate_filename(cls, v: str) -> str:
        if not re.match(r"^[\w\-. ]+\.[a-zA-Z]{1,10}$", v) and v != "unknown":
            raise ValueError("Invalid filename format")
        return v


class SeoScanRequest(BaseModel):
    url: str | None = Field(default=None, max_length=2048)
    max_pages: int = Field(default=20, ge=1, le=100)

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str | None) -> str | None:
        if v is None:
            return v
        v = v.strip()
        if not v.startswith(("http://", "https://")):
            v = "https://" + v
        return v

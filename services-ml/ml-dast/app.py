"""CloudSentinel ml-dast: ML dynamic analysis service for Python and Node.js web apps.

Until a trained model file exists at MODEL_PATH the service is "untrained": /scan returns an
empty findings list and /model-info reports status "untrained". It never fabricates findings
and, while untrained, sends no traffic to the target.

A trained model is a joblib artifact exposing
``scan(base_url, max_pages, max_requests) -> list[dict]``. The CloudSentinel backend only calls
/scan with a target it has authorized (the verified staging deployment or an owner target).
Optional metadata (name, version, trained_on, metrics) is read from MODEL_META_PATH.
"""
import hashlib
import json
import os
from pathlib import Path
from typing import List, Literal, Optional
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field, ValidationError, field_validator

SERVICE = "ml-dast"
MODEL_PATH = Path(os.environ.get("MODEL_PATH", "/models/ml-dast/model.joblib"))
MODEL_META_PATH = Path(os.environ.get("MODEL_META_PATH", str(MODEL_PATH.with_suffix(".json"))))

Severity = Literal["HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]


class ScanRequest(BaseModel):
    baseUrl: str = Field(min_length=1, max_length=2000)
    maxPages: int = Field(default=50, ge=1, le=500)
    maxRequests: int = Field(default=500, ge=1, le=5000)

    @field_validator("baseUrl")
    @classmethod
    def http_only(cls, value: str) -> str:
        parsed = urlparse(value)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ValueError("baseUrl must be an http(s) URL")
        return value


class Finding(BaseModel):
    alert: str = Field(min_length=1, max_length=500)
    attack_type: str = Field(min_length=1, max_length=500)
    severity: Severity
    endpoint: str = Field(max_length=500)
    method: str = Field(min_length=1, max_length=10)
    param: str = Field(default="", max_length=200)
    request_payload: str = Field(default="", max_length=1000)
    response_details: str = Field(default="", max_length=1000)
    cwe_id: Optional[int] = Field(default=None, ge=1)
    solution: str = Field(default="", max_length=1000)
    confidence: float = Field(ge=0.0, le=1.0)


class ScanResponse(BaseModel):
    findings: List[Finding]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_model():
    """Return (detector, info). detector is None while untrained."""
    if not MODEL_PATH.is_file():
        return None, {"name": SERVICE, "version": "untrained", "sha256": None,
                      "trained_on": None, "metrics": {}, "status": "untrained"}
    meta = {}
    if MODEL_META_PATH.is_file():
        meta = json.loads(MODEL_META_PATH.read_text(encoding="utf-8"))
    import joblib  # only needed once a model exists

    detector = joblib.load(MODEL_PATH)
    if not callable(getattr(detector, "scan", None)):
        raise RuntimeError(f"{MODEL_PATH} does not expose scan(base_url, max_pages, max_requests)")
    return detector, {
        "name": str(meta.get("name", SERVICE)),
        "version": str(meta.get("version", "0")),
        "sha256": sha256_file(MODEL_PATH),
        "trained_on": meta.get("trained_on"),
        "metrics": meta.get("metrics", {}),
        "status": "trained",
    }


app = FastAPI(title="CloudSentinel ml-dast", version="0.1.0")
DETECTOR, MODEL_INFO = load_model()


@app.get("/health")
def health():
    return {"status": "ok", "service": SERVICE, "model": MODEL_INFO["status"]}


@app.get("/model-info")
def model_info():
    return MODEL_INFO


@app.post("/scan", response_model=ScanResponse)
def scan(request: ScanRequest):
    if DETECTOR is None:
        return {"findings": []}
    try:
        raw = DETECTOR.scan(request.baseUrl, request.maxPages, request.maxRequests)
    except Exception as exc:  # model failure must surface, never look like a clean scan
        raise HTTPException(status_code=500, detail=f"model scan failed: {type(exc).__name__}") from exc
    try:
        findings = [Finding.model_validate(item) for item in raw]
    except ValidationError as exc:
        raise HTTPException(status_code=500, detail=f"model returned an invalid finding: {exc.error_count()} error(s)") from exc
    return {"findings": findings}

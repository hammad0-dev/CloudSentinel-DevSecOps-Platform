"""CloudSentinel ml-dast: ML dynamic analysis service for Python and Node.js web apps.

/scan crawls the target (same origin), sends a fixed payload list for SQL injection (CWE-89) and
reflected XSS (CWE-79) to every discovered parameter, featurizes each request/response pair and
reports one finding per (endpoint, parameter, class) whose model probability reaches the threshold.

Safety: every request goes through dastml.guards.GuardedClient. Targets outside the allowlist
(ML_DAST_ALLOWED_HOSTS, default 127.0.0.1,localhost; ML_DAST_ALLOWED_PORTS, default 5101-5108) are
refused with HTTP 400 before any traffic is sent; requests are same-origin only, bounded by
maxPages / maxRequests, rate-limited (ML_DAST_RATE_PER_SEC, default 20) and never follow off-origin
redirects. The backend must also authorize the target (verified staging deployment).

Until a trained model file exists at MODEL_PATH the service is "untrained": /scan returns an empty
findings list without sending any traffic, and /model-info reports status "untrained". It never
fabricates findings.

A trained model is a joblib artifact exposing ``scan(base_url, max_pages, max_requests[, threshold=])``
(dastml.detector.DastDetector). Metadata (name, version, trained_on, metrics, threshold,
limitations, components) is read from MODEL_META_PATH. ML_DAST_CONFIDENCE_THRESHOLD overrides the
model's threshold.
"""
import hashlib
import inspect
import json
import os
from pathlib import Path
from typing import List, Literal, Optional
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field, ValidationError, field_validator

from dastml.guards import GuardError, TargetPolicy

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


def env_threshold():
    raw = os.environ.get("ML_DAST_CONFIDENCE_THRESHOLD")
    if not raw:
        return None
    value = float(raw)
    if not 0.0 <= value <= 1.0:
        raise RuntimeError("ML_DAST_CONFIDENCE_THRESHOLD must be between 0 and 1")
    return value


def load_model():
    """Return (detector, info). detector is None while untrained."""
    if not MODEL_PATH.is_file():
        return None, {"name": SERVICE, "version": "untrained", "sha256": None,
                      "trained_on": None, "metrics": {}, "status": "untrained", "threshold": None}
    meta = {}
    if MODEL_META_PATH.is_file():
        meta = json.loads(MODEL_META_PATH.read_text(encoding="utf-8"))
    import joblib  # only needed once a model exists

    detector = joblib.load(MODEL_PATH)
    if not callable(getattr(detector, "scan", None)):
        raise RuntimeError(f"{MODEL_PATH} does not expose scan(base_url, max_pages, max_requests)")
    override = env_threshold()
    default = meta.get("threshold", getattr(detector, "threshold", None))
    info = {
        "name": str(meta.get("name", SERVICE)),
        "version": str(meta.get("version", "0")),
        "sha256": sha256_file(MODEL_PATH),
        "trained_on": meta.get("trained_on"),
        "metrics": meta.get("metrics", {}),
        "status": "trained",
        "threshold": override if override is not None else default,
        "classes": meta.get("classes"),
        "limitations": meta.get("limitations", []),
    }
    if meta.get("components"):
        info["components"] = meta["components"]
    return detector, info


app = FastAPI(title="CloudSentinel ml-dast", version="0.2.0")
DETECTOR, MODEL_INFO = load_model()


@app.get("/health")
def health():
    return {"status": "ok", "service": SERVICE, "model": MODEL_INFO["status"]}


@app.get("/model-info")
def model_info():
    return MODEL_INFO


def run_detector(request):
    kwargs = {}
    params = inspect.signature(DETECTOR.scan).parameters
    if "threshold" in params and MODEL_INFO.get("threshold") is not None:
        kwargs["threshold"] = MODEL_INFO["threshold"]
    if "policy" in params:
        kwargs["policy"] = TargetPolicy.from_env()
    return DETECTOR.scan(request.baseUrl, request.maxPages, request.maxRequests, **kwargs)


@app.post("/scan", response_model=ScanResponse)
def scan(request: ScanRequest):
    if DETECTOR is None:
        return {"findings": []}
    try:
        TargetPolicy.from_env().origin_of(request.baseUrl)  # refuse before any traffic
    except GuardError as exc:
        raise HTTPException(status_code=400, detail=f"target refused: {exc}") from exc
    try:
        raw = run_detector(request)
    except GuardError as exc:
        raise HTTPException(status_code=400, detail=f"target refused: {exc}") from exc
    except Exception as exc:  # model failure must surface, never look like a clean scan
        raise HTTPException(status_code=500, detail=f"model scan failed: {type(exc).__name__}") from exc
    try:
        findings = [Finding.model_validate(item) for item in raw]
    except ValidationError as exc:
        raise HTTPException(status_code=500, detail=f"model returned an invalid finding: {exc.error_count()} error(s)") from exc
    return {"findings": findings}

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

Optional ``seedPaths`` (extra pages to crawl, e.g. ``/search?q=x``) and ``openapiUrl`` (a same-origin
OpenAPI/Swagger JSON document) widen the crawl; each must resolve to the target's origin or the scan
is refused with HTTP 400 before any traffic.

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
from typing import Any, Dict, List, Literal, Optional
from urllib.parse import urljoin, urlparse

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field, ValidationError, field_validator

from dastml.guards import GuardError, TargetPolicy
from dastml.openapi import OpenAPIError

SERVICE = "ml-dast"
MODEL_PATH = Path(os.environ.get("MODEL_PATH", "/models/ml-dast/model.joblib"))
MODEL_META_PATH = Path(os.environ.get("MODEL_META_PATH", str(MODEL_PATH.with_suffix(".json"))))

Severity = Literal["HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]


class ScanRequest(BaseModel):
    baseUrl: str = Field(min_length=1, max_length=2000)
    maxPages: int = Field(default=50, ge=1, le=500)
    maxRequests: int = Field(default=500, ge=1, le=5000)
    # Optional crawl seeds for endpoints not linked from HTML. Paths (or same-origin URLs) are
    # resolved against baseUrl; anything that resolves to another origin refuses the scan.
    seedPaths: List[str] = Field(default_factory=list, max_length=50)
    openapiUrl: Optional[str] = Field(default=None, min_length=1, max_length=2000)

    @field_validator("seedPaths")
    @classmethod
    def seed_lengths(cls, value):
        if any(not s or len(s) > 500 for s in value):
            raise ValueError("each seed path must be 1-500 characters")
        return value

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
    # crawl coverage of this scan (pages, points_found, points_probed, requests, stopped), when the
    # model reports it: zero points found means the scan tested nothing, not that the app is clean.
    coverage: Optional[Dict[str, Any]] = None


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
    for field, name in (("seedPaths", "seed_paths"), ("openapiUrl", "openapi_url")):
        value = getattr(request, field)
        if not value:
            continue
        if name not in params:  # never drop requested coverage silently
            raise HTTPException(status_code=501, detail=f"the loaded model does not support {field}")
        kwargs[name] = value
    return DETECTOR.scan(request.baseUrl, request.maxPages, request.maxRequests, **kwargs)


def check_seeds(request, policy):
    """Every seed must resolve to the scan target's own origin (same allowlist, same origin)."""
    origin = policy.origin_of(request.baseUrl)
    for seed in list(request.seedPaths) + ([request.openapiUrl] if request.openapiUrl else []):
        if policy.origin_of(urljoin(request.baseUrl, seed)) != origin:
            raise GuardError(f"seed {seed!r} is not same-origin with {request.baseUrl}")


@app.post("/scan", response_model=ScanResponse)
def scan(request: ScanRequest):
    if DETECTOR is None:
        return {"findings": []}
    try:
        check_seeds(request, TargetPolicy.from_env())  # refuse before any traffic
    except GuardError as exc:
        raise HTTPException(status_code=400, detail=f"target refused: {exc}") from exc
    try:
        raw = run_detector(request)
    except HTTPException:
        raise
    except GuardError as exc:
        raise HTTPException(status_code=400, detail=f"target refused: {exc}") from exc
    except OpenAPIError as exc:
        raise HTTPException(status_code=400, detail=f"openapiUrl could not be used: {exc}") from exc
    except Exception as exc:  # model failure must surface, never look like a clean scan
        raise HTTPException(status_code=500, detail=f"model scan failed: {type(exc).__name__}") from exc
    try:
        findings = [Finding.model_validate(item) for item in raw]
    except ValidationError as exc:
        raise HTTPException(status_code=500, detail=f"model returned an invalid finding: {exc.error_count()} error(s)") from exc
    coverage = getattr(DETECTOR, "last_scan", None)
    return {"findings": findings, "coverage": dict(coverage) if isinstance(coverage, dict) and coverage else None}

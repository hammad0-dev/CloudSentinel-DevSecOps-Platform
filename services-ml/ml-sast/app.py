"""CloudSentinel ml-sast: ML static analysis service for Python and Node.js sources.

Until a trained model file exists at MODEL_PATH the service is "untrained": /scan returns an
empty findings list and /model-info reports status "untrained". It never fabricates findings.

A trained model is a joblib artifact exposing ``scan(files) -> list[dict]`` where ``files`` is a
list of ``{"path": str, "content": str}``. Optional metadata (name, version, trained_on, metrics)
is read from MODEL_META_PATH (default: MODEL_PATH with a .json suffix).
"""
import hashlib
import json
import os
from pathlib import Path
from typing import List, Literal, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field, ValidationError

SERVICE = "ml-sast"
MODEL_PATH = Path(os.environ.get("MODEL_PATH", "/models/ml-sast/model.joblib"))
MODEL_META_PATH = Path(os.environ.get("MODEL_META_PATH", str(MODEL_PATH.with_suffix(".json"))))
MAX_FILES = int(os.environ.get("ML_SAST_MAX_FILES", "5000"))
MAX_FILE_CHARS = int(os.environ.get("ML_SAST_MAX_FILE_CHARS", str(1024 * 1024)))
SUPPORTED_SUFFIXES = (".py", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx")

Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


class SourceFile(BaseModel):
    path: str = Field(min_length=1, max_length=2000)
    content: str = Field(max_length=MAX_FILE_CHARS)


class ScanRequest(BaseModel):
    files: List[SourceFile] = Field(max_length=MAX_FILES)


class Finding(BaseModel):
    rule: str = Field(min_length=1, max_length=200)
    cwe_id: Optional[int] = Field(default=None, ge=1)
    severity: Severity
    message: str = Field(min_length=1, max_length=8000)
    file_path: str = Field(min_length=1, max_length=2000)
    line_number: Optional[int] = Field(default=None, ge=1)
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
        raise RuntimeError(f"{MODEL_PATH} does not expose scan(files)")
    return detector, {
        "name": str(meta.get("name", SERVICE)),
        "version": str(meta.get("version", "0")),
        "sha256": sha256_file(MODEL_PATH),
        "trained_on": meta.get("trained_on"),
        "metrics": meta.get("metrics", {}),
        "status": "trained",
    }


app = FastAPI(title="CloudSentinel ml-sast", version="0.1.0")
DETECTOR, MODEL_INFO = load_model()


@app.get("/health")
def health():
    return {"status": "ok", "service": SERVICE, "model": MODEL_INFO["status"]}


@app.get("/model-info")
def model_info():
    return MODEL_INFO


@app.post("/scan", response_model=ScanResponse)
def scan(request: ScanRequest):
    files = [f for f in request.files if f.path.lower().endswith(SUPPORTED_SUFFIXES)]
    if DETECTOR is None or not files:
        return {"findings": []}
    try:
        raw = DETECTOR.scan([f.model_dump() for f in files])
    except Exception as exc:  # model failure must surface, never look like a clean scan
        raise HTTPException(status_code=500, detail=f"model scan failed: {type(exc).__name__}") from exc
    submitted = {f.path for f in files}
    try:
        findings = [Finding.model_validate(item) for item in raw]
    except ValidationError as exc:
        raise HTTPException(status_code=500, detail=f"model returned an invalid finding: {exc.error_count()} error(s)") from exc
    unknown = sorted({f.file_path for f in findings} - submitted)
    if unknown:
        raise HTTPException(status_code=500, detail=f"model reported unknown file(s): {unknown[:3]}")
    return {"findings": findings}

"""CloudSentinel ml-sast: ML static analysis service for Python and Node.js sources.

/scan splits every submitted Python/JavaScript file into function-level units (``sastml.extract``),
classifies each unit into one of 8 classes (safe + 7 CWEs) and returns one finding per unit whose
most likely vulnerable class reaches the confidence threshold. ``line_number`` is the unit's start line.

Model artifact (MODEL_PATH):
* a joblib file holding an object with ``predict_proba(codes, langs)`` and ``info`` (``sastml.model.SastModel``,
  ``sastml.codebert.CodeBertXGB``), or
* a Hugging Face folder with ``config.json`` (fine-tuned CodeBERT, ``sastml.codebert.CodeBertClassifier``).
Metadata for /model-info (name, version, trained_on, metrics, threshold) is read from MODEL_META_PATH
(default: ``<MODEL_PATH>.json``, or ``cloudsentinel.json`` inside a model folder). The SHA-256 is computed
over the model file (for a folder: its weights file) at startup.

Without a model file the service is "untrained": /scan returns no findings and /model-info says so.
It never fabricates findings.

Env: MODEL_PATH, MODEL_META_PATH, ML_SAST_CONFIDENCE_THRESHOLD (overrides the model's default threshold),
ML_SAST_MAX_FILES, ML_SAST_MAX_FILE_CHARS.
"""
import hashlib
import json
import os
from pathlib import Path
from typing import List, Literal, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from sastml import CLASSES
from sastml.extract import extract, language_of
from sastml.features import explain

SERVICE = "ml-sast"
MODEL_PATH = Path(os.environ.get("MODEL_PATH", "/models/ml-sast/model.joblib"))
MAX_FILES = int(os.environ.get("ML_SAST_MAX_FILES", "5000"))
MAX_FILE_CHARS = int(os.environ.get("ML_SAST_MAX_FILE_CHARS", str(1024 * 1024)))
SUPPORTED_SUFFIXES = (".py", ".js", ".mjs", ".cjs", ".jsx")

RULES = {
    "CWE-89": ("sql-injection", "CRITICAL", "SQL injection: query built from untrusted input"),
    "CWE-79": ("xss", "HIGH", "Cross-site scripting: untrusted input reaches HTML output"),
    "CWE-78": ("command-injection", "CRITICAL", "OS command injection: untrusted input reaches a shell command"),
    "CWE-22": ("path-traversal", "HIGH", "Path traversal: untrusted input used in a file path"),
    "CWE-798": ("hardcoded-credentials", "HIGH", "Hardcoded credential or secret"),
    "CWE-502": ("insecure-deserialization", "CRITICAL", "Insecure deserialization of untrusted data"),
    "CWE-327": ("weak-crypto", "MEDIUM", "Weak or broken cryptography / non-cryptographic randomness"),
}

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


def _weights_file(folder: Path) -> Path:
    for name in ("model.safetensors", "pytorch_model.bin"):
        if (folder / name).is_file():
            return folder / name
    raise RuntimeError(f"{folder} has no model weights")


def load_model(path: Path = MODEL_PATH):
    """Return (model, info). model is None while untrained."""
    untrained = {"name": SERVICE, "version": "untrained", "sha256": None, "trained_on": None, "metrics": {},
                 "status": "untrained", "classes": CLASSES, "threshold": None}
    if path.is_dir() and (path / "config.json").is_file():
        from sastml.codebert import CodeBertClassifier
        model, weights = CodeBertClassifier(path), _weights_file(path)
        meta_path = Path(os.environ.get("MODEL_META_PATH", str(path / "cloudsentinel.json")))
    elif path.is_file():
        import joblib
        model, weights = joblib.load(path), path
        meta_path = Path(os.environ.get("MODEL_META_PATH", str(path.with_suffix(".json"))))
    else:
        return None, untrained
    if not callable(getattr(model, "predict_proba", None)):
        raise RuntimeError(f"{path} does not expose predict_proba(codes, langs)")
    meta = json.loads(meta_path.read_text(encoding="utf-8")) if meta_path.is_file() else {}
    base = getattr(model, "info", {}) or {}
    threshold = os.environ.get("ML_SAST_CONFIDENCE_THRESHOLD")
    info = {
        "name": str(meta.get("name", base.get("name", SERVICE))),
        "version": str(meta.get("version", "0")),
        "sha256": sha256_file(weights),
        "trained_on": meta.get("trained_on", base.get("trained_on")),
        "metrics": meta.get("metrics", {}),
        "status": "trained",
        "classes": CLASSES,
        "threshold": float(threshold) if threshold else float(meta.get("threshold", base.get("threshold") or 0.5)),
        "limitations": meta.get("limitations", []),
    }
    if meta.get("components") or base.get("components"):
        info["components"] = meta.get("components", base.get("components"))
    if threshold and hasattr(model, "thresholds"):  # env override applies to every class of a hybrid
        model.thresholds = {c: float(threshold) for c in model.thresholds}
    return model, info


app = FastAPI(title="CloudSentinel ml-sast", version="0.2.0")
MODEL, MODEL_INFO = load_model()


@app.get("/health")
def health():
    return {"status": "ok", "service": SERVICE, "model": MODEL_INFO["status"]}


@app.get("/model-info")
def model_info():
    return MODEL_INFO


def units_of(files):
    units = []
    for f in files:
        if not f.path.lower().endswith(SUPPORTED_SUFFIXES):
            continue
        for u in extract(f.path, f.content):
            units.append((f.path, u))
    return units


def finding(path, u, cwe_index, conf, detector="ml"):
    cwe = CLASSES[cwe_index]
    slug, severity, title = RULES[cwe]
    where = "top-level code" if u.name == "<module>" else f"function '{u.name}'"
    if detector == "rule-based":
        msg = f"[rule-based secrets detector] {title} in {where} (rule confidence {conf:.2f})."
        rule = f"{u.lang}.{slug}.rule"
    else:
        signals = explain(u.code)
        msg = f"{title} suspected in {where} (model confidence {conf:.2f}" + (f"; signals: {', '.join(signals)}" if signals else "") + ")."
        rule = f"{u.lang}.{slug}"
    return Finding(rule=rule, cwe_id=int(cwe.split("-")[1]), severity=severity, message=msg,
                   file_path=path, line_number=max(u.start_line, 1), confidence=round(conf, 4))


def to_findings(units, proba, threshold):
    findings = []
    for (path, u), p in zip(units, proba):
        best = max(range(1, len(CLASSES)), key=lambda i: p[i])
        conf = float(p[best])
        if conf >= threshold:
            findings.append(finding(path, u, best, conf))
    return findings


@app.post("/scan", response_model=ScanResponse)
def scan(request: ScanRequest):
    if MODEL is None:
        return {"findings": []}
    units = units_of(request.files)
    if not units:
        return {"findings": []}
    codes, langs = [u.code for _, u in units], [u.lang for _, u in units]
    try:
        if hasattr(MODEL, "candidates"):  # v2 hybrid: ML ensemble + rule-based secrets, several findings per unit
            cands = MODEL.candidates(codes, langs)
            return {"findings": [finding(path, u, i, conf, det) for (path, u), cs in zip(units, cands) for i, conf, det in cs]}
        proba = MODEL.predict_proba(codes, langs)
    except Exception as exc:  # model failure must surface, never look like a clean scan
        raise HTTPException(status_code=500, detail=f"model scan failed: {type(exc).__name__}") from exc
    return {"findings": to_findings(units, proba, MODEL_INFO["threshold"])}

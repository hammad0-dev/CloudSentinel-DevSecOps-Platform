"""CodeBERT models: a fine-tuned classifier and a frozen-embedding + XGBoost alternative.

Input text is ``"<lang> </s> <code>"`` truncated to ``max_len`` tokens (head of the function).
Both wrappers expose ``predict_proba(codes, langs)`` with columns in ``CLASSES`` order, like SastModel.
"""
import json
import os
from pathlib import Path

import numpy as np

from . import CLASSES

BASE = "microsoft/codebert-base"


def _torch():
    import torch
    torch.set_num_threads(int(os.environ.get("TORCH_THREADS", "8")))
    return torch


def texts(codes, langs):
    return [f"{l} </s> {c}" for c, l in zip(codes, langs)]


class CodeBertClassifier:
    """Fine-tuned RobertaForSequenceClassification stored as a Hugging Face folder."""

    def __init__(self, path, max_len=256, batch=32):
        from transformers import AutoModelForSequenceClassification, AutoTokenizer
        self.path, self.max_len, self.batch = Path(path), max_len, batch
        self.tok = AutoTokenizer.from_pretrained(self.path)
        self.model = AutoModelForSequenceClassification.from_pretrained(self.path).eval()
        meta = self.path / "cloudsentinel.json"
        self.info = json.loads(meta.read_text()) if meta.exists() else {}
        self.classes = list(CLASSES)

    def predict_proba(self, codes, langs):
        torch = _torch()
        out = []
        with torch.no_grad():
            for i in range(0, len(codes), self.batch):
                enc = self.tok(texts(codes[i:i + self.batch], langs[i:i + self.batch]), truncation=True, max_length=self.max_len, padding=True, return_tensors="pt")
                out.append(torch.softmax(self.model(**enc).logits, -1).numpy())
        return np.concatenate(out) if out else np.zeros((0, len(CLASSES)), dtype=np.float32)


def embed(codes, langs, model_name=BASE, max_len=256, batch=32, cache_dir=None):
    """Mean-pooled last hidden state of the frozen base model."""
    torch = _torch()
    from transformers import AutoModel, AutoTokenizer
    tok = AutoTokenizer.from_pretrained(model_name, cache_dir=cache_dir)
    model = AutoModel.from_pretrained(model_name, cache_dir=cache_dir).eval()
    out = []
    with torch.no_grad():
        for i in range(0, len(codes), batch):
            enc = tok(texts(codes[i:i + batch], langs[i:i + batch]), truncation=True, max_length=max_len, padding=True, return_tensors="pt")
            h = model(**enc).last_hidden_state
            m = enc["attention_mask"].unsqueeze(-1).float()
            out.append(((h * m).sum(1) / m.sum(1)).numpy())
    return np.concatenate(out).astype(np.float32)


class CodeBertXGB:
    """Frozen CodeBERT embeddings -> XGBoost. Saved with joblib; the base model is loaded on demand."""

    def __init__(self, estimator, info, max_len=256):
        self.estimator, self.info, self.max_len = estimator, info, max_len
        self.classes = list(CLASSES)

    def predict_proba(self, codes, langs, embeddings=None):
        X = embeddings if embeddings is not None else embed(codes, langs, max_len=self.max_len)
        p = self.estimator.predict_proba(X)
        out = np.zeros((len(X), len(CLASSES)), dtype=np.float32)
        out[:, list(self.estimator.classes_)] = p
        return out

"""Fine-tune microsoft/codebert-base on CPU (background job with checkpoints and resume).

* data: stratified subset of the train split (max --max-samples, default 8000; train is smaller, so all of it)
* max_len 256, 3 epochs, AdamW lr 2e-5, linear warmup/decay, class-weighted cross entropy
* after every epoch: validation macro-F1 on the val split; checkpoint (model + optimizer + scheduler +
  epoch) to checkpoints/codebert/last/ (only the latest is kept); best epoch by val macro-F1 is saved to
  models/codebert/ as a Hugging Face folder with cloudsentinel.json metadata
* resume: rerun the same command; it continues from checkpoints/codebert/last/
Log: logs/codebert.log. Usage: python scripts/train_codebert.py [--epochs 3] [--max-samples 8000]
"""
import argparse
import collections
import json
import os
import random
import shutil
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("HF_HOME", str(ROOT / ".hf"))
from sastml import CLASSES  # noqa: E402
from sastml.codebert import BASE, CodeBertClassifier, texts  # noqa: E402
from sastml.evaluation import best_threshold, load, metrics  # noqa: E402


def log(msg):
    line = f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}"
    print(line, flush=True)
    with open(ROOT / "logs/codebert.log", "a") as fh:
        fh.write(line + "\n")


def stratified(rows, n, seed=0):
    if len(rows) <= n:
        return rows
    by = collections.defaultdict(list)
    for r in rows:
        by[(r["label"], r["lang"])].append(r)
    rnd = random.Random(seed)
    out = []
    for k, rs in by.items():
        rnd.shuffle(rs)
        out += rs[:max(1, round(n * len(rs) / len(rows)))]
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--epochs", type=int, default=3)
    ap.add_argument("--max-samples", type=int, default=8000)
    ap.add_argument("--max-len", type=int, default=256)
    ap.add_argument("--batch", type=int, default=16)
    ap.add_argument("--lr", type=float, default=2e-5)
    args = ap.parse_args()
    import torch
    from transformers import AutoModelForSequenceClassification, AutoTokenizer, get_linear_schedule_with_warmup
    torch.set_num_threads(int(os.environ.get("TORCH_THREADS", "8")))
    torch.manual_seed(0)

    train = stratified(load("train"), args.max_samples)
    val = load("val")
    ckpt, best_dir = ROOT / "checkpoints/codebert/last", ROOT / "models/codebert"
    tok = AutoTokenizer.from_pretrained(BASE)
    resume = (ckpt / "state.pt").exists()
    model = AutoModelForSequenceClassification.from_pretrained(ckpt if resume else BASE, num_labels=len(CLASSES),
                                                               id2label=dict(enumerate(CLASSES)), label2id={c: i for i, c in enumerate(CLASSES)})
    y_all = torch.tensor([CLASSES.index(r["label"]) for r in train])
    counts = torch.bincount(y_all, minlength=len(CLASSES)).float()
    weights = (len(y_all) / (len(CLASSES) * counts.clamp(min=1)))
    loss_fn = torch.nn.CrossEntropyLoss(weight=weights)
    steps_per_epoch = (len(train) + args.batch - 1) // args.batch
    opt = torch.optim.AdamW(model.parameters(), lr=args.lr, weight_decay=0.01)
    sched = get_linear_schedule_with_warmup(opt, int(0.06 * steps_per_epoch * args.epochs), steps_per_epoch * args.epochs)
    start_epoch, best = 0, -1.0
    if resume:
        state = torch.load(ckpt / "state.pt", weights_only=False)
        opt.load_state_dict(state["opt"])
        sched.load_state_dict(state["sched"])
        start_epoch, best = state["epoch"] + 1, state["best"]
        log(f"resumed from epoch {state['epoch'] + 1}, best val macro-F1 {best:.3f}")
    log(f"train={len(train)} val={len(val)} epochs={args.epochs} max_len={args.max_len} batch={args.batch} steps/epoch={steps_per_epoch} threads={torch.get_num_threads()}")
    enc_text = texts([r["code"] for r in train], [r["lang"] for r in train])

    for epoch in range(start_epoch, args.epochs):
        model.train()
        order = list(range(len(train)))
        random.Random(epoch).shuffle(order)
        t0, running = time.time(), 0.0
        for step in range(steps_per_epoch):
            idx = order[step * args.batch:(step + 1) * args.batch]
            enc = tok([enc_text[i] for i in idx], truncation=True, max_length=args.max_len, padding=True, return_tensors="pt")
            loss = loss_fn(model(**enc).logits, y_all[idx])
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            opt.step()
            sched.step()
            opt.zero_grad()
            running += loss.item()
            if (step + 1) % 20 == 0 or step + 1 == steps_per_epoch:
                el = time.time() - t0
                eta = el / (step + 1) * (steps_per_epoch - step - 1)
                log(f"epoch {epoch + 1} step {step + 1}/{steps_per_epoch} loss {running / (step + 1):.4f} elapsed {el / 60:.1f}m eta {eta / 60:.1f}m")
        model.eval()
        model.save_pretrained(ckpt)
        tok.save_pretrained(ckpt)
        clf = CodeBertClassifier(ckpt, max_len=args.max_len)
        vp = clf.predict_proba([r["code"] for r in val], [r["lang"] for r in val])
        score = metrics(val, vp)["macro_f1"]
        log(f"epoch {epoch + 1} val macro-F1 {score:.3f}")
        if score > best:
            best = score
            thr, thr_scores = best_threshold(val, vp)
            if best_dir.exists():
                shutil.rmtree(best_dir)
            shutil.copytree(ckpt, best_dir)
            info = {"name": "ml-sast-codebert", "kind": "codebert", "base_model": BASE, "epoch": epoch + 1, "val_macro_f1_argmax": score,
                    "threshold": thr, "val_macro_f1_by_threshold": thr_scores, "max_len": args.max_len, "batch": args.batch, "lr": args.lr,
                    "n_train": len(train), "trained_on": "data/processed/train.jsonl (stratified subset)" if len(train) < len(load("train")) else "data/processed/train.jsonl"}
            (best_dir / "cloudsentinel.json").write_text(json.dumps(info, indent=2) + "\n")
            log(f"new best saved to models/codebert (epoch {epoch + 1}, threshold {thr})")
        torch.save({"opt": opt.state_dict(), "sched": sched.state_dict(), "epoch": epoch, "best": best}, ckpt / "state.pt")
    log("done")


if __name__ == "__main__":
    main()

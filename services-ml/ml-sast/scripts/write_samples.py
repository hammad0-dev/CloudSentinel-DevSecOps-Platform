"""Write a few synthetic examples per class/language to data/samples/ (committed; no third-party code)."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from sastml.extract import js_parses  # noqa: E402
from sastml.synthetic import generate  # noqa: E402

rows = generate(per_family=2, seed=99, js_validator=js_parses)
picked, seen = [], {}
for r in rows:
    k = (r["label"], r["lang"])
    if seen.get(k, 0) < 2:
        seen[k] = seen.get(k, 0) + 1
        picked.append(r)
out = ROOT / "data/samples/synthetic_samples.jsonl"
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text("".join(json.dumps(r) + "\n" for r in picked))
print(len(picked), "samples ->", out.relative_to(ROOT))

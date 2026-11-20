"""Collect real Python/JS vulnerable/fixed function pairs from OSV (GitHub-reviewed npm + PyPI advisories).

Pipeline (time-boxed; resumable via data/raw/osv/commits_done.jsonl):
1. Advisories from the OSV dumps (data/raw/osv/{npm,PyPI}.zip). Keep records with GitHub CWE ids that
   map to a target class; skip malware (MAL-*) and withdrawn records.
2. Fix commits: references of the form github.com/<owner>/<repo>/commit/<sha>. Skip repos that are, or
   look like forks of, a development/fresh evaluation app, and commits already in CrossVul.
3. Per commit (GitHub API): skip if more than MAX_SOURCE_FILES non-test .py/.js files changed.
4. Fetch before (parent) / after versions of each changed non-test .py/.js file from
   raw.githubusercontent.com (no clones). Extract units; keep units whose code changed.
5. Sink filter: the changed lines (removed + added) must contain a sink of the labelled class
   (``SINKS``); diffs that are only whitespace/comments are dropped by the normalized comparison.
6. At most PER_REPO pairs per repository.
Rows go to data/raw/osv/rows.jsonl (before -> class, after -> safe).
Stops at --deadline-minutes or if data/raw/osv exceeds --max-gb. Needs GH_TOKEN in the environment.
"""
import argparse
import collections
import concurrent.futures as cf
import io
import json
import os
import re
import shutil
import sys
import time
import urllib.error
import urllib.request
import warnings
import zipfile
from pathlib import Path

warnings.filterwarnings("ignore", category=SyntaxWarning)
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))
from build_dataset import CWE_MAP, TEST_NAME, keyed, norm  # noqa: E402
from sastml.extract import extract, language_of  # noqa: E402
from sastml.secrets import scan as secret_scan  # noqa: E402

OUT = ROOT / "data/raw/osv"
EVAL_APPS = re.compile(r"(?i)(nodegoat|dvna|vulpy|pygoat|django\.?nv|dvws|vulnerable-node|dvpwa|juice-?shop)")
MAX_SOURCE_FILES = 5
PER_REPO = 20
SRC_EXT = (".py", ".js", ".mjs", ".cjs", ".jsx")
SINKS = {
    "CWE-89": r"(?i)\.(execute|executemany|raw|query)\s*\(|\b(select|insert|update|delete)\b.{0,80}\b(from|into|set|where)\b|knex\.raw|sequelize\.query|\btext\(",
    "CWE-79": r"(?i)innerHTML|outerHTML|document\.write|\.html\(|res\.(send|write|end)\(|render_template_string|mark_safe|Markup\(|\|\s*safe|escape|sanitiz|<\s*/?\s*\w+[^>]*>|insertAdjacentHTML|dangerouslySetInnerHTML|HttpResponse\(",
    "CWE-78": r"(?i)\b(exec|execSync|spawn|spawnSync|execFile|execFileSync|fork)\s*\(|child_process|os\.(system|popen)|subprocess|shell\s*[=:]|shlex",
    "CWE-22": r"(?i)\b(open|readFile|readFileSync|createReadStream|writeFile|writeFileSync|unlink|sendFile|send_file|send_from_directory|download|rmdir|mkdir|rename)\b|path\.(join|resolve|normalize|basename)|os\.path\.(join|abspath|realpath|normpath|basename)|\.\./|secure_filename|startsWith|startswith",
    "CWE-502": r"(?i)pickle|yaml\.(load|safe_load|unsafe_load|full_load)|safeLoad|unserialize|deserializ|marshal|jsonpickle|shelve|torch\.load|Loader\s*=|schema\s*:",
    "CWE-327": r"(?i)\bmd5\b|\bsha1\b|\bdes\b|des3|rc4|ecb|createCipher|createHash|hashlib|Math\.random|random\.|randomBytes|secrets\.|bcrypt|scrypt|pbkdf2|cipher",
    "CWE-798": None,  # uses the rule-based secrets scanner on the removed lines
}
CLASS_ORDER = ["CWE-502", "CWE-327", "CWE-798", "CWE-89", "CWE-78", "CWE-22", "CWE-79"]  # rare classes first


def http(url, token=None, accept=None, timeout=30):
    req = urllib.request.Request(url, headers={"User-Agent": "cloudsentinel-ml-sast-research", **({"Authorization": f"Bearer {token}"} if token else {}),
                                               **({"Accept": accept} if accept else {})})
    for attempt in range(4):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.status, resp.read(), dict(resp.headers)
        except urllib.error.HTTPError as e:
            if e.code in (403, 429) and attempt < 3:
                reset = int(e.headers.get("x-ratelimit-reset", "0") or 0)
                wait = max(5, min(900, reset - int(time.time()) + 2)) if e.headers.get("x-ratelimit-remaining") == "0" else 10 * (attempt + 1)
                print(f"rate limited ({e.code}), sleeping {wait}s", flush=True)
                time.sleep(wait)
                continue
            return e.code, b"", dict(e.headers or {})
        except Exception:
            time.sleep(2 * (attempt + 1))
    return 0, b"", {}


def advisories():
    """(repo, sha, target_class, advisory_id, raw_cwe) for mapped GitHub fix commits."""
    out, seen = [], set()
    for eco in ("npm", "PyPI"):
        with zipfile.ZipFile(OUT / f"{eco}.zip") as z:
            for name in z.namelist():
                if name.startswith("MAL-"):
                    continue
                rec = json.loads(z.read(name))
                if rec.get("withdrawn"):
                    continue
                cwes = (rec.get("database_specific") or {}).get("cwe_ids") or []
                targets = sorted({CWE_MAP[c] for c in cwes if c in CWE_MAP})
                if len(targets) != 1:  # unmapped or ambiguous (several target classes): drop
                    continue
                for ref in rec.get("references", []):
                    m = re.match(r"https://github\.com/([\w.-]+/[\w.-]+)/(?:pull/\d+/)?commits?/([0-9a-f]{40})", ref.get("url", ""))
                    if not m:
                        continue
                    repo, sha = m.group(1).lower().removesuffix(".git"), m.group(2)
                    if EVAL_APPS.search(repo) or (repo, sha) in seen:
                        continue
                    seen.add((repo, sha))
                    out.append({"repo": repo, "sha": sha, "target": targets[0], "advisory": rec["id"], "aliases": rec.get("aliases", []),
                                "cwe_raw": [c for c in cwes if c in CWE_MAP], "ecosystem": eco})
    return out


def changed_lines(before, after):
    b = [x.strip() for x in before.split("\n")]
    a = [x.strip() for x in after.split("\n")]
    sb, sa = set(b), set(a)
    return [x for x in b if x and x not in sa], [x for x in a if x and x not in sb]


def sink_ok(target, removed, added):
    if target == "CWE-798":
        return any(secret_scan(x) for x in removed)
    rx = re.compile(SINKS[target])
    return any(rx.search(x) for x in removed + added)


def process_commit(c, token, per_repo):
    status, body, _ = http(f"https://api.github.com/repos/{c['repo']}/commits/{c['sha']}", token, "application/vnd.github+json")
    if status != 200:
        return {"status": f"api_{status}"}, []
    data = json.loads(body)
    parents = data.get("parents") or []
    if len(parents) != 1:
        return {"status": "merge_or_root"}, []
    parent = parents[0]["sha"]
    files = [f for f in data.get("files", []) if f.get("filename", "").lower().endswith(SRC_EXT)
             and not TEST_NAME.search(Path(f["filename"]).name) and not re.search(r"(^|/)(tests?|__tests__|spec|fixtures?|examples?|docs?|node_modules|vendor|dist|build)/", f["filename"])]
    if not files:
        return {"status": "no_source_files"}, []
    if len(files) > MAX_SOURCE_FILES:
        return {"status": "too_many_files"}, []
    rows = []
    for f in files:
        if f.get("status") != "modified" or per_repo[c["repo"]] >= PER_REPO:
            continue
        path = f["filename"]
        sb, before, _ = http(f"https://raw.githubusercontent.com/{c['repo']}/{parent}/{path}", token)
        sa, after, _ = http(f"https://raw.githubusercontent.com/{c['repo']}/{c['sha']}/{path}", token)
        if sb != 200 or sa != 200 or len(before) > 512 * 1024 or len(after) > 512 * 1024:
            continue
        ub, ua = keyed(extract(path, before.decode("utf-8", "ignore"))), keyed(extract(path, after.decode("utf-8", "ignore")))
        for k, u in ub.items():
            v = ua.get(k)
            if v is None or norm(u.code) == norm(v.code) or (k[0] == "<module>" and c["target"] != "CWE-798"):
                continue
            if u.end_line - u.start_line > 400:
                continue
            removed, added = changed_lines(u.code, v.code)
            if not sink_ok(c["target"], removed, added):
                continue
            if per_repo[c["repo"]] >= PER_REPO:
                break
            per_repo[c["repo"]] += 1
            base = {"lang": u.lang, "source": f"repo:{c['repo']}", "pair_id": f"osv:{c['advisory']}:{c['sha'][:12]}:{path}:{k[0]}:{k[1]}", "origin": "osv",
                    "advisory": c["advisory"], "aliases": c["aliases"], "cwe_raw": c["cwe_raw"], "commit": f"https://github.com/{c['repo']}/commit/{c['sha']}",
                    "file": path, "function": k[0], "removed_lines": removed[:40], "added_lines": added[:40]}
            rows.append({**base, "code": u.code, "label": c["target"]})
            rows.append({**base, "code": v.code, "label": "safe"})
    return {"status": "ok", "pairs": len(rows) // 2}, rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--deadline-minutes", type=float, default=150)
    ap.add_argument("--max-gb", type=float, default=5.0)
    ap.add_argument("--workers", type=int, default=6)
    args = ap.parse_args()
    token = os.environ.get("GH_TOKEN")
    if not token:
        sys.exit("GH_TOKEN is not set")
    deadline = time.time() + args.deadline_minutes * 60
    OUT.mkdir(parents=True, exist_ok=True)
    crossvul = json.loads((ROOT / "data/raw/crossvul/extracted/dataset_final_sorted/metadata.json").read_text())
    crossvul_shas = {m.group(1) for c in crossvul for m in [re.search(r"/commit/([0-9a-f]{40})", c.get("url", ""))] if m}
    commits = [c for c in advisories() if c["sha"] not in crossvul_shas]
    by_class = collections.defaultdict(list)
    for c in commits:
        by_class[c["target"]].append(c)
    order = [c for group in itertools_roundrobin([by_class[k] for k in CLASS_ORDER]) for c in [group]]
    done_path, rows_path = OUT / "commits_done.jsonl", OUT / "rows.jsonl"
    done = {json.loads(l)["key"] for l in done_path.open()} if done_path.exists() else set()
    per_repo = collections.Counter()
    if rows_path.exists():
        for l in rows_path.open():
            r = json.loads(l)
            if r["label"] != "safe":
                per_repo[r["source"][5:]] += 1
    todo = [c for c in order if f"{c['repo']}@{c['sha']}" not in done]
    print(f"advisory commits mapped: {len(commits)} (after CrossVul dedupe); by class: { {k: len(v) for k, v in by_class.items()} }; todo {len(todo)}", flush=True)
    stats = collections.Counter()
    with cf.ThreadPoolExecutor(args.workers) as pool, done_path.open("a") as dfh, rows_path.open("a") as rfh:
        futures = {}
        it = iter(todo)
        stop_reason = "all commits processed"

        def submit():
            c = next(it, None)
            if c is not None:
                futures[pool.submit(process_commit, c, token, per_repo)] = c
        for _ in range(args.workers * 2):
            submit()
        n = 0
        while futures:
            fin, _ = cf.wait(list(futures), return_when=cf.FIRST_COMPLETED)
            for fu in fin:
                c = futures.pop(fu)
                try:
                    st, rows = fu.result()
                except Exception as e:  # keep going; record the failure
                    st, rows = {"status": f"error_{type(e).__name__}"}, []
                stats[st["status"]] += 1
                for r in rows:
                    rfh.write(json.dumps(r) + "\n")
                dfh.write(json.dumps({"key": f"{c['repo']}@{c['sha']}", "target": c["target"], **st}) + "\n")
                n += 1
                if n % 50 == 0:
                    rfh.flush(); dfh.flush()
                    size = sum(p.stat().st_size for p in OUT.rglob("*") if p.is_file()) / 1e9
                    print(f"{time.strftime('%H:%M:%S')} commits {n}/{len(todo)} stats {dict(stats)} data {size:.2f} GB", flush=True)
                    if size > args.max_gb:
                        stop_reason = "disk budget exceeded"
                if time.time() < deadline and stop_reason == "all commits processed":
                    submit()
                elif stop_reason == "all commits processed":
                    stop_reason = "deadline reached"
        print(f"stopped: {stop_reason}; processed {n}; stats {dict(stats)}", flush=True)


def itertools_roundrobin(groups):
    groups = [list(g) for g in groups]
    i = 0
    while any(groups):
        g = groups[i % len(groups)]
        if g:
            yield g.pop(0)
        i += 1


if __name__ == "__main__":
    main()

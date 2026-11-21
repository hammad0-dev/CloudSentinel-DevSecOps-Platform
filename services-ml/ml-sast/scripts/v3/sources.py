"""ml-sast v3: turn each new source into v2-format rows (fix pairs: function before the fix -> its CWE class,
after the fix -> safe). Data is read only (never executed); run with `python -I`.

Rows go to /mnt/d/cs-data/sast-v3/work/<source>/rows.jsonl (large, on D:), counts to
reports/v3/sources/<source>.json (per language and per CWE, before and after every filter).
Usage: python -I scripts/v3/sources.py pyvul|jsvul|gitlab|cvefixes
"""
import collections
import hashlib
import json
import re
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
D = Path("/mnt/d/cs-data/sast-v3")
WORK = D / "work"
REPORT = ROOT / "reports/v3/sources"
# the v2 CWE map (scripts/build_dataset.py)
CWE_MAP = {
    "CWE-89": "CWE-89", "CWE-564": "CWE-89",
    "CWE-79": "CWE-79", "CWE-80": "CWE-79", "CWE-83": "CWE-79", "CWE-87": "CWE-79",
    "CWE-78": "CWE-78", "CWE-77": "CWE-78", "CWE-88": "CWE-78",
    "CWE-22": "CWE-22", "CWE-23": "CWE-22", "CWE-35": "CWE-22", "CWE-36": "CWE-22", "CWE-73": "CWE-22",
    "CWE-798": "CWE-798", "CWE-259": "CWE-798", "CWE-321": "CWE-798",
    "CWE-502": "CWE-502",
    "CWE-327": "CWE-327", "CWE-328": "CWE-327", "CWE-326": "CWE-327", "CWE-916": "CWE-327", "CWE-759": "CWE-327", "CWE-760": "CWE-327",
}
JS_EXT = (".js", ".mjs", ".cjs")
TEST_NAME = re.compile(r"(^|/)(tests?|__tests__|spec)/|(^test_|_test\.py$|\.test\.[cm]?js$|\.spec\.[cm]?js$)")
MAX_LINES = 400


def norm(code):
    code = re.sub(r"(?m)#.*$|//.*$", "", code)
    code = re.sub(r"/\*.*?\*/", "", code, flags=re.S)
    return re.sub(r"\s+", " ", code).strip()


def targets(cwes):
    """The set of target classes a CWE list maps to (rows are kept only if this has exactly one element)."""
    return {CWE_MAP[c] for c in cwes if c in CWE_MAP}


def repo_of(url):
    m = re.search(r"github\.com/([^/]+/[^/]+?)(?:\.git)?/(?:commit|pull)/", url or "")
    return m.group(1).lower() if m else None


class Stats:
    def __init__(self):
        self.before = collections.Counter()   # (lang, cwe_raw) for every raw record
        self.drop = collections.Counter()     # reason -> count
        self.after = collections.Counter()    # (lang, class) of kept pairs

    def dump(self, name, extra=None):
        REPORT.mkdir(parents=True, exist_ok=True)
        out = {"source": name,
               "raw_by_lang": dict(collections.Counter(k[0] for k in self.before.elements())),
               "raw_by_lang_cwe_top": {f"{l}|{c}": n for (l, c), n in self.before.most_common(60)},
               "dropped": dict(self.drop),
               "kept_pairs_by_lang_class": {f"{l}|{c}": n for (l, c), n in sorted(self.after.items())},
               "kept_pairs": sum(self.after.values()), "kept_rows": 2 * sum(self.after.values()), **(extra or {})}
        (REPORT / f"{name}.json").write_text(json.dumps(out, indent=1) + "\n")
        return out


def emit(rows, st, *, origin, lang, repo, pair, cwe_raw, cls, before, after, file="", function="", cve=None, extra=None):
    if not before or not after or not before.strip():
        st.drop["empty_code"] += 1
        return
    if norm(before) == norm(after):
        st.drop["before_equals_after"] += 1
        return
    if before.count("\n") > MAX_LINES or after.count("\n") > MAX_LINES:
        st.drop["too_long"] += 1
        return
    if not repo:
        st.drop["no_repository"] += 1
        return
    base = {"lang": lang, "source": f"repo:{repo}", "pair_id": pair, "origin": origin, "cve": cve, "cwe_raw": cwe_raw,
            "file": file, "function": function, **(extra or {})}
    rows.append({**base, "code": before, "label": cls})
    rows.append({**base, "code": after, "label": "safe"})
    st.after[(lang, cls)] += 1


def write(name, rows):
    out = WORK / name
    out.mkdir(parents=True, exist_ok=True)
    with open(out / "rows.jsonl", "w") as fh:
        for r in rows:
            r["id"] = hashlib.sha256((r["lang"] + "\0" + r["code"]).encode()).hexdigest()[:16]
            fh.write(json.dumps(r) + "\n")


def pyvul():
    p = D / "pyvul/repo/dataset"
    cmap = json.loads((p / "commits_cwe_map.json").read_text())
    rows, st = [], Stats()
    for line in open(p / "function_level_dataset.out", encoding="utf-8", errors="replace"):
        if not line.strip():
            continue
        r = json.loads(line)
        lang = {"Python": "python", "JavaScript": "javascript"}.get(r.get("programming_language"))
        cwe = cmap.get(r.get("commit"))
        st.before[(r.get("programming_language"), cwe)] += 1
        if lang is None:
            st.drop["language_not_python_or_js"] += 1
            continue
        t = targets([cwe] if cwe else [])
        if len(t) != 1:
            st.drop["cwe_not_exactly_one_target"] += 1
            continue
        emit(rows, st, origin="pyvul", lang=lang, repo=repo_of(r.get("commit")), pair=f"pyvul:{r.get('file_change_id')}:{r.get('function_name')}",
             cwe_raw=cwe, cls=t.pop(), before=r.get("code_before"), after=r.get("code_after"), function=r.get("function_name") or "",
             extra={"commit": r.get("commit"), "js_scope": "JavaScript, not strictly Node.js" if lang == "javascript" else None})
    write("pyvul", rows)
    return st.dump("pyvul", {"licence": "none stated (research use with attribution)", "commit": "1172bfd1579b4ad2a524549412170d08ca618fb3"})


def jsvul():
    p = WORK / "jsvul/js_vul"
    recs = {}
    for s in ("train", "val", "test"):
        for line in open(p / f"{s}.jsonl"):
            r = json.loads(line)
            recs[r["id"]] = r
    rows, st, used = [], Stats(), set()
    for r in recs.values():
        ext = Path(r["file"]).suffix.lower()
        lang_raw = "javascript" if ext in JS_EXT else ext or "none"
        st.before[(lang_raw, ",".join(r.get("cwe") or []) or None)] += 1
        if str(r["label"]) != "1":
            continue
        if not r.get("paired_id") or r["paired_id"] not in recs:
            st.drop["vulnerable_without_fixed_pair"] += 1
            continue
        if ext not in JS_EXT:
            st.drop["not_js_extension (ts/tsx/jsx/...)"] += 1
            continue
        if TEST_NAME.search(r["file"]):
            st.drop["test_file"] += 1
            continue
        t = targets(r.get("cwe") or [])
        if len(t) != 1:
            st.drop["cwe_not_exactly_one_target"] += 1
            continue
        fixed = recs[r["paired_id"]]
        used.add(r["id"])
        emit(rows, st, origin="jsvul", lang="javascript", repo=(r.get("project") or "").lower() or None, pair=f"jsvul:{r['id']}",
             cwe_raw=",".join(r["cwe"]), cls=t.pop(), before=r["body"], after=fixed["body"], file=r["file"], function=r.get("name") or "",
             cve=r.get("cve"), extra={"commit": r.get("sha"), "js_scope": "JavaScript, not strictly Node.js"})
    write("jsvul", rows)
    return st.dump("jsvul", {"licence": "CC BY 4.0 (Zenodo 18195839)", "note": "only fix pairs (paired_id); JsVul's unchanged-function negatives are not used"})


def gitlab():
    """ruleid/ok annotated rule tests: the annotated statement's enclosing function, or for module-level code the
    annotated statement itself, is one unit; ruleid -> the rule's CWE class, ok -> safe."""
    from sastml.extract import extract
    base = D / "gitlab-sast-rules/repo"
    rows, st = [], Stats()
    ann = re.compile(r"^\s*(?:#|//)\s*(ruleid|ok)\s*:\s*([\w.\-]+)")
    for f in sorted(base.rglob("*")):
        if f.suffix not in (".py",) + JS_EXT or ".git" in f.parts or f.parts[len(base.parts)] in ("ci", "scripts", "qa", "spec"):
            continue
        yml = f.with_suffix(".yml")
        meta = yml.read_text("utf-8", "ignore") if yml.exists() else ""
        cwes = re.findall(r"CWE-\d+", meta)
        lang = "python" if f.suffix == ".py" else "javascript"
        text = f.read_text("utf-8", "ignore")
        lines = text.splitlines()
        units = [u for u in extract(str(f.name), text) if u.name != "<module>"]
        rel = str(f.relative_to(base))
        licence = "LGPL (rules/lgpl*/LICENSE)" if rel.startswith("rules/lgpl") else "MIT (GitLab; some files note Apache-2.0 bandit origin)"
        # v3 fix (found in the noise check): a unit can carry several annotations (ruleid and ok in one function).
        # Collect them per unit first; a unit is vulnerable if any target-class ruleid points into it, dropped if a
        # non-target ruleid does (its true label is not 'safe'), and safe only if every annotation in it is ok.
        units_ann = {}
        t = targets(cwes)
        for i, ln in enumerate(lines):
            m = ann.match(ln)
            if not m:
                continue
            kind = m.group(1)
            st.before[(lang, f"{kind}:{','.join(sorted(set(cwes))) or None}")] += 1
            j = i + 1
            while j < len(lines) and (not lines[j].strip() or ann.match(lines[j])):
                j += 1
            if j >= len(lines):
                continue
            owner = next((u for u in units if u.start_line <= j + 1 <= u.end_line), None)
            if owner is not None:
                code, key = owner.code, ("fn", owner.start_line)
            else:
                k = j
                while k + 1 < len(lines) and lines[k + 1].strip() and not ann.match(lines[k + 1]) and not lines[k + 1].lstrip().startswith(("#", "//")):
                    k += 1
                code, key = "\n".join(lines[j:k + 1]), ("stmt", j)
            u = units_ann.setdefault(key, {"code": code, "kinds": set(), "j": j, "name": owner.name if owner else "<statement>"})
            u["kinds"].add(kind)
        for key, u in units_ann.items():
            if "ruleid" in u["kinds"]:
                if len(t) != 1:
                    st.drop["ruleid_of_non_target_rule (unit dropped)"] += 1
                    continue
                cls = next(iter(t))
            else:
                cls = "safe"
            if len(u["kinds"]) > 1:
                st.drop["unit_with_ruleid_and_ok (kept as vulnerable)"] += 1
            rows.append({"lang": lang, "source": f"rules:{rel.rsplit('/', 1)[0]}", "pair_id": f"gitlab:{rel}:{u['j']}", "origin": "gitlab_rules",
                         "cve": None, "cwe_raw": ",".join(cwes), "file": rel, "function": u["name"],
                         "code": u["code"], "label": cls, "licence": licence})
            st.after[(lang, cls)] += 1
    write("gitlab", rows)
    out = st.dump("gitlab", {"licence": "MIT (repo), rules/lgpl* LGPL", "commit": "83144bd2ec7d3200cda96347fa923f81c8ad8413",
                             "note": "hand-written rule test cases (not fix pairs): one row per annotated unit"})
    out["kept_rows"] = len(rows)
    (REPORT / "gitlab.json").write_text(json.dumps(out, indent=1) + "\n")
    return out


def cvefixes():
    db = WORK / "cvefixes/CVEfixes.db"
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    cur = con.cursor()
    cwe_of = collections.defaultdict(set)
    for cve, cwe in cur.execute("SELECT cve_id, cwe_id FROM cwe_classification"):
        cwe_of[cve].add(cwe)
    fix_cve = collections.defaultdict(set)
    for cve, h, repo in cur.execute("SELECT cve_id, hash, repo_url FROM fixes"):
        fix_cve[h].add(cve)
    rows, st = [], Stats()
    q = ("SELECT f.file_change_id, f.hash, f.filename, f.programming_language, c.repo_url, m.name, m.before_change, m.code, m.signature "
         "FROM method_change m JOIN file_change f ON m.file_change_id = f.file_change_id JOIN commits c ON c.hash = f.hash "
         "WHERE f.programming_language IN ('Python', 'JavaScript')")
    by_key = collections.defaultdict(dict)
    meta = {}
    for fcid, h, fname, plang, repo_url, name, before, code, sig in cur.execute(q):
        side = "before" if str(before).lower() == "true" else "after"
        by_key[(fcid, sig or name)][side] = code
        meta[(fcid, sig or name)] = (h, fname, plang, repo_url, name)
    for k, sides in by_key.items():
        h, fname, plang, repo_url, name = meta[k]
        cwes = sorted({c for cve in fix_cve.get(h, ()) for c in cwe_of.get(cve, ())})
        lang = "python" if plang == "Python" else "javascript"
        st.before[(plang, ",".join(cwes) or None)] += 1
        ext = Path(fname or "").suffix.lower()
        if (lang == "python" and ext != ".py") or (lang == "javascript" and ext not in JS_EXT):
            st.drop["extension_not_py_js_mjs_cjs"] += 1
            continue
        if TEST_NAME.search(fname or ""):
            st.drop["test_file"] += 1
            continue
        if "before" not in sides or "after" not in sides:
            st.drop["no_before_after_pair"] += 1
            continue
        t = targets(cwes)
        if len(t) != 1:
            st.drop["cwe_not_exactly_one_target"] += 1
            continue
        emit(rows, st, origin="cvefixes", lang=lang, repo=repo_of((repo_url or "") + "/commit/x") or (repo_url or "").lower() or None,
             pair=f"cvefixes:{k[0]}:{name}", cwe_raw=",".join(cwes), cls=t.pop(), before=sides["before"], after=sides["after"], file=fname,
             function=name, cve=",".join(sorted(fix_cve.get(h, ()))), extra={"commit": h,
                                                                               "js_scope": "JavaScript, not strictly Node.js" if lang == "javascript" else None})
    write("cvefixes", rows)
    return st.dump("cvefixes", {"licence": "CC BY 4.0 (Zenodo 13118970, v1.0.8)"})


if __name__ == "__main__":
    out = {"pyvul": pyvul, "jsvul": jsvul, "gitlab": gitlab, "cvefixes": cvefixes}[sys.argv[1]]()
    print(json.dumps({k: v for k, v in out.items() if k != "raw_by_lang_cwe_top"}, indent=1))

"""Stream the CVEfixes v1.0.8 SQL dump (zip -> gzip -> SQL text, never fully extracted) into a SMALL SQLite database
on D: that holds only what ml-sast v3 needs: fixes, cwe_classification, commits (repo), and the file_change /
method_change rows of Python and JavaScript files. No Postgres/SQLite server, no full extraction to disk.

Two passes over the dump:
  1. schema, fixes, cwe_classification, commits(hash, repo_url), file_change rows with programming_language in
     (Python, JavaScript) -- without their large file-level columns (code_before/after, diff);
  2. method_change rows whose file_change_id is one of those files.
Each INSERT statement is executed into an in-memory staging database with the dump's own schema (so values are parsed by
SQLite itself, not by hand), filtered, and copied to the output. The data is never executed as code.
Output: /mnt/d/cs-data/sast-v3/work/cvefixes/CVEfixes.db (sources.py cvefixes reads it).
Usage: python -I scripts/v3/cvefixes_extract.py
"""
import io
import json
import re
import sqlite3
import subprocess
import sys
import time
import zipfile
from pathlib import Path

ZIP = Path("/mnt/d/cs-data/sast-v3/cvefixes/CVEfixes_v1.0.8.zip")
MEMBER = "CVEfixes_v1.0.8/Data/CVEfixes_v1.0.8.sql.gz"
OUT = Path("/mnt/d/cs-data/sast-v3/work/cvefixes/CVEfixes.db")
KEEP_SMALL = {"fixes", "cwe_classification", "commits"}
INS = re.compile(r'^INSERT INTO "?(\w+)"?')


def statements():
    """Yield complete SQL statements from the gzipped dump inside the zip (pigz -dc for speed)."""
    zf = zipfile.ZipFile(ZIP)
    raw = zf.open(MEMBER)
    proc = subprocess.Popen(["pigz", "-dc"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    import threading

    def feed():
        while True:
            b = raw.read(1 << 20)
            if not b:
                break
            proc.stdin.write(b)
        proc.stdin.close()
    threading.Thread(target=feed, daemon=True).start()
    buf = []
    for line in io.TextIOWrapper(proc.stdout, encoding="utf-8", errors="replace"):
        buf.append(line)
        if line.rstrip().endswith(";") and sqlite3.complete_statement("".join(buf)):
            yield "".join(buf)
            buf = []
    proc.wait()


def main():
    OUT.parent.mkdir(parents=True, exist_ok=True)
    if OUT.exists():
        sys.exit(f"{OUT} exists; delete it to rebuild")
    tmp = OUT.with_suffix(".partial")
    if tmp.exists():
        tmp.unlink()
    out = sqlite3.connect(tmp)
    mem = sqlite3.connect(":memory:")
    schema = {}
    keep_fc, t0, n = set(), time.time(), 0
    stats = {}
    # pass 1
    for st in statements():
        n += 1
        head = st.lstrip()[:200]
        if head.upper().startswith("CREATE TABLE"):
            name = re.search(r'CREATE TABLE (?:IF NOT EXISTS )?"?(\w+)"?', head, re.I).group(1)
            schema[name] = st
            mem.execute(st)
            if name in KEEP_SMALL or name in ("file_change", "method_change"):
                out.execute(st)
            continue
        m = INS.match(head)
        if not m:
            continue
        t = m.group(1)
        if t in KEEP_SMALL:
            out.execute(st)
            stats[t] = stats.get(t, 0) + 1
        elif t == "file_change":
            mem.execute(st)
            rows = mem.execute("SELECT * FROM file_change").fetchall()
            cols = [d[1] for d in mem.execute("PRAGMA table_info(file_change)")]
            mem.execute("DELETE FROM file_change")
            for row in rows:
                rec = dict(zip(cols, row))
                stats["file_change_all"] = stats.get("file_change_all", 0) + 1
                if rec.get("programming_language") in ("Python", "JavaScript"):
                    keep_fc.add(rec["file_change_id"])
                    for big in ("code_before", "code_after", "diff", "diff_parsed"):
                        if big in rec:
                            rec[big] = None
                    out.execute(f"INSERT INTO file_change ({','.join(cols)}) VALUES ({','.join('?' * len(cols))})", [rec[c] for c in cols])
        if n % 200000 == 0:
            out.commit()
            print(f"pass1 {n} statements, {len(keep_fc)} py/js files, {time.time() - t0:.0f}s", flush=True)
    out.commit()
    stats["file_change_py_js"] = len(keep_fc)
    print(f"pass1 done: {stats} ({time.time() - t0:.0f}s)", flush=True)
    # pass 2
    n = 0
    for st in statements():
        n += 1
        head = st.lstrip()[:200]
        m = INS.match(head)
        if not m or m.group(1) != "method_change":
            continue
        mem.execute(st)
        cols = [d[1] for d in mem.execute("PRAGMA table_info(method_change)")]
        for row in mem.execute("SELECT * FROM method_change").fetchall():
            rec = dict(zip(cols, row))
            stats["method_change_all"] = stats.get("method_change_all", 0) + 1
            if rec.get("file_change_id") in keep_fc:
                out.execute(f"INSERT INTO method_change ({','.join(cols)}) VALUES ({','.join('?' * len(cols))})", list(row))
                stats["method_change_py_js"] = stats.get("method_change_py_js", 0) + 1
        mem.execute("DELETE FROM method_change")
        if n % 200000 == 0:
            out.commit()
            print(f"pass2 {n} statements, {stats.get('method_change_py_js', 0)} kept, {time.time() - t0:.0f}s", flush=True)
    out.commit()
    out.close()
    tmp.rename(OUT)
    Path(str(OUT) + ".stats.json").write_text(json.dumps(stats, indent=1))
    print("done", json.dumps(stats), f"{time.time() - t0:.0f}s", flush=True)


if __name__ == "__main__":
    main()

"""Run the offline ZAP full scan (unmodified zap-full-scan.py) for the v3 comparison, one app at a time.

Differences from lab/zap-scan.sh (v1/v2), decided before any v3 ZAP run:
* every ground-truth skip path / skip parameter of the app, plus every parameter that fetches a remote
  URL, goes on ZAP's GLOBAL exclude list (globalexcludeurl: spider, scanner and proxy). In v2 a context
  file did not stop the spider from requesting DSVW's excluded parameters;
* a scan is used only if the wrapper exited 0 AND the target container was neither killed, OOM-killed nor
  restarted during the scan AND (DSVW, SirAppSec) its request log shows no excluded parameter. The
  verdict goes to logs/zap_v3/<app>.status ("ok" or the reason); scripts/zap_compare_v3.py reads it.
Usage: python scripts/zap_run_v3.py app [app ...]
"""
import json
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "logs/zap_v3"
IMAGE = "cloudsentinel/zap-offline:verified-closure"
TARGET = {"labflask": "labflask:8080", "labexpress": "labexpress:8080", "labfastapi": "labfastapi:8080", "vulnerable-node": "vulnerable-node:3000",
          "vampi": "vampi:5000", "node-api-goat": "node-api-goat:3001", "dsvw": "dsvw:8080", "sirappsec": "sirappsec:5000", "nodegoat": "nodegoat:4000"}
# parameters that make the target fetch a URL (never on the ml-dast skip list because ml-dast refuses URL values itself)
REMOTE_FETCH = {"dsvw": [("/", "path")]}  # (SirAppSec's SSRF route /v1/test is a skip path already)


def excludes(app):
    gt = json.loads((ROOT / "data/dast/ground_truth_v3.json").read_text())
    host = "http://" + TARGET[app]
    rx = []
    for s in gt["skip"]:
        if s["app"] != app:
            continue
        if "param" in s:
            rx.append(f"^{re.escape(host)}.*[?&]{re.escape(s['param'])}=.*")
        else:
            rx.append("^" + re.sub(r"\\\{[^}]+\\\}", "[^/]+", re.escape(host + s["path"])) + ".*")
    rx += [f"^{re.escape(host)}.*[?&]{re.escape(p)}=.*" for _, p in REMOTE_FETCH.get(app, [])]
    return rx


def container(app):
    name = f"mldast-lab-{app}-1"
    r = subprocess.run(["docker", "inspect", "-f", "{{.State.Running}} {{.State.OOMKilled}} {{.RestartCount}} {{.State.StartedAt}}", name],
                       capture_output=True, text=True, timeout=30)
    return name, r.stdout.strip()


def scan(app):
    OUT.mkdir(parents=True, exist_ok=True)
    rx = excludes(app)
    cfg = ["-silent", "-config", "api.disablekey=true"]
    for i, r in enumerate(rx):
        cfg += ["-config", f"globalexcludeurl.url_list.url({i}).regex={r}", "-config", f"globalexcludeurl.url_list.url({i}).description=cs-v3-{i}",
                "-config", f"globalexcludeurl.url_list.url({i}).enabled=true"]
    name, before = container(app)
    since = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())  # UTC: without the Z docker reads local time
    for f in (OUT / f"{app}.json", OUT / f"{app}.status"):
        f.unlink(missing_ok=True)
    t0 = time.time()
    cmd = ["docker", "run", "--rm", "--network", "mldast-lab_lab", "-v", f"{OUT}:/zap/wrk:rw", IMAGE, "zap-full-scan.py", "-t", f"http://{TARGET[app]}/",
           "-m", "3", "-T", "30", "-I", "-J", f"{app}.json", "-z", " ".join(cfg)]  # -z is split on spaces; the regexes contain none
    assert not any(" " in c for c in cfg)
    with open(OUT / f"{app}.log", "w") as log:
        try:
            rc = subprocess.run(cmd, stdout=log, stderr=subprocess.STDOUT, timeout=2700).returncode
        except subprocess.TimeoutExpired:
            rc = "timeout"
    _, after = container(app)
    status = "ok"
    if rc != 0:  # with -I, zap-full-scan exits 0 unless it failed (every v2 run exited 0)
        status = f"wrapper exit {rc}"
    elif not (OUT / f"{app}.json").exists():
        status = "no report"
    elif not after.startswith("true false") or before.split()[2:] != after.split()[2:]:
        status = f"target not stable (before: {before}; after: {after})"
    if status == "ok" and rx:
        logs = subprocess.run(["docker", "logs", "--since", since, name], capture_output=True, text=True, timeout=60)
        text = logs.stdout + logs.stderr
        skips = [s for s in json.loads((ROOT / "data/dast/ground_truth_v3.json").read_text())["skip"] if s["app"] == app]
        bad = [p for _, p in REMOTE_FETCH.get(app, [])] + [s["param"] for s in skips if s.get("param")]
        hits = sorted({p for p in bad if re.search(rf"[?&]{re.escape(p)}=", text)})
        paths = sorted({s["path"] for s in skips if "param" not in s
                        and re.search(r'"(GET|POST|PUT|DELETE) ' + re.sub(r"\\\{[^}]+\\\}", "[^/ ]+", re.escape(s["path"])) + r"[/?\s]", text)})
        if hits or paths:
            status = f"excluded parameters/paths were requested: {hits + paths}"
        elif not text.strip():
            status = "ok (target writes no request log: exclusions not verifiable)"
    (OUT / f"{app}.status").write_text(status + "\n")
    (OUT / f"{app}.meta.json").write_text(json.dumps({"app": app, "excludes": rx, "exit": rc, "seconds": round(time.time() - t0), "container_before": before,
                                                       "container_after": after, "status": status}, indent=1) + "\n")
    print(app, status, round(time.time() - t0), flush=True)


if __name__ == "__main__":
    for a in sys.argv[1:]:
        scan(a)

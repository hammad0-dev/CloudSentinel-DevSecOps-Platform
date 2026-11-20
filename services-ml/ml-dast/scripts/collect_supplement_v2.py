"""Supplement the final v2 collection without re-probing the ML payloads (disclosed in the model card).

1. The CWE-601 rule payloads were missing from the collector's class list during the final
   collection; send them now to every recorded injection point and append the responses to that
   point's raw record (ML rows are unaffected: ML uses only CWE-89/CWE-79 payload rows).
2. Re-run the passive pass with the redirect-hop fix (Set-Cookie from every hop of a same-origin
   redirect chain), overwriting raw_v2/<app>.passive.json.
Never touches DVNA or DSVW. Usage: python scripts/collect_supplement_v2.py [app ...]
"""
import gzip
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))
import collect_lab  # noqa: E402
from dastml.guards import GuardedClient, TargetPolicy  # noqa: E402
from dastml.groundtruth import GroundTruth  # noqa: E402
from dastml.paths import paths, refuse_frozen  # noqa: E402
from dastml.probe import load_payloads, new_marker, send  # noqa: E402
from featurize import point_of  # noqa: E402

P = paths("v2")


def main(apps):
    gt = GroundTruth(P["ground_truth"])
    redirect = load_payloads(("CWE-601",), P["payloads"])
    for app in apps:
        refuse_frozen(app)
        meta = gt.apps()[app]
        if meta["role"] != "train_loao":
            raise SystemExit(f"refused: {app} is {meta['role']}")
        base = f"http://127.0.0.1:{meta['port']}"
        policy = TargetPolicy(allowed_ports=collect_lab.LAB_PORTS, max_pages=200, max_requests=20000, rate_per_sec=25.0,
                              skip_paths=gt.skip_paths(app), skip_params=gt.skip_params(app), timeout_sec=15.0)
        client = GuardedClient(base, policy)
        collect_lab.login(client, app, first=False)
        path = P["raw"] / f"{app}.jsonl.gz"
        records = [json.loads(line) for line in gzip.open(path, "rt")]
        added = 0
        for rec in records:
            have = {r.get("payload_id") for r in rec["responses"]}
            point = point_of(rec)
            collect_lab.login(client, app)
            original = dict(point.params).get(point.param, "1") or "1"
            for p in redirect:
                if p["id"] in have:
                    continue
                marker = new_marker()
                raw = p["value"].replace("{M}", marker)
                value = original + raw if p["mode"] == "append" else raw
                try:
                    rec["responses"].append({"kind": "payload", "payload_id": p["id"], "marker": marker, "value": value, **send(client, point, value)})
                    added += 1
                except Exception as exc:  # noqa: BLE001 - a refused/broken request is recorded as missing, not fatal
                    rec.setdefault("supplement_errors", []).append(f"{p['id']}: {type(exc).__name__}")
        with gzip.open(path, "wt") as fh:
            for rec in records:
                fh.write(json.dumps(rec) + "\n")
        passive = collect_lab.passive_pass(base, policy, app)
        (P["raw"] / f"{app}.passive.json").write_text(json.dumps(passive, indent=0) + "\n")
        cookies = sum(len(s.get("headers", {}).get("set-cookie", [])) for s in passive)
        print(app, {"redirect_payload_responses_added": added, "requests": client.requests_sent, "passive_set_cookie_headers": cookies}, flush=True)


if __name__ == "__main__":
    gt_apps = [a for a, m in GroundTruth(P["ground_truth"]).apps().items() if m["role"] == "train_loao"]
    main(sys.argv[1:] or gt_apps)

"""Ground-truth lookup: map an injection point + payload class to a label (or None = drop)."""
import json
import re
from pathlib import Path

GT_PATH = Path(__file__).resolve().parents[1] / "data/dast/ground_truth.json"
ML_CLASSES = ("CWE-89", "CWE-79")


def _template_regex(path):
    return re.compile("^" + re.sub(r"\\\{[^}]+\\\}", "[^/]+", re.escape(path)) + "$")


class GroundTruth:
    def __init__(self, path=GT_PATH):
        self.data = json.loads(Path(path).read_text())
        self.entries = []
        for e in self.data["endpoints"]:
            self.entries.append((e, _template_regex(e["path"])))

    def apps(self):
        return self.data["apps"]

    def skip_paths(self, app):
        return tuple(s["path"] for s in self.data["skip"] if s["app"] == app and "param" not in s)

    def skip_params(self, app):
        """(path, parameter) pairs that are never requested (endpoints sharing a path, e.g. DSVW)."""
        return tuple((s["path"], s["param"]) for s in self.data["skip"] if s["app"] == app and "param" in s)

    def passive(self, app):
        """{check: bool} passive-check ground truth read from the app's source, or {}."""
        return {k: v for k, v in self.data.get("passive", {}).get(app, {}).items() if isinstance(v, bool)}

    def entry(self, app, point):
        """The ground-truth entry for this point, or None if it is not listed."""
        for e, rx in self.entries:
            if e["app"] != app or e["method"] != point.method or e["in"] != point.location or not rx.match(point.path):
                continue
            if point.location == "path":
                # v3: an entry may name its path segment ("seg": index in path.split("/")), so two
                # path parameters of one route (/v1/search/{filter}/{query}) are separate entries.
                if e["params"] and ("seg" not in e or point.param == "{seg%d}" % e["seg"]):
                    return e
            elif point.param in e["params"]:
                return e
        return None

    def label(self, app, point, payload_class):
        """'safe', the CWE, or None (unlisted endpoint, or class listed as unknown)."""
        e = self.entry(app, point)
        if e is None or payload_class in e.get("unknown", []):
            return None
        return payload_class if payload_class in e["vuln"] else "safe"

    def cluster(self, app, point, payload_class=None):
        """Bootstrap/LOAO cluster id: one per (app, endpoint, parameter). A parameter vulnerable to
        both ML classes (e.g. vulnerable-node /search?q: SQLi and XSS) gets one cluster per payload
        class ("...|q#CWE-89", "...|q#CWE-79"), so each cluster has a single true class."""
        e = self.entry(app, point)
        param = e["params"][0] if (e and point.location == "path") else point.param
        cid = f"{app}|{point.method}|{e['path'] if e else point.path}|{param}"
        if e and payload_class in ML_CLASSES and len(set(e["vuln"]) & set(ML_CLASSES)) > 1:
            cid += "#" + payload_class
        return cid

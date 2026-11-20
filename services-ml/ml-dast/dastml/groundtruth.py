"""Ground-truth lookup: map an injection point + payload class to a label (or None = drop)."""
import json
import re
from pathlib import Path

GT_PATH = Path(__file__).resolve().parents[1] / "data/dast/ground_truth.json"


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
        return tuple(s["path"] for s in self.data["skip"] if s["app"] == app)

    def entry(self, app, point):
        """The ground-truth entry for this point, or None if it is not listed."""
        for e, rx in self.entries:
            if e["app"] != app or e["method"] != point.method or e["in"] != point.location or not rx.match(point.path):
                continue
            if point.location == "path":
                if e["params"]:
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

    def cluster(self, app, point):
        """Bootstrap/LOAO cluster id: one per (app, endpoint, parameter)."""
        e = self.entry(app, point)
        param = e["params"][0] if (e and point.location == "path") else point.param
        return f"{app}|{point.method}|{e['path'] if e else point.path}|{param}"

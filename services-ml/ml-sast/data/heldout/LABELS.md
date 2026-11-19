# Held-out evaluation apps: labelling

These four deliberately vulnerable apps are **never** used for training, tuning, threshold selection or
template design. They are cloned at the pinned commits below into `data/heldout/<app>/` (gitignored) and
turned into function-level rows by `scripts/build_heldout.py`.

| App | Language | Commit | Paths in scope |
|---|---|---|---|
| [OWASP NodeGoat](https://github.com/OWASP/NodeGoat) | JavaScript | `c5cb68a7` | `app/`, `config/`, `server.js` |
| [DVNA](https://github.com/appsecco/dvna) | JavaScript | `9ba473ad` | `core/`, `routes/`, `models/`, `config/`, `server.js` |
| [vulpy](https://github.com/fportantier/vulpy) | Python | `5249cc8b` | `bad/`, `good/` |
| [PyGoat](https://github.com/adeyosemanputra/pygoat) | Python | `2aa4cc14` | `dockerized_labs/`, `introduction/`, `pygoat/settings.py` |

Tests, migrations, static/vendor assets, `node_modules`, vulpy's `utils/` attack scripts and PyGoat's
`challenge/` sandbox runner are out of scope.

## How labels were made

1. **Known issues first.** The candidates came from each project's own documentation:
   - DVNA's vulnerability list (A1–A10, `config/vulns.js`).
   - NodeGoat's OWASP Top 10 tutorial and the commented "Fix for A1…" blocks in its code.
   - vulpy's `bad/` vs `good/` diff.
   - PyGoat's lab names and "Vulnerable:" comments.
2. **Then hand checks.** Each candidate was confirmed by reading the code: the source reaches the sink
   with no effective sanitizer. For template XSS, the template was opened too, to confirm that
   `<%- %>`, `|safe` or `autoescape: false` is really present.
3. **Then a grep sweep for other sinks.** I grepped every in-scope file for the sinks of all 8 classes
   (SQL execute/raw, shell, file open/send, pickle/yaml, md5/sha1/random, secret literals) and labelled
   each hit by hand, vulnerable or not. This found issues the apps don't advertise:
   - `good/libuser.py` in vulpy still has SQL injection in `create()`.
   - Many hardcoded `SECRET_KEY`/API-key literals across the PyGoat labs.
4. **Labels point at a line.** Each label is an exact code substring (`match`) in `labels.json`, with a
   `ref` explaining it. The unit (function, or `<module>` for top-level code) that contains the line
   gets the CWE. Every other unit in scope is labelled `safe`.

## Label kinds

- **`cwe` / `cwes`:** a vulnerability in one of the 8 target classes. `cwes` is used when one function
  has two issues: vulpy `bad/libapi.py:keygen` uses weak randomness *and* puts the username into a file
  path. A prediction of either class counts as correct.
- **`exclude`:** a real issue outside the target classes, or a case I could not decide. Those units are
  left out of the metrics instead of being counted as `safe`.
  - Out-of-class issues: eval/code injection (CWE-95), NoSQL injection (CWE-943), SSRF (CWE-918),
    XXE (CWE-611), open redirect (CWE-601), IDOR (CWE-639) and SSTI (CWE-1336).
  - Ambiguous cases: seed-data SQL formatting from constants, a hardcoded seed password hash, and
    PyGoat XSS lab 3, whose template has no `|safe`.
- **`template_sink: true`:** the exploit lives in a template or template-engine setting, and the Python
  or JS function only passes tainted data along. There are 5 such units. They are reported both
  included and excluded ("code-visible only"), because a function-level model cannot see the template.

## Mapping decisions

- Weak randomness for tokens, OTPs or API keys (`random.*`, `Math.random`) is mapped to **CWE-327**,
  because that class means "broken or weak crypto" in this project. Strictly it is CWE-338.
- An MD5-derived reset token (DVNA) is also mapped to CWE-327.
- Hardcoded placeholder secrets such as `"your-secret-key-here"` count as **CWE-798**: they ship as
  the real configuration.

## Counts

Units after extraction (`scripts/build_heldout.py`; also in `data/manifest.json` under `heldout`):

| App | safe | CWE-89 | CWE-79 | CWE-78 | CWE-22 | CWE-798 | CWE-502 | CWE-327 | excluded |
|---|---|---|---|---|---|---|---|---|---|
| NodeGoat | 60 | 0 | 1 | 0 | 0 | 2 | 0 | 0 | 3 |
| DVNA | 27 | 1 | 2 | 1 | 0 | 1 | 1 | 2 | 4 |
| vulpy | 115 | 4 | 0 | 0 | 1 | 6 | 0 | 0 | 2 |
| PyGoat | 190 | 1 | 2 | 1 | 1 | 13 | 3 | 5 | 6 |

## Threats to validity

- **One labeller.** No second reviewer, so some unadvertised vulnerabilities may be labelled `safe`,
  which would show up as false positives.
- **Small numbers.** CWE-78, CWE-22 and CWE-502 have 2–4 vulnerable units each, so per-class held-out
  scores are very noisy. Macro-F1 is the headline number, and support is always reported.
- **Not representative.** The apps are deliberately vulnerable teaching code; real production code
  looks different.

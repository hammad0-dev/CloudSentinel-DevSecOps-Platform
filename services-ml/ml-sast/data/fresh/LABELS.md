# Fresh held-out apps (v2): labelling and freeze

These three apps are the **fresh held-out set** for ml-sast v2. They were cloned, labelled and frozen
**before** any v2 work started: before the secrets detector, the thresholds, the ensemble and the new
training data. They are never used for training, tuning or design, and are scored **exactly once** by
`scripts/eval_fresh_final.py`.

The v1 held-out apps (NodeGoat, DVNA, vulpy, PyGoat; `data/heldout/`) are the **development set** from
v2 on. Tuning on them is allowed and expected.

| App | Language | Commit | Paths in scope |
|---|---|---|---|
| [django.nV](https://github.com/nVisium/django.nV) | Python (Django) | `a48901f1` | `taskManager/` |
| [DVWS-node](https://github.com/snoopysecurity/dvws-node) | JavaScript (Express, GraphQL, SOAP) | `4221c04f` | `src/` (the Svelte/TS `frontend/` is out of scope) |
| [vulnerable-node](https://github.com/cr0hn/vulnerable-node) | JavaScript (Express) | `d68f2a3c` | `routes/`, `model/`, `middleware/`, `db/`, `config.js`, `server.js`, `sast/seeds/` |

## Freeze

`FREEZE.json` holds hashes of four things:
- `labels.json`;
- every in-scope source file (`sources_sha256`, 79 files);
- the built rows (`rows_sha256`);
- the pinned commits.

`scripts/build_heldout.py --set fresh` refuses (exit 1) if any of them changed, and
`scripts/eval_fresh_final.py` checks the freeze and refuses to run a second time.

## Method

The method is the same as for the development set (see `../heldout/LABELS.md`).

1. **Documented vulnerabilities first.**
   - django.nV's `# A1 - Injection` style comments.
   - DVWS-node's `README.md` and `CHALLENGES.md`.
   - vulnerable-node's lab table and `VULN (...)` comments, and for `sast/seeds/`, its own
     `ground-truth.yaml`.
2. **A grep sweep of every in-scope file** for the sinks of all 8 classes. Each hit was read and
   decided by hand.
3. **Each label is an exact code substring** in `labels.json`, with a `ref`. The unit containing that
   line gets the label, and every other unit is `safe`.

Notable decisions:

- **django.nV `misc.store_uploaded_file`** builds `os.system("mv " + ... + title)`. It is both command
  injection and path traversal, so `cwes: [CWE-78, CWE-22]`.
- **django.nV `settings.py`** has a hardcoded `SECRET_KEY` and an MD5 password hasher in the same
  `<module>` unit, so `cwes: [CWE-798, CWE-327]`.
- **Template-sink XSS** is flagged `template_sink: true`:
  - django.nV `search` and `task_details` (`|safe` in their templates);
  - vulnerable-node `routes/shop.js` search (`<%- q %>`).

  For stored XSS the *rendering* view is labelled.
- **Hardcoded secrets with an env fallback** count as CWE-798, for example
  `process.env.JWT_SECRET || "jwt-super-secret"`, because the literal ships as the default.
- **vulnerable-node `sast/seeds/`:**
  - Labelled from `ground-truth.yaml`, plus every other in-class sink in the same files (for example
    all three weak-crypto functions, and the command injection in `deserialization.js`).
  - Out-of-class seeds are excluded: eval, NoSQL, open redirect, prototype pollution, ReDoS and SSRF.
  - The placeholder `postgres://u:p@localhost/db` connection strings are excluded as ambiguous.
- **Excluded, out of class:**
  - Code injection (CWE-95), NoSQL injection (CWE-943), XPath (CWE-643), LDAP (CWE-90), XML/SOAP
    injection (CWE-91), XXE (CWE-611), SSRF (CWE-918), open redirect (CWE-601).
  - Mass assignment (CWE-915), JWT verification without pinned algorithms (CWE-347), and secrets in
    logs or log injection (CWE-532/117).
- **Excluded, ambiguous:**
  - django.nV `download` (an IDOR where the stored path is only indirectly attacker-controlled) and
    `tm_settings`.
  - DVWS `getPassphrase`, which concatenates with `sql.escape`.
  - vulnerable-node `updateProfile` (documented as mass assignment, though user keys also become
    column names), `logPaymentAttempt`, and the seed passwords.

## Counts

Built by `scripts/build_heldout.py --set fresh`. Counts are by first label.

| App | safe | CWE-89 | CWE-79 | CWE-78 | CWE-22 | CWE-798 | CWE-502 | CWE-327 | excluded |
|---|---|---|---|---|---|---|---|---|---|
| django.nV | 45 | 1 | 2 | 0 (+1 multi) | 1 | 0 (+1 multi) | 0 | 1 | 3 |
| DVWS-node | 141 | 2 | 0 | 1 | 3 | 0 | 2 | 0 | 10 |
| vulnerable-node | 91 | 5 | 4 | 2 | 3 | 4 | 1 | 3 | 24 |

That is 349 units in total: 35 vulnerable (3 of them template-sink cases), 277 safe and 37 excluded.

## Threats to validity

The same as for the development set: one labeller, small per-class counts, and deliberately
vulnerable teaching code.

The `sast/seeds/` files are tiny single-pattern examples written as scanner bait. They hold 15 of the
35 vulnerable units (and 48 of the 349 units), and are easier than real application code. Fresh-set
results are therefore reported both with and without the seed files.

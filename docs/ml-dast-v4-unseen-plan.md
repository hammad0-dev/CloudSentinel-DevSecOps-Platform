# ml-dast v4 on a new unseen app: candidate qualification (stopped: no candidate qualifies)

**Outcome: no candidate qualifies, so nothing was scanned.** No container was started, and nothing was frozen,
pre-registered, collected or scored. The deployment is unchanged: the engine on port 8002 serves v2
(`ml-dast-lr` 2.0.0, `5dc397d0b6c4…`). v3 and v4 stay packaged separately.

## Rules applied (from the task, unchanged)

- **Candidates, in order:** DSVPWA, XVNA, dvws-node, Broken Crystals.
- **Eligibility:** Python or Node.js, runnable in Docker, a license that permits use, and never used anywhere in
  this repo.
- **Qualification, decided from source before any scan:**
  - (a) at least 3 SQLi or reflected-XSS vulnerable parameters (combined) reachable without login;
  - (b) at least 8 safe parameters.

**How (b) was read.** The scored set is the reachable endpoint-params, so (b) was read as at least 8 parameters that
are reachable without login and safe for the ML classes (SQLi and reflected XSS). A safe parameter behind a login
cannot be scored and so cannot measure false alarms, which is what (b) is for. The DVPWA held-out failed for exactly
this reason. The counts under the looser readings are given below, so this reading can be overridden.

**Repo check:** a grep of `lab/`, `data/`, `reports/`, `docs/` and `services-ml/` (vendor sources excluded) found:
- DSVPWA and XVNA: no hits.
- dvws-node: used in ml-sast's fresh test set (`services-ml/ml-sast/data/fresh/LABELS.md:14`).
- Broken Crystals: one mention, as a rejected candidate in `docs/ml-dast-v3-plan.md:73`; never used.

## Per-candidate result

| Candidate | Eligible? | (a) vulnerable, no login | (b) safe and reachable | Result |
|---|---|---|---|---|
| DSVPWA (`mtawadrousv/DSVPWA` @ `276231dd`, MIT, Python `http.server`) | yes | **5** | **6** (8 only under the loosest reading) | **fails (b)** |
| XVNA (`vegabird/xvna`) | **no license** (GitHub reports none; the repo is a README plus `xvna.zip`) | not read | not read | **not eligible** |
| dvws-node (`snoopysecurity/dvws-node`) | **already used** (ml-sast fresh set) | not read | not read | **excluded** |
| Broken Crystals (`NeuraLegion/brokencrystals` @ `1765acfd`, MIT, NestJS/TypeScript) | yes | **≤ 2** | not counted (fails (a)) | **fails (a)** |

### DSVPWA (read in full: `dsvpwa.py`, `dsvpwa/{server,handlers,attacks}.py`, `db/attacks.xml`, `templates/*.html`)

**How the app works:**
- Every route is a `GET` with query parameters (`handlers.py:196-211`), and there is no login middleware.
- The routes come from `db/attacks.xml`. The run would use the default `--risk 1` (`dsvpwa.py:21`), which keeps the
  command-injection and pickle handlers switched off (`attacks.py:158`, `attacks.py:195`).
- The handler at `/settings` and the session-gated pages need a `SESSIONID` that maps to a logged-in user, so their
  parameters are not reachable without login.

| Endpoint, param | Label (from source) | Without login | Citation |
|---|---|---|---|
| `/users` `id` | CWE-89 | yes | `attacks.py:39` (string concatenation) |
| `/login` `password` | CWE-89 | yes (it is the login form) | `attacks.py:289` |
| `/post` `msg` | CWE-79 reflected | yes | `attacks.py:71`, inserted raw into the template |
| `/jump` `path` | CWE-79 reflected (and CWE-601) | yes | `attacks.py:122`, inside a JS string |
| `/home` `path` | CWE-79 reflected | yes | `attacks.py:237`, inside a JS string |
| `/login` `username` | safe | yes | `attacks.py:282` (`re.sub(r"[^\w]", '', …)`) |
| `/guestbook` `comment` | stored XSS (rule check); safe for the ML classes | yes | parameterised insert `attacks.py:88`, raw output `attacks.py:97` |
| `/docs` `path` | CWE-22 (and SSRF); safe for the ML classes | yes | `html.escape` at `attacks.py:215` |
| `/diag` `domain` | safe at risk 1 (CWE-78 at risk 3) | yes | `attacks.py:158` |
| `/extract` `object` | safe at risk 1 (CWE-502 at risk 3) | yes | `attacks.py:195` |
| `/home` `session` | session fixation (CWE-384); safe for the ML classes | yes | `attacks.py:231` |
| `/settings` `email` | stored XSS | **no** | `attacks.py:324`, `attacks.py:341`, `attacks.py:260` |
| `/settings` `firstname`, `lastname` | safe (ignored by the handler) | **no** | `attacks.py:333`, `attacks.py:337` |
| `/danger` `delete` | safe (a clickjacking/CSRF target, not an injection) | **no** | `attacks.py:387` |

**Counts:**
- (a) = 5.
- (b), safe for the ML classes and reachable = 6: username, comment, docs path, domain, object, session.

**Alternative readings of (b):**
- Counting the unreachable `firstname`, `lastname` and `delete` too: 8, excluding the two stored-XSS params.
- Counting only params with no vulnerability of any class: 3 reachable (6 in total).

Only the loosest combination reaches 8. One more weakness, recorded whatever the reading: DSVPWA is a single-file
`http.server` app in the style of DSVW, which is a training app, so it would also be weak evidence of generalization.

### Broken Crystals (read: all 13 controller files, plus the user, product, testimonial and partner services, and `main.ts`)

**Route guards:**
- 72 routes. `@UseGuards(AuthGuard)` guards `products` `GET /` and `GET /search` (`products.controller.ts:54`,
  `products.controller.ts:121`), the JWT validate routes, and most `users/one/*` routes.
- There is no global guard (`main.ts`, `app.module.ts`).
- The probe can send query, form, JSON and path parameters, but not headers (`dastml/probe.py:64-80`).

**SQLi and reflected XSS reachable without login:**
- `GET /api/testimonials/count` `query`: the parameter is executed as raw SQL (`testimonials.service.ts:61`), and
  errors come back as `text/html` (`testimonials.controller.ts:95`). This is **1 parameter**.
- `GET /api/products/views`, header `x-product-name`: SQLi without login, but **header-only**. The probe cannot send
  it. Counting it anyway gives 2.
- `GET /api/products/search` `name`: SQLi (`products.service.ts:59`), but **behind `AuthGuard`**.
- No server-side reflected XSS in HTML:
  - `subscriptions` returns `email` as a plain string (`subscriptions.controller.ts`), served as text/plain.
  - `partners/*` returns `text/xml` (XPath injection, a different class).
  - `/api/render` is template injection (`app.controller.ts:66-83`), a different class.
  - The remaining XSS in Broken Crystals is DOM-based, in the client app, which the probe does not execute.
- The other unguarded vulnerabilities are other classes: OS command (`/api/spawn`), XXE (`/api/metadata`),
  path traversal and SSRF (`/api/file*`), open redirect (`/api/goto`), LDAP (`/api/users/ldap`) and email header
  injection.

**(a) ≤ 2, so it fails.** Heaviness was not the deciding factor, but the compose file also pulls in Keycloak, Ollama,
mailcatcher and a gRPC proxy.

## What would let the test go ahead (not done; needs a decision)

1. **Accept the loosest reading of (b) for DSVPWA.** It has 8 ML-safe parameters if unreachable ones count, but only
   6 would actually be scored, so false-alarm evidence would be thin.
2. **Add more candidates to the list.** Examples are a Python or Node app with unauthenticated HTML forms, each still
   checked from source with the same rules.
3. **Add header injection points to the probe.** That would make Broken Crystals' `x-product-name` probe-able, but
   it is a code change, and it still gives only 2.

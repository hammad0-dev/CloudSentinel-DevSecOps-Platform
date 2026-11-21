# How to run an authenticated ml-dast scan

This guide is for running an ml-dast scan against a deployed app that needs a login. You call the ml-dast service
directly; the backend pipeline does not do authenticated scans yet (see the last section). The design is in
[`ml-dast-auth-plan.md`](ml-dast-auth-plan.md).

## 1. Put the credentials on the service side

Credentials are never sent in a scan request. Give the service a credential profile in one of two ways.

**Option A: environment variables** on the ml-dast process. `<REF>` is upper-case letters, digits and `_`.

```bash
export ML_DAST_AUTH_STAGING_USERNAME='demo'
export ML_DAST_AUTH_STAGING_PASSWORD='…'
export ML_DAST_AUTH_STAGING_ORIGINS='http://192.168.49.2:32707'   # the only origin(s) these credentials may go to
```

**Option B: a local JSON file**, named by `ML_DAST_AUTH_FILE`. Keep it outside the repository, or gitignored like
`services-ml/ml-dast/lab/auth.local.json`.

```json
{"STAGING": {"username": "demo", "password": "…", "origins": ["http://192.168.49.2:32707"]}}
```

**What the service enforces:**
- A profile with no `origins` is refused, and so is a scan whose target is not one of the profile's origins. Both
  are refused before any request is sent.
- The target must also pass the usual allowlist (`ML_DAST_ALLOWED_HOSTS`, `ML_DAST_ALLOWED_PORTS`).

## 2. Send the scan with an `auth` object

```bash
curl -s http://127.0.0.1:8002/scan -H 'Content-Type: application/json' -d '{
  "baseUrl": "http://192.168.49.2:32707/",
  "maxPages": 50, "maxRequests": 3000,
  "auth": {
    "loginPath": "/login",
    "method": "POST",
    "body": "form",
    "usernameField": "username",
    "passwordField": "password",
    "loginPagePath": "/login",
    "csrfField": "csrf_token",
    "success": {"cookie": "sid"},
    "loggedOut": {"redirectTo": "/login"},
    "credentialRef": "STAGING"
  }
}'
```

| Field | Meaning |
|---|---|
| `loginPath` (required) | Same-origin path the login is sent to |
| `method` | `POST` (default) or `GET` |
| `body` | `form` (default) or `json` |
| `usernameField`, `passwordField` | Field names; the defaults are `username` and `password` |
| `extraFields` | Up to 10 fixed, non-secret fields (for example `{"remember": "1"}`) |
| `loginPagePath`, `csrfField` | Page fetched before the login, and the hidden input to copy from its form (`auto` tries the common names) |
| `success` (required) | One of: `{"cookie": name}`, `{"text": "shown after login"}`, `{"tokenJson": "token"}`. The last is a JSON login whose token is then sent as `Authorization: Bearer …` |
| `loggedOut` | Signs that the session expired, which trigger one re-login and one resend: `status` (for example `[401]`), `redirectTo` (default: `loginPath`), `text`, `loginRedirect: false` (when the login form is at `/`) |
| `credentialRef` (required) | Name of the credential profile from step 1 |
| `maxRelogins` | Cap on re-logins per scan (default 20, at most 200) |

**What comes back:**
- **On success:** the same `findings` and `coverage` as an unauthenticated scan. `coverage.auth` adds the number of
  logins and re-logins.
- **On failure:** a login that fails, or credentials that cannot be resolved for the target, answer HTTP 400. The
  error message never contains a credential.

## 3. What an authenticated scan never does

- **Logout:** it never requests logout links.
- **Destructive actions:** it never deletes data or accounts, changes or resets a password, or resets a database.
  - **Matched on:** a word on the destructive-action list in the request path, a query-parameter name, or a form's
    action. Links and forms whose text names such an action are also skipped.
  - **Method:** it never sends `DELETE`.
  - **The list:** `dastml/auth.py` (`DESTRUCTIVE_WORDS`), documented in the plan, section 3.
- **Other hosts:** it never sends credentials anywhere except the allowlisted target's origin. It never follows
  redirects to another host, and never sends a parameter value that carries a URL.

## 4. Limits

- **CSRF tokens:**
  - **Session-bound tokens:** work; the value seen in the crawl is reused.
  - **Rotating tokens:** tokens that change on every request, or that a re-login invalidates, are not refreshed per
    probe.
- **No multi-step logins:** MFA, OTP, CAPTCHA and SSO redirects to another origin are not supported.
- **API apps need seeds:** a single-page app's API still needs `seedPaths` or `openapiUrl`, because a login does not
  make its endpoints crawlable.
- **The passive header checks** still fetch pages without cookies, as before.
- **The model is unchanged.** Authentication only changes which pages and parameters are reached. Results on pages
  behind a login are only as good as the model is on those apps; see the model card.

## 5. Why the backend pipeline does not do this yet

Authenticated scans from the pipeline need per-project credential storage. That needs its own security design:
- encryption at rest;
- who may read, rotate or delete a credential;
- an audit trail;
- binding each credential to the project's verified staging origin;
- keeping credentials out of pipeline logs and job payloads.

Until that exists, authenticated scans are run against the ml-dast service directly, as above.

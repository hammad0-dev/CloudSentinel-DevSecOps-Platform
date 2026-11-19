# CloudSentinel Python Clean Fixture

Vulnerability-free Flask app expected to pass every CloudSentinel gate (SAST, Dependency, IaC) and reach Deploy and DAST.

Differences from `cloudsentinel-test-python-flask`, which Sonar blocks:
- CSRF protection enabled with Flask-WTF (`python:S4502`).
- Secret key read from `FLASK_SECRET_KEY` via `from_prefixed_env()` (`python:S2068`); only GET routes exist, so CSRF needs no key at runtime.
- Served by waitress instead of the Flask dev server bound to `0.0.0.0` (`python:S8392`).

Run locally: `pip install -r requirements.txt && python app.py`, then `curl http://127.0.0.1:8080/health`.

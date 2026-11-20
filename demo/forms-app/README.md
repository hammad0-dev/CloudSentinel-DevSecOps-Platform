# cloudsentinel-demo-forms

A small Flask catalogue with a feedback form: the target for the CloudSentinel ML DAST demo.

**Intentionally vulnerable.** Run it only on localhost or in an isolated staging cluster; never
expose it to the internet.

| Endpoint | Input | Status |
|---|---|---|
| `GET /search?q=` | query parameter `q` | **SQL injection (CWE-89)**: the term is concatenated into SQL |
| `GET /search-safe?q=` | query parameter `q` | safe twin: parameterized query |
| `POST /feedback` | form fields `name`, `message` | **reflected XSS (CWE-79)** in `name` (`message` is not echoed) |
| `POST /feedback-safe` | form fields `name`, `message` | safe twin: escaped by the template engine |

All endpoints are reachable from HTML links and forms on `/`, so a crawler needs no seeds.
SQLite lives in `/tmp` (the container's root filesystem is read-only); there are no secrets.

Run locally: `pip install -r requirements.txt && python app.py` (http://127.0.0.1:8080).
Container: `docker build -t demo-forms:0.1.0 . && docker run --rm -p 8080:8080 demo-forms:0.1.0`.
Kubernetes: `k8s/` holds a hardened Deployment and NodePort Service (non-root, read-only root
filesystem, all capabilities dropped, resource limits); `k8s/.appname` tells the CloudSentinel
pipeline which Deployment is the application.

# cloudsentinel-test-flask-postgres

Two-tier fixture for the EKS generator: a Flask API (waitress on 8080) that reads its PostgreSQL connection from
environment variables. Expected classification: `two-tier`, one `app` component, RDS `postgres`.
No credentials are in this repository; `/db` reports the connected user and `/secret-fingerprint` a 12-character
hash of the mounted secret, never a value.

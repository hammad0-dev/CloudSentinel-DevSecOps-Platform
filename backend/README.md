# CloudSentinel backend (Ubuntu)

Backend targets Ubuntu Node.js (`HOST=http://localhost:<PORT>`). SonarQube runs on the same machine at `http://localhost:9000`; clones land under `CLONE_DIR` (Linux-friendly paths via Node.js `path`).

## Ubuntu setup

**Step 1:** sudo apt install nodejs npm postgresql git

**Step 2:** Install sonar-scanner to `/opt/sonar-scanner` and add it to `PATH`.

**Step 3:** Setup PostgreSQL database:

```sql
CREATE DATABASE cloudsentinel;
CREATE USER csuser WITH PASSWORD 'cspassword123';
GRANT ALL PRIVILEGES ON DATABASE cloudsentinel TO csuser;
```

Apply your schema (e.g. repo `schema.sql`) according to how you bootstrap the DB.

**Step 4:** Configure `.env`, then from this directory run:

```bash
npm install
```

**Step 5:**

```bash
npm run dev
```

**Step 6:** Verify at http://localhost:3000/health  

(`GET /api/health` returns the same JSON.)

## Split dev (Windows frontend)

Point the frontend `BASE_URL` at your Ubuntu LAN IP (`http://<ubuntu-ip>:3000/api`) and ensure `server.js` allows your Vite `Origin`. Replace `http://YOUR_WINDOWS_IP:5173` with your PC’s LAN address if needed.

### SAST classification schema

If SAST reports `column "issue_type" of relation "scan_results" does not exist`,
apply the existing additive classification migration from the repository root:

```bash
npm run migrate:sast -w cloudsentinel-backend
```

Migration 016 adds `issue_type` and `hotspot_review` plus validation constraints.
It is repeatable and preserves historical rows as `UNKNOWN` / `NOT_APPLICABLE`.
No backend restart is required for these columns. Failed pipeline executions remain
historical; retry the project's webhook to create a new execution.

The actual persistence path can be checked without scanning or public test data:

```bash
npm run test:sast:db -w cloudsentinel-backend
```

This uses a temporary isolated PostgreSQL schema and removes it afterward.

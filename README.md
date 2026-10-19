# CloudSentinel

CloudSentinel is a modular DevSecOps security platform for onboarding GitHub repositories, running SAST and dependency scans, generating SBOMs, and visualizing risk/compliance insights in a modern web dashboard.

Break it. Scan it. Reproduce it. Benchmark against it. Improve it.

---

## What Makes It Different

Unlike static demo dashboards, CloudSentinel is built as a testable security workflow:

- Real scan execution (`git clone` + build + scanner), not fake sample rows.
- Deterministic scan lifecycle tracking (`RUNNING -> COMPLETED / FAILED`).
- Combined compliance view from both SAST findings and dependency CVEs.
- SBOM-backed dependency visibility with exportable reports.
- Modular architecture so frontend, backend, SAST, and dependency modules can evolve independently.

---

## What We Have Implemented

### Frontend

- React + Vite application with protected routes and JWT session flow.
- Auth screens: login, register, forgot password, reset password.
- Project management UI: add/list/view/delete repositories.
- SAST results view with findings + Sonar metrics.
- Dependency dashboard with vulnerabilities, package inventory, license summary, and SBOM export access.
- Compliance dashboard combining SAST + dependency findings.

### Backend

- Node.js + Express API with PostgreSQL persistence.
- JWT authentication, user profile endpoints, password reset flow.
- Project onboarding and scan history APIs.
- Health endpoints (`/health`, `/api/health`) and boot-time stale scan cleanup.

### SAST Module

- Real SonarQube pipeline:
  - clone repository with non-interactive Git auth support,
  - detect/build Java (Maven) and Gradle layouts when needed,
  - run `sonar-scanner`,
  - ingest Sonar issues into `scan_results`,
  - compute and persist security score.
- Scan orchestration persisted in `scan_history` with single-row status transitions.
- Sonar metric retrieval for reporting and dashboard cards.

### Dependency + SBOM Module

- Real Trivy-based dependency scanning (`trivy fs`).
- CycloneDX SBOM generation and download endpoint.
- Results persisted in:
  - `dependency_scans` (run metadata + severity totals),
  - `sbom_components` (packages, versions, CVEs, severities, licenses, fix versions).
- Dependency report API for frontend export and analytics.

### Compliance Mapping

- OWASP and CIS mapping built from SAST findings.
- Dependency findings merged into compliance controls.
- Unified compliance score + control coverage summary.

---

## Architecture

| Layer | Main Tech | Purpose |
|---|---|---|
| Frontend | React, Vite, Tailwind, Recharts | Dashboards, project/scan UX, exports |
| Backend | Node.js, Express | Auth, project APIs, scan orchestration, reports |
| Database | PostgreSQL | Users, projects, scans, findings, SBOM components |
| SAST Engine | SonarQube + Sonar Scanner | Static analysis and code metrics |
| Dependency Engine | Trivy | Dependency CVEs, package inventory, SBOM |

---

## Repository Layout

```text
cloudsentinel/
├── frontend/
│   ├── src/
│   │   ├── pages/
│   │   ├── components/
│   │   ├── context/
│   │   └── lib/
│   └── .env.example
├── backend/
│   ├── routes/
│   │   ├── auth.js
│   │   ├── projects.js
│   │   ├── dependency.js
│   │   └── sast/              # index.js, pipeline.js, config.js, compliance.js, metrics.js
│   ├── middleware/
│   ├── server.js
│   ├── db.js
│   ├── .env.windows.example
│   └── .env.ubuntu.example
├── schema.sql
└── README.md
```

---

## Running The Project

You can run CloudSentinel in local split mode (frontend and backend on same or different hosts).

### Prerequisites

- Node.js 18+
- PostgreSQL 15+
- Git CLI
- SonarQube server
- Sonar Scanner CLI
- Trivy
- (For Java repos) JDK 17+

### 1) Install Dependencies

From project root:

```bash
npm install
```

### 2) Configure Environment

Backend (`backend/.env`):

- `PORT=3000`
- `JWT_SECRET=...`
- `SONAR_HOST=http://<sonar-host>:9000`
- `SONAR_TOKEN=<real_sonar_token>`
- `CLONE_DIR=<absolute_path>`
- `DATABASE_URL=postgresql://...` (or `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, `DB_PASSWORD`)
- Optional: `GITHUB_TOKEN`, `SAST_KEEP_CLONE`, `SONAR_ENABLE_BRANCH_ANALYSIS`, `TRIVY_CMD`

Frontend (`frontend/.env`):

- `VITE_API_BASE_URL=http://<backend-host>:3000/api`
- `VITE_GOOGLE_CLIENT_ID=<optional>`

### 3) Setup Database

```sql
CREATE DATABASE cloudsentinel;
CREATE USER csuser WITH PASSWORD 'your_password';
GRANT ALL PRIVILEGES ON DATABASE cloudsentinel TO csuser;
```

Apply schema:

```bash
psql -U postgres -d cloudsentinel -f schema.sql
```

### 4) Start Services

Run both frontend + backend:

```bash
npm run dev
```

Or run separately:

```bash
cd backend && npm run dev
cd frontend && npm run dev
```

### 5) Open Application

- Frontend: `http://localhost:5173`
- API health: `http://localhost:3000/api/health`

---

## Core API Modules

Base prefix: `/api`

### Auth

- `POST /auth/register`
- `POST /auth/login`
- `GET /auth/me`
- `PATCH /auth/profile`
- `POST /auth/forgot-password`
- `POST /auth/reset-password`

### Projects

- `POST /projects/analyze`
- `POST /projects`
- `GET /projects`
- `GET /projects/:id`
- `GET /projects/:id/scans`
- `DELETE /projects/:id`

### SAST

- `POST /sast/scan/:projectId`
- `GET /sast/:projectId`
- `GET /sast/compliance/:projectId`
- `GET /sast/report/:projectId`
- `GET /sast/analytics/overview`

### Dependencies & SBOM

- `POST /dependencies/scan/:projectId`
- `GET /dependencies/:projectId`
- `GET /dependencies/report/:projectId`
- `GET /dependencies/sbom/:projectId`

---

## Scan Pipeline Behavior

### SAST

1. Insert `scan_history` row as `RUNNING`.
2. Clone repository into `CLONE_DIR`.
3. Build Java/Gradle projects when needed.
4. Execute `sonar-scanner`.
5. Fetch Sonar issues + metrics.
6. Replace `scan_results`.
7. Update security score and mark scan `COMPLETED` (or `FAILED` on error).

### Dependency + SBOM

1. Insert `dependency_scans` row as `RUNNING`.
2. Clone repository into temporary scan directory.
3. Run `trivy fs` for vulnerability + license data.
4. Generate CycloneDX SBOM.
5. Persist `sbom_components` + scan summary.
6. Mark dependency scan `COMPLETED` (or `FAILED` on error).

---

## Benchmarking and Reproducibility

CloudSentinel is designed for repeatable security testing workflows:

- Re-run scans on the same repository and compare severity trends.
- Validate scanner behavior against known vulnerable targets.
- Use saved scan history for security regression checks across changes.
- Export SAST/dependency report payloads and SBOM artifacts for audit evidence.

---

## Technologies Used

- JavaScript / TypeScript
- React + Vite
- Node.js + Express
- PostgreSQL
- SonarQube + Sonar Scanner
- Trivy
- JWT Authentication

---

## Troubleshooting Quick Notes

- `Cannot find module 'express'`: run `npm install` in root or backend.
- Sonar unauthorized: verify `SONAR_TOKEN`.
- Sonar zero LOC: check repository URL/branch and scan host plugin setup.
- Git clone auth prompt/hang: configure valid `GITHUB_TOKEN` or project PAT.
- Dependency scan too slow/timeouts: adjust `DEP_TRIVY_TIMEOUT_MS` and ensure Trivy DB is up to date.
- Java scanning issues: ensure JDK 17+ is available on scan host.

---

## Security Notes

- Never commit `.env` files or real secrets.
- Rotate tokens/passwords if exposed.
- Use least-privilege credentials.
- Use HTTPS and production-grade secret management for deployment.

---

## Contributing

PRs are welcome.

Ways to contribute:

- Add new vulnerability mapping logic.
- Improve scanner orchestration and reliability.
- Enhance frontend reporting and analytics UX.
- Expand dependency/SBOM insights and compliance coverage.

---

CloudSentinel is built for automation, reproducibility, and continuous security improvement across frontend, backend, SAST, dependency, and SBOM workflows.
# CloudSentinel

CloudSentinel is a full-stack DevSecOps platform for registering GitHub repositories, running SAST scans with SonarQube, storing findings in PostgreSQL, and visualizing security/compliance analytics in a React frontend.

---

## What Is Implemented

- JWT auth (email/password), Google sign-in, forgot/reset password.
- Project onboarding (GitHub repo + optional PAT), project listing, project details, delete.
- Real SAST execution pipeline (`git clone` -> optional Maven build -> `sonar-scanner` -> ingest issues -> compute score).
- Scan lifecycle tracking with `RUNNING -> COMPLETED/FAILED` in `scan_history`.
- Sonar-backed metrics in UI (bugs, vulnerabilities, hotspots, smells, coverage, duplications, LOC).
- OWASP Top 10 + CIS mapping from findings.
- Security/compliance report export (readable HTML + JSON technical export).
- Dashboard and compliance analytics pages wired to live project/scan data.

---

## Architecture

| Layer | Main Tech | Purpose |
|---|---|---|
| Frontend | React + Vite + Tailwind + Recharts | Dashboards, project management, scan views, compliance/reporting UI |
| Backend | Node.js + Express | Auth, project APIs, scan orchestration, metrics/compliance/report APIs |
| Database | PostgreSQL | Users, projects, scan history, scan results, reset tokens |
| SAST Engine | SonarQube + Sonar Scanner CLI | Static analysis and issue/metrics source |

### Split deployment support

CloudSentinel supports split environments (for example, frontend on Windows, backend + SonarQube + PostgreSQL on Ubuntu).  
Make sure frontend points to the correct backend via `VITE_API_BASE_URL`.

---

## Supported Languages

From your current SonarQube plugin set and backend flow, scans are compatible with:

- Java
- Python
- JavaScript / TypeScript / CSS
- C# / VB.NET
- Go
- PHP
- Kotlin
- Ruby
- Scala
- HTML / XML
- IaC-related config files
- Generic text/config analyzers

> Note: Java projects require compiled classes. Backend handles this by running Maven build when `pom.xml` is detected.

---

## Repository Layout

```text
cloudsentinel/
├── frontend/
│   ├── src/
│   │   ├── pages/
│   │   ├── components/
│   │   ├── context/
│   │   ├── lib/ + utils/
│   │   └── styles.css
│   ├── .env
│   └── .env.example
├── backend/
│   ├── routes/
│   │   ├── auth.js
│   │   ├── projects.js
│   │   └── sast/            # index.js, pipeline.js, config.js, compliance.js, metrics.js
│   ├── middleware/
│   ├── server.js
│   ├── db.js
│   ├── .env
│   ├── .env.windows.example
│   └── .env.ubuntu.example
├── schema.sql
└── README.md
```

---

## Prerequisites

- Node.js 18+
- PostgreSQL 15+
- SonarQube server
- Sonar Scanner CLI
- Git CLI
- (For Java repos) JDK 17+ on scan server

---

## Environment Configuration

## Backend (`backend/.env`)

Required:

- `PORT=3000`
- `JWT_SECRET=...`
- `SONAR_HOST=http://<sonar-host>:9000`
- `SONAR_TOKEN=<real_sonar_token>`
- `CLONE_DIR=<absolute_path>`
- DB config via either:
  - `DATABASE_URL=postgresql://...`
  - or `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, `DB_PASSWORD`

Recommended:

- `GITHUB_TOKEN=<github_pat>` (for private repos/rate limits)
- `SAST_KEEP_CLONE=true|false` (debugging clone artifacts)
- `SONAR_ENABLE_BRANCH_ANALYSIS=true|false` (keep false on Community Edition)
- `MAVEN_CMD=mvn` (optional Maven command override)

Optional auth/email:

- `GOOGLE_CLIENT_ID`
- `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `SMTP_FROM`
- `FRONTEND_URL=http://localhost:5173`

## Frontend (`frontend/.env`)

- `VITE_API_BASE_URL=http://<backend-host>:3000/api`
- `VITE_GOOGLE_CLIENT_ID=<google_web_client_id>` (for Google button)

After changing frontend env, restart Vite dev server.

---

## Database Setup

```sql
CREATE DATABASE cloudsentinel;
CREATE USER csuser WITH PASSWORD 'your_password';
GRANT ALL PRIVILEGES ON DATABASE cloudsentinel TO csuser;
```

Then apply schema:

```bash
psql -U postgres -d cloudsentinel -f schema.sql
```

For PostgreSQL 15+ schema permission issues, connect specifically to `cloudsentinel` DB and grant on `public` schema there.

---

## After `git clone` (required)

This repository does **not** include **`node_modules`**. If you skip install you will see **`Cannot find module 'express'`** (or similar).

**Option A — monorepo root (recommended after clone):**

```bash
cd CloudSentinel
npm install          # installs root + backend + frontend workspaces
npm run dev:backend  # or: cd backend && npm run dev
```

**Option B — backend only:**

```bash
cd CloudSentinel/backend
npm install
npm run dev
```

---

## Run Locally

## Backend

```bash
cd backend
npm install
npm run dev
```

Health check:

```bash
curl http://localhost:3000/health
```

## Frontend

```bash
cd frontend
npm install
npm run dev
```

Open:

- `http://localhost:5173/`
- `http://localhost:5173/landing`

---

## API Overview

Base prefix: `/api`

## Auth

- `POST /auth/register`
- `POST /auth/login`
- `POST /auth/google`
- `POST /auth/github/exchange`
- `POST /auth/forgot-password`
- `POST /auth/reset-password`
- `GET /auth/me`
- `PATCH /auth/profile`

## Projects

- `POST /projects/analyze`
- `POST /projects`
- `GET /projects`
- `GET /projects/:id`
- `GET /projects/:id/scans`
- `DELETE /projects/:id`

## SAST

- `POST /sast/scan/:projectId`
- `GET /sast/:projectId`
- `GET /sast/compliance/:projectId`
- `GET /sast/report/:projectId`
- `GET /sast/analytics/overview`

---

## SAST Pipeline (Current Behavior)

1. Create `scan_history` row as `RUNNING`.
2. Clone repository into `CLONE_DIR/<projectId>`.
3. If Java project (`pom.xml`), run Maven build (`mvnw`/`mvn`) before scanner.
4. Run `sonar-scanner` from cloned repo (`sonar.projectBaseDir`, `sonar.sources=.`).
5. Validate Sonar indexed code (`ncloc` + `files` > 0).
6. Pull issues from Sonar API.
7. Replace `scan_results` rows for the project.
8. Update scan summary in `scan_history`.
9. Mark scan `COMPLETED` or `FAILED`.
10. Cleanup clone dir unless `SAST_KEEP_CLONE=true`.

---

## Severity Summary

Latest completed scan severity counts are stored in `scan_history` (`critical`, `high`, `medium`, `low`) and used by dashboards/reports.

---

## Compliance & Reporting

CloudSentinel maps SAST findings into:

- OWASP Top 10 controls
- CIS Controls categories

Report exports:

- **Readable report**: HTML
- **Technical report**: JSON

Compliance page is project-selectable and backed by live data from `scan_results`.

---

## Frontend Routes

- `/` and `/landing` - marketing landing
- `/login`, `/register`, `/forgot-password`, `/reset-password`
- `/dashboard`
- `/projects`
- `/projects/:id`
- `/projects/:id/sast`
- `/projects/:id/dast`
- `/cicd`, `/dependencies`, `/iac`, `/cloud`, `/kubernetes`, `/compliance`, `/monitoring`, `/secrets`
- `/settings`

---

## Troubleshooting

## `psql` not recognized on Windows

Use full path to `psql.exe` or run DB commands from Ubuntu/PostgreSQL host.

## Sonar says no lines of code

- Verify clone contains source files.
- Confirm correct branch and repo URL.
- Ensure scanner points to cloned source directory.

## Community edition branch error

If Sonar rejects `sonar.branch.name`, keep:

- `SONAR_ENABLE_BRANCH_ANALYSIS=false`

## Java scan fails

- `sonar.java.binaries` errors: ensure Maven build produces `target/classes`.
- `release version 17 not supported`: install/select JDK 17 on scan host.
- `spawn ./mvnw EACCES`: run wrapper via `sh mvnw ...` (already implemented).

## Google login issues

- Frontend needs valid `VITE_GOOGLE_CLIENT_ID`.
- Backend needs valid `GOOGLE_CLIENT_ID`.
- Ensure both are from same Google OAuth app setup.

---

## Security Notes

- Never commit `.env` or real secrets.
- Rotate tokens/passwords if exposed.
- Use HTTPS in production.
- Use least-privilege PATs and DB credentials.

---

## Current Maturity

CloudSentinel currently provides an operational end-to-end SAST and compliance workflow suitable for FYP/demo and iterative production hardening.
# CloudSentinel

Full-stack **DevSecOps / security dashboard**: register GitHub projects, run **SAST** via **SonarQube** (`sonar-scanner`), store findings and scores in **PostgreSQL**, and browse results in a **React (Vite)** UI.

This README documents **everything implemented to date**, **split Windows ↔ Ubuntu deployment**, **errors we hit and how they were fixed**, and **how to resume work tomorrow**.

---

## Table of contents

1. [Architecture (current)](#architecture-current)
2. [Tech stack](#tech-stack)
3. [Repository layout](#repository-layout)
4. [What we built (feature list)](#what-we-built-feature-list)
5. [Behaviour changes & fixes (session history)](#behaviour-changes--fixes-session-history)
6. [Environment configuration (full detail)](#environment-configuration-full-detail)
7. [Database (PostgreSQL 15+ notes)](#database-postgresql-15-notes)
8. [Run the stack](#run-the-stack)
9. [SAST pipeline (step-by-step)](#sast-pipeline-step-by-step)
10. [SonarQube: “no lines of code” / branch mismatch](#sonarqube-no-lines-of-code--branch-mismatch)
11. [Where scan results appear](#where-scan-results-appear)
12. [HTTP API](#http-api)
13. [Frontend routes](#frontend-routes)
14. [Debugging from Ubuntu terminal](#debugging-from-ubuntu-terminal)
15. [Troubleshooting (expanded)](#troubleshooting-expanded)
16. [Git workflow](#git-workflow)
17. [Resume tomorrow (checklist)](#resume-tomorrow-checklist)
18. [Security](#security)

---

## Architecture (current)

| Piece | Where it usually runs | Role |
|--------|------------------------|------|
| **Frontend (Vite)** | Windows (or Ubuntu if you run Vite there) | Browser UI, typically `http://localhost:5173` |
| **Backend (Express)** | Ubuntu VM and/or Windows | REST API on **`PORT`** (e.g. **3000**), JWT auth, DB, orchestrates **`git clone`** + **`sonar-scanner`** |
| **PostgreSQL** | Same machine as the backend you are using | App data: users, projects, scans, issues |
| **SonarQube** | Often the same Ubuntu host as the backend | Web UI **`http://localhost:9000`** on that host; scan analysis + issue API |

**Important:** There are **two separate Postgres databases** if you run the backend on **both** Windows and Ubuntu — users/projects on Windows are **not** the same rows as on Ubuntu unless you replicate data.

The frontend targets one API via **`VITE_API_BASE_URL`** in **`frontend/.env`** (must include **`/api`**, e.g. `http://192.168.141.128:3000/api`).

**CORS** is set in **`backend/server.js`** (`allowedOrigins`). Add your Windows LAN origin if you open the app as `http://<windows-ip>:5173`. Replace the placeholder **`http://YOUR_WINDOWS_IP:5173`** with your real IP.

---

## Tech stack

- **Frontend:** React (Vite), React Router v6, Tailwind CSS, Axios, React Hot Toast, Lucide, Recharts (where used).
- **Backend:** Node.js, Express, `pg`, JWT, bcrypt, Axios, Nodemailer; optional Google/GitHub OAuth routes in **`auth.js`** (primary flow is email/password).
- **Database:** PostgreSQL — **`schema.sql`** at repo root.
- **Analysis:** Git CLI + Sonar Scanner CLI → SonarQube Web API (`/api/issues/search`) → stored in **`scan_results`**.

---

## Repository layout

```text
cloudsentinel/
├── frontend/
│   ├── .env                      # VITE_API_BASE_URL (gitignored)
│   ├── .env.example
│   └── src/
│       ├── lib/api.js            # Axios: baseURL from import.meta.env.VITE_API_BASE_URL
│       ├── utils/api.js          # Re-exports lib/api.js
│       └── pages/                # Login, Register, Projects, ProjectDetails, SASTResults, ...
├── backend/
│   ├── server.js                 # dotenv path; CORS; mounts /api/auth, /api/projects, /api/sast
│   ├── db.js                     # DATABASE_URL or DB_* vars
│   ├── middleware/auth.js
│   ├── routes/auth.js
│   ├── routes/projects.js        # analyze, CRUD, scans list (fake /projects/:id/scan removed)
│   ├── routes/sast/            # git clone, sonar-scanner, issues ingest, RUNNING→COMPLETED/FAILED
│   ├── .env                    # machine-specific (gitignored)
│   ├── .env.windows.example
│   └── .env.ubuntu.example
├── schema.sql
├── .gitignore                    # .env, node_modules
└── README.md                     # This file
```

---

## What we built (feature list)

### Authentication

- Register with **full name**, **email**, **password** (hashed with bcrypt).
- Login returns **JWT**; frontend stores it as **`cloudsentinel_token`** in **`localStorage`**.
- **Forgot / reset password** via email when SMTP is configured (otherwise reset link may be logged server-side for dev).
- **`GET /api/auth/me`** for session bootstrap.

### Registration UX (explicit change)

- After **successful register**, the app **does not** auto-login or redirect to the dashboard.
- It shows a success toast, then **`navigate("/login", { state: { email } })`** so the user **signs in manually**.
- The login page **prefills email** when arriving from registration (`location.state.email`).

### Projects

- **Add project:** name, **HTTPS GitHub URL**, optional **GitHub PAT** (stored per project for private repos / clone).
- **`POST /api/projects/analyze`** — calls GitHub API to infer stack/language from **`package.json`**, **`requirements.txt`**, **`pom.xml`**, etc., where present.
- **`GET /api/projects`** includes **`latestScan`** summary per project for the UI.
- **Delete project** supported.

### SAST

- **Only real scan endpoint:** **`POST /api/sast/scan/:projectId`** (authenticated).
- **Removed** the old dummy **`POST /api/projects/:id/scan`** that inserted fake “completed” rows without running Sonar.
- **Project details** and **projects list** “Scan” buttons call **`/sast/scan/:id`**, then refresh project data from the API.
- Clone directory: **`CLONE_DIR`** env (Linux: e.g. **`/tmp/cloudsentinel-scans/<projectId>`**; Windows: e.g. **`D:/temp/cloudsentinel-scans/<projectId>`**).
- Java repos (**`pom.xml`** present) are automatically built before scan (`mvnw`/`mvn`) so Sonar Java analysis has **`target/classes`**.
- Sonar branch analysis is gated by env **`SONAR_ENABLE_BRANCH_ANALYSIS=true`** (disabled by default for Community Edition compatibility).
- Optional debug mode: **`SAST_KEEP_CLONE=true`** keeps clone folders after scan for investigation.

### Dependency & SBOM (Module 6)

- Implemented real dependency scanning with **Trivy** via **`POST /api/dependencies/scan/:projectId`**.
- Backend runs both:
  - **Vulnerability scan** (`trivy fs --format json`)
  - **SBOM generation** (`trivy fs --format cyclonedx`)
- Stored data model:
  - **`dependency_scans`** (run status + severity totals + sbom payload)
  - **`sbom_components`** (package, version, CVE, severity, CVSS, fixed version, description)
- Frontend **Dependencies** page includes:
  - Vulnerabilities table
  - All packages and license views
  - SBOM tree
  - HTML export report + SBOM export endpoint integration
- Implemented robust scan-dir handling (unique temp clone dirs per scan) to avoid concurrent scan path conflicts.

### Compliance mapping (combined sources)

- Compliance dashboard is now based on **both**:
  - SAST findings from `scan_results`
  - Dependency CVE findings from `sbom_components`
- Dependency findings are mapped into:
  - **OWASP A06:2021 (Vulnerable Components)**
  - **CIS-2 (Software Asset / dependency control)**
- Compliance summary now exposes source split:
  - `sastFindings`
  - `dependencyFindings`

### UI system refresh (enterprise blue)

- Global frontend color tokens were migrated to a blue enterprise palette in `frontend/src/styles.css`.
- Auth and landing experiences were redesigned to consistent split-panel enterprise layouts:
  - `Login`
  - `Register`
  - `ForgotPassword`
  - `ResetPassword`
  - `Landing`

### Scan history semantics (explicit change)

- Each scan creates **one** **`scan_history`** row with status **`RUNNING`**, then **`UPDATE`**s that same row to **`COMPLETED`** (with issue counts) or **`FAILED`** on error — **no second INSERT** for completion (avoids duplicate rows and confusing ordering).
- Frontend maps **`FAILED`** to a **Failed** badge (red).

---

## Behaviour changes & fixes (session history)

These are the concrete fixes so you remember **why** the code looks the way it does:

| Problem | Root cause | What we changed |
|---------|------------|------------------|
| **`Username for 'https://github.com':`** on Ubuntu | `git clone` over HTTPS without PAT; blocking **`execSync`** | PAT embedded via **`x-access-token`** URL; **`GIT_TERMINAL_PROMPT=0`**, **`GIT_ASKPASS=/bin/false`** on Linux; **`spawn`** instead of blocking sync where needed |
| Frontend stuck **“Loading project…”** | **`spawnSync`/`execSync`** blocked the **entire Node event loop** during clone/Sonar | **`gitCloneAsync`**, **`runSonarScannerAsync`** using **`child_process.spawn`** + Promises so **GET /projects/:id** can respond during a scan |
| **Sonar “Not authorized”** / token shown as **`PASTE_SONAR_USER_TOKEN`** | **`SONAR_TOKEN`** in **`.env`** left as template text | Set a **real** Sonar user token from Sonar UI (**My Account → Security → Tokens**) |
| **`scan_results` empty** + **`Invalid token`** with curl | Used literal **`YOUR_JWT`** / wrong project id; or scan never completed | Use JWT from **`POST /api/auth/login`** or browser **`localStorage`**; use numeric **`project_id`** in **`/api/sast/:id`** |
| **Sonar UI: “The main branch has no lines of code”** while **GitHub `main` has files** | Wrong repo registered, clone empty, wrong branch, or Sonar branch/plugin mismatch | Verify **registered URL** matches repo; **`GIT_CLONE_BRANCH`**; inspect **`/tmp/cloudsentinel-scans/<id>`**; Sonar **Python** plugin; **`sonar.branch.name`** aligned with checked-out branch (see [dedicated section](#sonarqube-no-lines-of-code--branch-mismatch)) |
| UI shows **Scanning** but still old summary | Latest row **`RUNNING`** while counts still reflect the previous **`COMPLETED`** run | Expected until current scan finishes; refresh after scan completes |
| **`Invalid email or password`** after DB “works” | User exists only on **other** machine’s database | **`VITE_API_BASE_URL`** must point to the backend whose Postgres you registered against |
| **`password authentication failed for user "csuser"`** on Windows | **`.env`** copied from Ubuntu | Windows **`DATABASE_URL`** with local **`postgres`** user/password (see **`.env.windows.example`**) |
| **`SASL: SCRAM-SERVER-FIRST-MESSAGE: client password must be a string`** | **`DATABASE_URL`** has no password segment (e.g. `postgresql://csuser@localhost/db`) or **`DB_PASSWORD`** missing / not a string after dotenv | Use **`DB_PASSWORD=yourpassword`** with **`DB_*`**, or **`DATABASE_URL=postgresql://user:password@host:5432/dbname`** (URL‑encode special chars in the password). **`backend/db.js`** coerces an empty password to **`""`**. |
| **`bcrypt_lib.node: invalid ELF header`** on Linux | **`node_modules`** copied from Windows | **`rm -rf node_modules && npm install`** on Ubuntu |
| **`permission denied for schema public`** (PG 15+) | Grants applied while connected to **`postgres`** DB instead of **`cloudsentinel`** | Run **`GRANT`** … **`ON SCHEMA public`** while **`\\c cloudsentinel`** |
| **`Validation of project failed: To use the property "sonar.branch.name"... Developer Edition required`** | Running Community Edition while scanner always sent branch property | Gate branch arg behind **`SONAR_ENABLE_BRANCH_ANALYSIS=true`**; keep it disabled on Community |
| SonarScanner **`ContextException` / `Cannot analyse 'k8s/...'`** / **`org.sonar.iac`** in stack | Sonar **IaC / Kubernetes** sensor crashes on some **YAML** under **`k8s/`** (e.g. **spring-petclinic**) | Default **`sonar.exclusions`** now include **`**/k8s/**`** and common Helm paths. Override with **`SAST_SONAR_EXCLUSIONS`** if needed. |
| **`org.sonar.java.AnalysisException ... sonar.java.binaries`** | Java analyzer needs compiled classes | Build Java project before scanning and pass **`-Dsonar.java.binaries=target/classes`** |
| **`Fatal error compiling: release version 17 not supported`** | Scan server Java runtime too old for project toolchain | Install/select **JDK 17** (`java -version`, `javac -version`) on scan server |
| **`spawn ./mvnw EACCES`** | Maven wrapper not executable on Linux clone | Run wrapper via shell: **`sh mvnw -DskipTests clean package`** |

---

## Environment configuration (full detail)

### Backend (`backend/.env`)

**Windows (typical local dev)**

- **`PORT=3000`** (or free port).
- **`DATABASE_URL=postgresql://postgres:<password>@localhost:5432/cloudsentinel`** — matches **your** Windows Postgres password (not necessarily **`csuser`**).
- **`SONAR_HOST=http://<ubuntu-vm-ip>:9000`** if Sonar runs only on the VM (not `localhost` unless Sonar is on the same PC).
- **`CLONE_DIR=D:/temp/cloudsentinel-scans`** (create folder or adjust path).
- **`GITHUB_TOKEN`** — real **`ghp_…`** PAT with repo access for clones/analysis.
- **`SMTP_PASS`** — Gmail app passwords often need **quotes** if they contain spaces: `SMTP_PASS="xxxx xxxx xxxx xxxx"`.

**Ubuntu (typical API + Sonar + Postgres on same VM)**

- **`PORT=3000`**
- **`SONAR_HOST=http://localhost:9000`**
- **`SONAR_TOKEN=squ_…`** — **never** leave **`PASTE_SONAR_USER_TOKEN`** or placeholders.
- **`CLONE_DIR=/tmp/cloudsentinel-scans`**
- **`DB_*`** or **`DATABASE_URL`** for **`csuser`** / **`cloudsentinel`** as you created in Postgres.
- **`GITHUB_TOKEN`** — real PAT.

**Optional clone / Sonar branch tuning**

- **`GIT_CLONE_BRANCH=master`** — shallow clone that branch if **`main`** is empty but **`master`** has code (documented in **`.env.ubuntu.example`**).
- **`SONAR_BRANCH_NAME`** — override if git is in detached HEAD and detection falls back wrong.
- **`SONAR_ENABLE_BRANCH_ANALYSIS=true`** — only set when Sonar edition supports branch analysis.
- **`SAST_KEEP_CLONE=true`** — keep cloned repo on disk after scan (debugging).
- **`MAVEN_CMD=mvn`** — override Maven executable when wrapper is unavailable.

**Loading a different env file**

```bash
BACKEND_ENV_FILE=/path/to/.env node server.js
```

(`server.js` uses **`require("dotenv").config({ path: process.env.BACKEND_ENV_FILE || ... })`**.)

### Frontend (`frontend/.env`)

```env
VITE_API_BASE_URL=http://<backend-host>:3000/api
```

Examples:

- API on **Ubuntu VM**: `http://192.168.141.128:3000/api` (replace with **`hostname -I`** on the VM).
- API on **same Windows machine**: `http://localhost:3000/api`.

Restart **`npm run dev`** after changing **`VITE_*`** vars.

Axios **`baseURL`** is **`VITE_API_BASE_URL`**; request paths are **`/projects`**, **`/auth/login`**, **`/sast/scan/:id`** (no second **`/api`** prefix in path strings).

See **`frontend/.env.example`**.

---

## Database (PostgreSQL 15+ notes)

1. Create database and role (example):

   ```sql
   CREATE DATABASE cloudsentinel;
   CREATE USER csuser WITH PASSWORD 'your_secure_password';
   GRANT ALL PRIVILEGES ON DATABASE cloudsentinel TO csuser;
   ```

2. **Must** connect to **`cloudsentinel`** before fixing **`public`** grants:

   ```bash
   sudo -u postgres psql -d cloudsentinel
   ```

   ```sql
   GRANT CREATE, USAGE ON SCHEMA public TO csuser;
   GRANT ALL ON SCHEMA public TO csuser;
   ```

   If you ran grants only while connected to database **`postgres`**, **`csuser`** still fails inside **`cloudsentinel`**.

3. Apply tables:

   ```bash
   sudo -u postgres psql -d cloudsentinel -f schema.sql
   ```

   Re-running when tables exist shows **“already exists”** — safe to ignore unless you need a clean reset.

**Tables:** `users`, `projects`, `scan_results`, `scan_history`, `password_resets`.

---

## Run the stack

### Backend + Frontend (recommended)

From **this directory** (the `cloudsentinel` folder that contains `backend/`, `frontend/`, and `package.json`):

```bash
npm install
npm run dev
```

This starts **API + Vite** in one terminal. Open **`http://localhost:5173`** (or the port Vite prints if 5173 is busy).

### Backend

```bash
cd backend
npm install
npm run dev
```

Verify:

```bash
curl -s http://localhost:3000/health
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

Browser: **`http://localhost:5173`**.

### Rule

Never copy **`node_modules`** from Windows to Linux (or vice versa). Native modules (**bcrypt**) must be built on the target OS.

---

## SAST pipeline (step-by-step)

1. Client calls **`POST /api/sast/scan/:projectId`** with **`Authorization: Bearer <jwt>`**.
2. Pre-check: if a SAST or dependency scan for the same project is already **`RUNNING`**, return **`409 Conflict`**.
3. Insert **`scan_history`** row: **`RUNNING`**, capture **`id`** (`scanHistoryId`).
4. mkdir **`CLONE_DIR`**, delete previous **`CLONE_DIR/<projectId>`** if present.
5. Build authenticated clone URL for **github.com** when **`GITHUB_TOKEN`** or **`projects.github_token`** is usable (**`x-access-token`** format).
6. **`git clone`** — default **`--depth 1`** ( **`SAST_SHALLOW_CLONE=false`** for full history). Optional **`GIT_CLONE_BRANCH`** → **`git clone -b <branch> --single-branch`**.
7. If **`pom.xml`** exists: Maven **`clean package`** with **`-DskipTests`** plus **`SAST_MAVEN_PARALLEL`** (default **`-T 1C`** for faster multi-module builds like **WebGoat**; set **`SAST_MAVEN_PARALLEL=`** empty to disable).
8. Detect branch: **`git rev-parse --abbrev-ref HEAD`** in clone dir; pass **`-Dsonar.branch.name=...`** only when **`SONAR_ENABLE_BRANCH_ANALYSIS=true`**.
9. Run **`sonar-scanner`** with **`sonar.java.binaries`** set to **discovered comma-separated paths** (each existing **`…/target/classes`** and Gradle **`…/build/classes/java/main`** etc.) — not a glob — and **`sonar.exclusions`** excluding **`node_modules`**, **`.git`**, **`.gradle/caches`**, **`build/generated`** (not all of **`build/`**). Overrides: **`SAST_SONAR_EXCLUSIONS`**, **`SAST_SONAR_JAVA_BINARIES`**. Scanner timeout: **`SAST_SONAR_SCAN_TIMEOUT_MS`**.
10. Poll Sonar **`/api/measures/component`** (**`ncloc`**, **`files`**) until both are non-zero or **`SAST_SONAR_INDEX_MAX_WAIT_MS`** elapses (**`SAST_SONAR_INDEX_POLL_MS`** between tries); fail clearly if indexing never succeeds.
11. Validate metrics; **`git clone`** / Maven also have timeouts (**`SAST_GIT_TIMEOUT_MS`**, **`SAST_MAVEN_TIMEOUT_MS`**). Sonar HTTP calls use **`SAST_SONAR_HTTP_TIMEOUT_MS`**.
12. **`GET <SONAR_HOST>/api/issues/search?projectKeys=cloudsentinel_<projectId>`** with token auth.
13. Replace **`scan_results`** for that project; **`UPDATE scan_history`** row **`scanHistoryId`** → **`COMPLETED`** + counts.
14. Delete clone dir unless **`SAST_KEEP_CLONE=true`**.
15. On any thrown error: **`UPDATE scan_history`** → **`FAILED`** for **`scanHistoryId`**; return **500** JSON **`{ error: "<message>" }`**.

**Why WebGoat (or OWASP Java) feels slower than a small JS repo:** the pipeline builds a **full Maven multi-module reactor** and Sonar analyzes **many Java compilation units**. A minimal React/Node demo has far less bytecode and fewer files — that difference is normal. Defaults (**shallow clone**, **`SAST_MAVEN_PARALLEL=-T 1C`**, Sonar **exclusions**) shrink wall time but will not match a tiny project.

---

## SonarQube: “no lines of code” / branch mismatch

Sonar’s message **“The main branch has no lines of code”** means: **for the Sonar project + branch you are looking at**, the last analysis recorded **zero** lines of code.

It does **not** always mean GitHub **`main`** is empty. Common cases:

1. **Registered wrong repository URL** in CloudSentinel (e.g. another fork/org). Fix the project’s **`repo_url`** or re-add the project pointing at **`https://github.com/<owner>/<repo>.git`** that actually contains **`main.py`**, etc.

2. **Default branch vs empty `main`:** GitHub’s **default branch** might be **`master`** or **`develop`** with all code, while **`main`** exists but is empty. Then:
   - Either push code to **`main`**, or  
   - Set **`GIT_CLONE_BRANCH=master`** (or the branch that has files) in **`backend/.env`** on the scan server.

3. **Verify the clone on the server** (during or after a scan, use your real **`projectId`**):

   ```bash
   ls -la /tmp/cloudsentinel-scans/<projectId>
   find /tmp/cloudsentinel-scans/<projectId> -name '*.py'
   ```

   If **`find`** prints nothing, Sonar will also see no Python sources.

4. **Sonar plugins:** Admin → **Marketplace** / **Plugins** — ensure **Python** (and Java, etc.) language packs are installed for your stack.

5. **Sonar server banner** (“version no longer active”): plan an upgrade; old servers can misbehave with newer scanners.

6. **Branch name in Sonar UI:** After analysis, open project **`cloudsentinel_<id>`** and select the **branch** that matches what was cloned (scanner passes **`-Dsonar.branch.name`** from **`git rev-parse`** when possible).

---

## Where scan results appear

| Location | What you see |
|----------|----------------|
| **CloudSentinel UI** | **Projects → View project** → Scan history; **`/projects/:id/sast`** → issue table + Sonar metric cards + charts |
| **PostgreSQL** | **`scan_results`** (issues), **`scan_history`** (runs) |
| **SonarQube Web** | **`http://<sonar-host>:9000`** → project key **`cloudsentinel_<numeric_project_id>`** |
| **Disk** | Clone under **`CLONE_DIR/<projectId>`** — deleted after a successful/failed scan path cleanup |

---

## HTTP API

Prefix: **`/api`** (included in **`VITE_API_BASE_URL`**).

**Auth**

| Method | Path | Notes |
|--------|------|--------|
| POST | `/api/auth/register` | `fullName`, `email`, `password` |
| POST | `/api/auth/login` | `email`, `password` → `{ token, user }` |
| POST | `/api/auth/google` | If configured |
| POST | `/api/auth/github/exchange` | If client uses it |
| GET | `/api/auth/me` | Bearer |
| PATCH | `/api/auth/profile` | Bearer |
| POST | `/api/auth/forgot-password` | email |
| POST | `/api/auth/reset-password` | token, password |

**Projects**

| Method | Path | Notes |
|--------|------|--------|
| POST | `/api/projects/analyze` | Preview stack (Bearer) |
| POST | `/api/projects` | Create (Bearer) |
| GET | `/api/projects` | List (Bearer) |
| GET | `/api/projects/:id` | Detail + latest scan (Bearer) |
| GET | `/api/projects/:id/scans` | History (Bearer) |
| DELETE | `/api/projects/:id` | Delete (Bearer) |

**SAST**

| Method | Path | Notes |
|--------|------|--------|
| POST | `/api/sast/scan/:projectId` | Run scan (Bearer); long-running; returns **409** if another scan is RUNNING for that project |
| GET | `/api/sast/:projectId` | Issues + summary + `sonarMetrics` (bugs, vulnerabilities, hotspots, codeSmells, coverage, duplications, ncloc) |
| GET | `/api/sast/compliance/:projectId` | Combined compliance mapping (SAST + dependencies) |
| GET | `/api/sast/report/:projectId` | Full SAST/compliance report payload |
| GET | `/api/sast/analytics/overview` | Aggregated analytics cards |

**Dependencies**

| Method | Path | Notes |
|--------|------|--------|
| POST | `/api/dependencies/scan/:projectId` | Run Trivy dependency scan (Bearer); long-running; returns **409** if another scan is RUNNING for that project |
| GET | `/api/dependencies/:projectId` | Latest dependency scan + packages + vulnerable rows + license summary |
| GET | `/api/dependencies/sbom/:projectId` | Download latest CycloneDX SBOM |
| GET | `/api/dependencies/report/:projectId` | Dependency report payload used for HTML export |

**Health**

- `GET /` — API banner  
- `GET /health` and `GET /api/health` — `{ ok: true, service: "CloudSentinel API" }`

---

## Frontend routes

| Path | Screen |
|------|--------|
| `/` | Landing |
| `/login`, `/register`, `/forgot-password`, `/reset-password` | Auth |
| `/dashboard` | Dashboard |
| `/projects` | Project list + add modal |
| `/projects/:id` | Project details, Scan, history |
| `/projects/:id/sast` | SAST results |
| `/projects/:id/dast` | DAST placeholder |
| `/dependencies` | Trivy dependency + SBOM dashboard |
| `/compliance` | Combined compliance view (SAST + dependency mappings) |
| `/cicd`, `/iac`, `/cloud`, `/kubernetes`, `/monitoring`, `/secrets` | Placeholder / extended modules |
| `/settings` | Profile |

---

## Debugging from Ubuntu terminal

**Health (no auth)**

```bash
curl -s http://localhost:3000/health
```

**Login → token**

```bash
curl -s -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"you@example.com","password":"yourpassword"}'
```

Copy **`token`** from JSON, then:

```bash
export TOKEN="<paste jwt>"
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:3000/api/projects | jq
curl -s -H "Authorization: Bearer $TOKEN" "http://localhost:3000/api/sast/3" | jq
```

Use the **numeric** project **`id`** from **`/api/projects`**, not the string **`PROJECT_ID`**.

**SQL**

```bash
sudo -u postgres psql -d cloudsentinel -c "SELECT id,email FROM users LIMIT 5;"
sudo -u postgres psql -d cloudsentinel -c "SELECT project_id,status,total_issues,completed_at FROM scan_history ORDER BY started_at DESC LIMIT 10;"
sudo -u postgres psql -d cloudsentinel -c "SELECT COUNT(*) FROM scan_results;"
```

---

## Troubleshooting (expanded)

| Symptom | What to check |
|---------|----------------|
| **Invalid email or password** | Same API URL as DB where you registered (`VITE_API_BASE_URL`); typo in email; wrong password |
| **Git asks for username in terminal** | Old backend build; missing **`GITHUB_TOKEN`**; pull latest **`routes/sast/`** code, restart |
| **Sonar “Not authorized”** | **`SONAR_TOKEN`** must be real (**`squ_...`** from Sonar), not placeholder text |
| **Sonar “no lines of code”** | [Section above](#sonarqube-no-lines-of-code--branch-mismatch); **`GIT_CLONE_BRANCH`**; correct repo URL |
| **SonarScanner: `Invalid value for sonar.sources` / `No files matching 'src/main/java'`** | The repo’s **`sonar-project.properties`** often forces Maven paths that don’t exist. By default CloudSentinel **removes** those files before analysis so **`sonar.sources=.`** from the API applies. To keep embedded config: **`SAST_USE_EMBEDDED_SONAR_PROPERTIES=true`**. Alternatively fix/remove **`sonar.sources`** in the GitHub repo. |
| **`Invalid sonar.java.binaries` / No `target/classes` match** | Many Sonar versions reject the glob `**/target/classes`. The backend discovers real Maven **`target/classes`** and Gradle **`build/classes/*/main`** after compile and passes them comma-separated. Gradle-only repos need **`gradlew`**. Defaults no longer exclude all of **`build/`** under Sonar exclusions. Override with **`SAST_SONAR_JAVA_BINARIES=path1,path2`** if needed. |
| **Gradle “build error” / VulnerableApp-style repo** | Repos like **VulnerableApp** are **Gradle only** (no `pom.xml`) and often declare **Java 17** via Gradle toolchains. Install **JDK 17** and set **`SAST_GRADLE_JAVA_HOME`**. They also use **Spotless + Prettier**; if Gradle stderr shows JS errors (e.g. `build is not defined`), add exclusions that match tasks in that repo, e.g. **`SAST_GRADLE_EXTRA_ARGS=-x spotlessCheck -x spotlessJavaCheck`** (use **`./gradlew tasks`** on a clone to confirm task names). CloudSentinel tries **`compileJava`** before **`classes` / `assemble`** to avoid extra plugin work. |
| **`scan_results` count = 0** | Scan **`FAILED`**; Sonar returned 0 issues; or analysis never wrote — check **`scan_history.status`** |
| **`Loading project…` forever** | Backend down; wrong URL; very old blocking git — update backend and restart |
| **`Scanning` / `RUNNING` never finishes** | One **HTTP POST** waits for clone + **sonar-scanner** + Sonar CE indexing. If **`SONAR_HOST`** is unreachable, git hangs, or analysis is slow, the row stayed **RUNNING** until we added limits. **Checks:** reachable Sonar (`curl` Sonar `/api/system/status` from backend host); valid **`SONAR_TOKEN`**; large repos need time (or raise **`SAST_SONAR_SCAN_TIMEOUT_MS`** / **`SAST_SONAR_INDEX_MAX_WAIT_MS`** in backend `.env`). **WebGoat / big Java:** Maven + Sonar can take **tens of minutes** — leave the tab open or use polling on Project Details. **Stuck badges:** restart the API — **SAST** and **dependency** rows **RUNNING** longer than **`SAST_ORPHAN_RUN_MINUTES`** are marked **FAILED** (`0` disables). **Dependencies page:** **`DEP_TRIVY_TIMEOUT_MS`** (default 1h) — first **Trivy** run downloads a large vuln DB; raise if needed. |
| **Two databases confusion** | Register/login against the backend you intend; use separate **`.env`** per OS |
| Dependency scan says path missing under `/tmp/...` with snap Trivy | Snap confinement can fail on `/tmp`; set `CLONE_DIR=/home/<user>/cloudsentinel-scans` and keep `TRIVY_CMD=/snap/bin/trivy` |
| **Dependencies: Total packages 0** for Gradle (e.g. VulnerableApp) | **Trivy** resolves Java mostly from **`pom.xml`**, **JARs**, or **`*.gradle.lockfile`** — plain `build.gradle` alone often yields empty results. Backend now runs **`./gradlew compileJava -x test`** before Trivy when there is **`gradlew`** and **no `pom.xml`**. Ensure **JDK 17** on the scanner (`SAST_GRADLE_JAVA_HOME` / `DEP_GRADLE_JAVA_HOME`). Opt out: **`DEP_SKIP_GRADLE_COMPILE=true`**. |
| Dependency scan returns no vulnerabilities unexpectedly | After the Gradle step above, rerun **Run Scan**; check API logs **`[dep-scan]`**; verify Trivy version (`trivy version`) and **`--list-all-pkgs`** JSON has `Results` |

---

## Git workflow

```bash
git status
git pull origin main    # use your branch name
```

Commit **`README.md`** and code; never commit **`.env`**.

If **`remote origin`** points at another user’s repo, use **`git remote set-url origin https://github.com/<you>/<repo>.git`**.

---

## Resume tomorrow (checklist)

1. Start **PostgreSQL**; confirm **`cloudsentinel`** exists and **`schema.sql`** applied; **`public`** grants for app user on **PG 15+**.
2. **`backend/.env`** complete: **`PORT`**, DB, **`JWT_SECRET`**, **`GITHUB_TOKEN`**, **`SONAR_HOST`**, **`SONAR_TOKEN`** (real), **`CLONE_DIR`**, **`TRIVY_CMD`**, optional **`GIT_CLONE_BRANCH`**.
3. **`frontend/.env`**: **`VITE_API_BASE_URL=http://<api-host>:3000/api`**.
4. **`npm install`** in **`backend`** and **`frontend`** (fresh on Linux if needed).
5. **`npm run dev`** backend → **`curl /health`** OK.
6. **`npm run dev`** frontend → **`http://localhost:5173`**.
7. Register or login → Projects → correct GitHub URL → run SAST + Dependency scans → validate `/projects/:id/sast`, `/dependencies`, `/compliance`.
8. For Java repos, ensure scan server has **JDK 17+** when project requires it.

---

## Security

- Never commit **`.env`** or live tokens.
- Rotate Sonar/GitHub/database passwords if exposed.
- Use HTTPS for production deployments; this README describes dev/split-LAN setups.

---

*This document reflects the codebase and operational lessons through the session that included: split Windows/Ubuntu env templates, `DATABASE_URL` vs `DB_*`, CORS, non-interactive Git clone with PAT, async SAST, scan_history RUNNING/COMPLETED/FAILED single-row updates, register→login redirect, Sonar token/branch troubleshooting, Java (Maven) pre-build with `sonar.java.binaries`, `SONAR_ENABLE_BRANCH_ANALYSIS` gating for Community Edition, `SAST_KEEP_CLONE` debugging mode, Trivy dependency scanning + CycloneDX SBOM generation, compliance mapping from both SAST and dependency findings, and enterprise blue frontend redesign across auth/landing pages.*

## Module 12 — Governance, Compliance & Unified Dashboard

The unified dashboard, findings, compliance, analytics and report views now use
persisted, owner-scoped scanner evidence. See [Module 12 setup and verification](docs/module12.md)
for migration 017, API filters, mapping versions, scoring methodology, local commands,
executed tests, demonstration steps and upstream data limitations.

FE-3 now supports separately versioned OWASP 2021/2025 mappings and evidence-based
CIS Docker static assessments. See the [FE-3 coverage and evaluator handoff](docs/fe3.md)
for migration 018, supported checks, actual data availability and verified limitations.

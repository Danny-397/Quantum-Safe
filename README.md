# QuantumSafe

[![CI](https://github.com/Danny-397/Quantamn-Safe/actions/workflows/ci.yml/badge.svg)](https://github.com/Danny-397/Quantamn-Safe/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-green)

**Find your quantum vulnerabilities before attackers do.**

QuantumSafe is a post-quantum security platform with two halves that reinforce
each other:

1. A **static-analysis engine** that scans codebases for cryptography that will
   be broken or weakened by quantum computers, scores the risk, and generates a
   NIST-aligned migration plan.
2. A **quantum-computing module** ([`quantum/`](quantum/)) that *implements the
   actual attacks* — **Shor's** and **Grover's** algorithms in Qiskit, run on a
   quantum simulator — so every risk rating is backed by the real algorithm that
   justifies it. The scanner says *what* to fix; the quantum module proves *why*.

It ships as three parts that share **one** detection engine:

- A **free CLI** (`pip install quantumsafe`) that scans local directories or
  public GitHub repos and prints/exports findings.
- A **Flask REST API** that powers the dashboard, ingests scans, and handles
  auth + billing.
- A **dark, Bloomberg-terminal-style web dashboard** with scan history,
  findings, migration plans, exports, and Stripe-powered subscriptions.

> ⚠️ **Disclaimer:** QuantumSafe is a security-awareness tool. It uses static
> pattern + AST analysis and is **not** a substitute for a professional
> cryptographic audit. Findings are heuristic and may include false
> positives/negatives.

---

## What this project demonstrates

QuantumSafe is a full, working product built end to end — not a tutorial clone.
It was built to show breadth and depth across the stack:

- **Quantum computing:** real implementations of **Shor's algorithm** (quantum
  order-finding + phase estimation, which factors a number and recovers an RSA
  key) and **Grover's algorithm** in **Qiskit**, run on a quantum simulator —
  see [`quantum/`](quantum/). Not described — executed.
- **Program analysis:** a real detection engine using Python's `ast` module
  (import + call resolution) alongside a multi-language regex engine, with
  per-line/per-family de-duplication so findings don't double-count.
- **Applied cryptography knowledge:** maps each finding to *why* it's quantum-
  vulnerable (Shor's vs. Grover's algorithm) and to the correct NIST PQC
  replacement (FIPS 203/204/205).
- **Backend engineering:** a Flask REST API with SQLAlchemy, JWT + bcrypt auth,
  hashed API keys, rate limiting, CORS lockdown, and Stripe subscription billing.
- **Frontend engineering:** a dependency-light dashboard (vanilla JS) with a
  consistent data contract against the API, charts, and exports.
- **Software engineering practice:** one shared detection package powering both
  the CLI and the API, an automated end-to-end test (`backend/smoke_test.py`),
  and deploy configs for a real multi-service deployment.

See [TECHNICAL_OVERVIEW.md](TECHNICAL_OVERVIEW.md) for the design decisions, the
quantum-threat background, and an honest list of limitations.

---

## Table of contents

1. [What it detects](#what-it-detects)
2. [Quantum Risk Score](#quantum-risk-score)
3. [CLI: install & usage](#cli-install--usage)
4. [API documentation](#api-documentation)
5. [Dashboard](#dashboard)
6. [Local development setup](#local-development-setup)
7. [Environment variables](#environment-variables)
8. [Deployment](#deployment)
9. [Project structure](#project-structure)
10. [NIST PQC references](#nist-pqc-references)

---

## What it detects

Across **Python, JavaScript/TypeScript, Java, Go, Ruby, C#, PHP, Rust, C/C++,
Kotlin, and Swift** (Python also via AST for precision):

| Risk | Algorithms |
|------|------------|
| **HIGH** — migrate immediately | RSA (any size, incl. RSA-2048/4096), ECDSA / ECDH / ECC, DSA, Diffie-Hellman, MD5, SHA-1 |
| **MEDIUM** — plan migration | TLS 1.0 / 1.1, 3DES / Triple DES, RC4, RSA key sizes under 2048 |
| **LOW** — monitor | SHA-256, AES-128, TLS 1.2 |

Each finding includes the file, line number, algorithm, risk level, *why* it is
vulnerable, and a NIST-approved replacement:

- RSA/ECC key exchange → **CRYSTALS-Kyber (ML-KEM, FIPS 203)**
- RSA/ECDSA/DSA signatures → **CRYSTALS-Dilithium (ML-DSA, FIPS 204)** / SPHINCS+ (FIPS 205)
- Hash functions → **SHA-3** or SHA-256
- Symmetric encryption → **AES-256**

## Quantum Risk Score

A 0–100 score computed **from real findings** (never hardcoded):

```
score = min(100, 15*HIGH + 5*MEDIUM + 1*LOW)
```

| Score | Band | Meaning |
|-------|------|---------|
| 0–30 | Low | Good quantum hygiene |
| 31–60 | Medium | Plan migration |
| 61–80 | High | Prioritize migration |
| 81–100 | Critical | Immediate action required |

---

## Quantum demonstrations (Shor & Grover)

The [`quantum/`](quantum/) module runs the real algorithms on a quantum simulator:

```bash
pip install -r quantum/requirements.txt
python quantum/shor.py     # quantum order-finding factors N=15, then breaks a toy RSA key
python quantum/grover.py   # recovers a hidden k-bit key in ~sqrt(2^k) steps
```

- **`shor.py`** uses quantum phase estimation over modular exponentiation to find
  the order of `a mod N`, factors `N`, and reconstructs an RSA private key from
  the factors — the concrete reason RSA/ECC are rated **HIGH**.
- **`grover.py`** uses amplitude amplification to search a key space in ~√N
  queries, halving effective key strength — the reason AES-128/SHA-256 are **LOW**
  (keep the primitive, double the size).

Honest scope: these run at small scale (factoring 15), which is the genuine state
of the art for end-to-end Shor — RSA-2048 needs millions of error-corrected
qubits that don't exist yet. That gap is exactly why migrating *now* matters. See
[quantum/README.md](quantum/README.md) for the math and the real-hardware path.

## CLI: install & usage

```bash
pip install quantumsafe        # from PyPI once published
# or, from this repo:
pip install -e .
```

### Commands

```bash
# Scan a local directory (colored terminal table)
quantumsafe scan --path ./myproject

# Scan a public GitHub repo (shallow-cloned to a temp dir, then cleaned up)
quantumsafe scan --repo https://github.com/org/app

# Write a report: JSON, HTML, SARIF, CycloneDX CBOM, or an SVG risk badge
quantumsafe scan --path ./myproject --output report.json
quantumsafe scan --path ./myproject --output report.html
quantumsafe scan --path ./myproject --output report.sarif       # GitHub code scanning
quantumsafe scan --path ./myproject --output report.cbom.json   # CycloneDX CBOM
quantumsafe scan --path ./myproject --output badge.svg          # embeddable risk badge

# Skip paths with glob patterns (repeatable)
quantumsafe scan --path . --exclude 'tests/*' --exclude 'vendor/*'

# Fail the process (exit 1) if any HIGH finding exists — handy in CI
quantumsafe scan --path . --fail-on-high

# Try it on the bundled examples
quantumsafe scan --path examples

# Link the CLI to your paid dashboard account (key from Settings page)
quantumsafe auth --key qs_live_xxxxxxxx

# Version
quantumsafe version
```

| Flag | Description |
|------|-------------|
| `--path` | Local directory or file to scan |
| `--repo` | Public `https://github.com/<org>/<repo>` URL |
| `--output` | Write to `.json`, `.cbom.json` (CycloneDX CBOM), `.html`, `.sarif`, or `.svg` (risk badge); terminal summary still printed |
| `--exclude` | Glob of paths to skip (repeatable) |
| `--fail-on-high` | Exit non-zero on any HIGH finding (CI gate) |

**Suppressing a finding:** add `# quantumsafe: ignore` (any comment style) to the
line. Useful for a known-safe, non-security use of an algorithm.

### Use in CI (GitHub Action)

QuantumSafe ships a reusable action that scans and uploads results to your
repo's **Security tab**:

```yaml
- uses: Danny-397/Quantamn-Safe@main
  with:
    path: .
    exclude: tests/*,vendor/*
    fail-on-high: "true"
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: quantumsafe.sarif
```

---

## API documentation

Base URL (dev): `http://localhost:5000` · all endpoints under `/api/v1`.
Authentication: **JWT** (`Authorization: Bearer <token>`) for the dashboard, or a
**CLI API key** (`X-API-Key: qs_live_...`) for the scan endpoint.

### Auth

```http
POST /api/v1/auth/register      { "email", "password" }  -> { token, user }
POST /api/v1/auth/login         { "email", "password" }  -> { token, user }
GET  /api/v1/auth/verify?token=...                        -> { message }
POST /api/v1/auth/forgot        { "email" }               -> { message }
POST /api/v1/auth/reset         { "token", "password" }   -> { message }
GET  /api/v1/auth/me            (JWT)                      -> { user }
```

Example:

```bash
curl -s http://localhost:5000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"you@example.com","password":"supersecret"}'
```

### Scanning

```http
POST /api/v1/scan               (JWT or X-API-Key)
     { "repo_url": "https://github.com/org/app" }   # or multipart file=<.zip>
     -> { scan_id, report }

GET  /api/v1/scans?page=1&per_page=20   (JWT)  -> paginated list
GET  /api/v1/scans/{id}                 (JWT)  -> scan + findings
GET  /api/v1/scans/{id}/export?format=json|html|csv   (JWT)
GET  /api/v1/scans/{id}/migration       (JWT)  -> grouped migration plan
GET  /api/v1/overview                   (JWT)  -> dashboard stats + trend
```

```bash
# Scan a repo from the CLI key (the path the CLI uses under the hood)
curl -s http://localhost:5000/api/v1/scan \
  -H "X-API-Key: qs_live_xxx" -H "Content-Type: application/json" \
  -d '{"repo_url":"https://github.com/pallets/flask"}'
```

### API key management

```http
GET  /api/v1/user/apikey   (JWT)  -> { has_api_key, api_key_prefix }
POST /api/v1/user/apikey   (JWT)  -> { api_key }   # full key shown ONCE
```

### Billing (Stripe)

```http
POST /api/v1/billing/checkout   (JWT)  { "plan": "pro"|"team" } -> { url }
POST /api/v1/billing/portal     (JWT)  -> { url }
POST /api/v1/billing/webhook    (Stripe signature)  -> { received: true }
```

All endpoints are rate-limited; CORS is restricted to `FRONTEND_ORIGIN`.

---

## Dashboard

A static site (`frontend/`) — no build step. Pages:

- **Landing** — hero, feature pillars, pricing (Free / Pro $19 / Team $49).
- **Auth** — login, register, forgot/reset password.
- **Dashboard** — Overview (risk score, totals, trend chart, recent scans),
  Scans (paginated), Findings (filterable), Settings (API key + account),
  Billing (upgrade / Stripe portal).
- **Scan detail** — full findings table, filter by risk, export JSON/HTML/CSV.
- **Migration plan** — findings grouped by risk with NIST replacement,
  standard reference, and estimated complexity.

Point the dashboard at your API by editing one line in `frontend/config.js`:

```js
window.QUANTUMSAFE_API = "https://quantumsafe-api.onrender.com";
```

(Leave it `""` for local development — it falls back to `http://localhost:5000`.)

---

## Local development setup

Requires Python 3.9+.

```bash
git clone https://github.com/Danny-397/Quantamn-Safe
cd Quantamn-Safe

# 1) Install the shared scanner package (CLI) in editable mode
pip install -e .

# 2) Install backend dependencies
pip install -r backend/requirements.txt

# 3) Configure environment
cp .env.example .env          # fill in SECRET_KEY / JWT_SECRET_KEY at minimum

# 4) Run the API (creates SQLite tables automatically)
cd backend
python app.py                 # http://localhost:5000  (health: /health)

# 5) Serve the dashboard (any static server)
cd ../frontend
python -m http.server 3000    # http://localhost:3000
```

### Run the whole stack with Docker

```bash
docker compose up --build
# Dashboard -> http://localhost:3000   API -> http://localhost:5000
```

### Tests

Run the test suite (scanner, scorer, recommender, full API; uses an in-memory
DB, no setup):

```bash
pip install -r requirements-dev.txt
pytest -q
```

Seed a demo account so the dashboard is populated:

```bash
cd backend && python seed_demo.py     # demo@quantumsafe.dev / demodemo123
```

Without `MAIL_SERVER` configured, verification/reset emails are printed to the
server log instead of being sent — so you can develop without SMTP.

---

## Environment variables

See [`.env.example`](.env.example). Summary and where to get each:

| Variable | Required | Where to get it |
|----------|----------|-----------------|
| `SECRET_KEY` | ✅ | Generate: `python -c "import secrets;print(secrets.token_hex(32))"` |
| `JWT_SECRET_KEY` | ✅ | Generate the same way (use a different value) |
| `DATABASE_URL` | prod | Render Postgres dashboard → *Connections* (SQLite used if unset) |
| `FRONTEND_ORIGIN` | ✅ | Your dashboard URL, e.g. `https://quantumsafe.vercel.app` |
| `DASHBOARD_URL` | ✅ | Same as above (used in emails + Stripe redirects) |
| `API_URL` | ✅ | The deployed API URL (used for email verify links) |
| `STRIPE_SECRET_KEY` | billing | Stripe Dashboard → *Developers → API keys* (`sk_test_...`) |
| `STRIPE_WEBHOOK_SECRET` | billing | Stripe → *Developers → Webhooks* → your endpoint (`whsec_...`) |
| `STRIPE_PRO_PRICE_ID` | billing | Stripe → *Products* → Pro $19/mo recurring price (`price_...`) |
| `STRIPE_TEAM_PRICE_ID` | billing | Stripe → *Products* → Team $49/mo recurring price (`price_...`) |
| `MAIL_SERVER` / `MAIL_PORT` / `MAIL_USE_TLS` | email | Your SMTP provider (e.g. `smtp.gmail.com` / 587 / true) |
| `MAIL_USERNAME` / `MAIL_PASSWORD` | email | SMTP credentials (Gmail: an App Password) |
| `MAIL_DEFAULT_SENDER` | email | The "from" address |
| `RATELIMIT_STORAGE_URI` | optional | `memory://` (dev) or a Redis URL (prod) |

---

## Deployment

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/Danny-397/Quantamn-Safe)

See **[DEPLOYMENT.md](DEPLOYMENT.md)** for a full step-by-step walkthrough
(Render + Vercel + Stripe + demo seeding). In short:

- **CLI → PyPI:** `python -m build && twine upload dist/*`
- **Backend → Render:** push the repo; Render reads [`render.yaml`](render.yaml)
  (web service + Postgres). Set the `sync: false` env vars in the dashboard.
  Add a Stripe webhook pointing at `https://<api>/api/v1/billing/webhook`.
- **Frontend → Vercel:** import the repo; [`vercel.json`](vercel.json) serves
  `frontend/` statically. Set `window.QUANTUMSAFE_API` to your Render API URL.
- **Database → Render Postgres** (provisioned by `render.yaml`).

---

## Project structure

```
Quantamn-Safe/
├── quantum/              # REAL quantum computing (Qiskit): the attacks themselves
│   ├── shor.py           #   Shor's algorithm — factors N, breaks RSA
│   ├── grover.py         #   Grover's algorithm — key-search speedup
│   └── README.md         #   the math + honest scope + real-hardware path
├── cli/                  # the `quantumsafe` package (CLI + shared engine)
│   ├── scanner.py        #   AST + regex detection
│   ├── scorer.py         #   risk score
│   ├── recommender.py    #   NIST recommendations
│   ├── reporter.py       #   terminal / JSON / HTML output
│   └── cli.py            #   argparse entry point
├── backend/              # Flask REST API
│   ├── app.py  config.py  extensions.py  models.py
│   ├── auth.py  api.py  billing.py  scanner_service.py
│   ├── requirements.txt   smoke_test.py
├── frontend/             # static dashboard (no build step)
│   ├── index.html  login.html  dashboard.html  scan.html  migration.html
│   ├── style.css  app.js
├── pyproject.toml        # packages cli/ as `quantumsafe`
├── render.yaml  vercel.json  .env.example  README.md
```

---

## NIST PQC references

- **FIPS 203** — Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM / CRYSTALS-Kyber)
- **FIPS 204** — Module-Lattice-Based Digital Signature Algorithm (ML-DSA / CRYSTALS-Dilithium)
- **FIPS 205** — Stateless Hash-Based Digital Signature Algorithm (SLH-DSA / SPHINCS+)
- **NIST SP 800-52 Rev. 2** — TLS guidance
- **NIST SP 800-131A Rev. 2** — transitioning cryptographic algorithms/key lengths
- **NIST IR 8547** — transition to post-quantum cryptography standards

---

## License

MIT — see [LICENSE](LICENSE).

# QuantumSafe — Architecture

This document describes how QuantumSafe is put together: its components, the
pipeline that turns code into a migration plan, and how data flows between the CLI,
the API, the dashboard, and the quantum/post-quantum modules.

For the threat model and the cryptographic reasoning behind the design, see
[WHITEPAPER.md](WHITEPAPER.md). For a one-screen diagram, see
[architecture_diagram.txt](architecture_diagram.txt).

---

## 1. Design principle: one engine, three surfaces

The single most important architectural decision is that **the CLI and the API
share exactly one detection engine** — the `cli/` package (installable as
`quantumsafe`). The scanner, scorer, recommender, and reporter live there. The
backend imports the same package rather than re-implementing detection, so a
terminal scan and a dashboard scan can never disagree.

```
                         cli/ (package: quantumsafe)
                 ┌──────────────────────────────────────┐
   CLI  ───────► │ scanner → scorer → recommender → reporter │
   API  ───────► └──────────────────────────────────────┘
```

The quantum (`quantum/`) and post-quantum (`pqc/`) modules are independent,
self-contained, runnable demonstrations. They are intentionally **not** imported
by the web request path — they are heavy (Qiskit, NumPy) and exist to justify the
risk model and implement the recommended defense, not to serve API traffic.

---

## 2. Components

| Component        | Location     | Responsibility                                                        |
|------------------|--------------|-----------------------------------------------------------------------|
| Scanner          | `cli/scanner.py`     | AST (Python) + regex (11 langs) detection; produces `Finding`s |
| Risk scorer      | `cli/scorer.py`      | `15·HIGH + 5·MED + 1·LOW`, capped at 100; risk bands           |
| Recommender      | `cli/recommender.py` | Maps each family → NIST replacement, FIPS ref, complexity      |
| Reporter         | `cli/reporter.py`    | Terminal / JSON / HTML / SARIF / CycloneDX CBOM / SVG badge    |
| CLI entry point  | `cli/cli.py`         | argparse: `scan`, `auth`, `version`; optional dashboard sync   |
| REST API         | `backend/`           | Flask app: auth, scan ingest, history, exports, migration plan |
| Dashboard        | `frontend/`          | Static site (vanilla JS): scans, findings, plans, settings     |
| Quantum module   | `quantum/`           | Shor + Grover (Qiskit) + resource estimation                   |
| Post-quantum     | `pqc/`               | LWE key-encapsulation mechanism + benchmark                    |
| Benchmark        | `benchmark/`         | Labeled corpus + precision/recall evaluation                   |
| Study            | `study/`             | Empirical scan over real open-source repos                     |

---

## 3. The core pipeline: CLI → API → Scanner → Risk Engine → Export

Every scan, regardless of entry point, flows through the same stages:

```
  INPUT            DETECTION            SCORING            ADVICE            OUTPUT
 ┌──────┐        ┌───────────┐        ┌──────────┐      ┌───────────┐     ┌──────────┐
 │ path │        │  scanner  │        │  scorer  │      │recommender│     │ reporter │
 │ repo │ ─────► │ AST+regex │ ─────► │ 0–100 +  │ ───► │  NIST/    │ ──► │ json/html│
 │ zip  │        │ →Findings │        │  band    │      │  FIPS map │     │ sarif/...│
 └──────┘        └───────────┘        └──────────┘      └───────────┘     └──────────┘
```

1. **Input.** A local path/file (CLI), a public GitHub URL (CLI + API), or an
   uploaded archive (API). Repos are shallow-cloned to a temp directory and
   removed afterward; archives are extracted with path-traversal ("zip-slip")
   guards.
2. **Detection.** `scanner.scan_path()` walks files, skips vendor dirs and
   oversized/minified files, parses Python with `ast`, applies regex rules to all
   languages, skips comment-only lines, honors `# quantumsafe: ignore`, and
   de-duplicates per line/family. It emits a list of `Finding` objects
   (file, line, family, algorithm, severity, reason).
3. **Scoring.** `scorer.calculate_score()` aggregates findings into a 0–100 score
   and `scorer.risk_band()` assigns Low/Medium/High/Critical.
4. **Advice.** `recommender.recommend(family)` attaches the NIST-aligned
   replacement, FIPS reference, and migration complexity to each family.
5. **Output.** `reporter` renders the chosen format (terminal table, JSON, HTML,
   SARIF for GitHub code scanning, CycloneDX CBOM, or an SVG risk badge).

---

## 4. Dashboard flow

```
  Browser (frontend/, static)                 Flask API (backend/)            DB
 ┌───────────────────────────┐               ┌──────────────────────┐    ┌────────┐
 │ index.html  (live demo)   │ ── POST ────► │ /api/v1/demo-scan    │    │        │
 │ login.html  (auth)        │ ── POST ────► │ /auth/register|login │ ─► │ users  │
 │ dashboard.html (overview) │ ── GET  ────► │ /overview /scans     │ ─► │ scans  │
 │ scan.html   (findings)    │ ── POST ────► │ /scan (repo|zip)     │ ─► │findings│
 │ migration.html (plan)     │ ── GET  ────► │ /scans/{id}/migration│    │        │
 └───────────────────────────┘               └──────────────────────┘    └────────┘
        config.js sets window.QUANTUMSAFE_API → API base URL
```

- The **landing page** runs a client-side preview scanner and can call
  `POST /api/v1/demo-scan` to run the *real* engine on a snippet (stored nothing,
  rate-limited).
- **Authenticated** pages call the API with a **JWT** (`Authorization: Bearer`).
  The CLI authenticates with a hashed **API key** (`X-API-Key`).
- The dashboard is a static site with **no build step**; it is configured by a
  single line in `frontend/config.js`.

---

## 5. CLI ↔ dashboard sync

After `quantumsafe auth --key <key> --api-url <url>`, each `quantumsafe scan`
also POSTs its report to `/api/v1/scan/import`, so terminal scans appear in the
web history. `--no-sync` keeps a scan local. The upload uses only the Python
standard library (`urllib`), so the CLI has no heavy runtime dependency on the
backend stack.

```
  quantumsafe scan ──► (local report) ──► POST /api/v1/scan/import ──► dashboard history
                         └── --no-sync: stop here, local only ──┘
```

---

## 6. Quantum + post-quantum module integration

These modules are **runnable companions**, not request-path dependencies:

```
        ┌────────────────────────────────────────────────────────────┐
        │  Detection engine rates RSA/ECC = HIGH, AES-128/SHA-256 = LOW │
        └───────────────┬───────────────────────────┬──────────────────┘
                        │ "why HIGH/LOW?"            │ "what do I use instead?"
                        ▼                            ▼
              quantum/  (the attack)          pqc/  (the defense)
              shor.py  → breaks RSA           lwe_kem.py → quantum-safe KEM
              grover.py→ halves symmetric     benchmark.py → sizes vs RSA/ML-KEM
              resources.py → qubit/depth cost
```

Running `quantum/shor.py` demonstrates *why* a HIGH rating is justified; running
`pqc/lwe_kem.py` demonstrates *that* the recommended replacement actually works.
The detection engine and the API never import these modules, so a deployment that
installs only the core requirements stays lightweight.

---

## 7. Data flow summary

1. **Untrusted input in.** Code (path/repo/zip/snippet) enters via CLI or API.
   Repo URLs are validated (HTTPS GitHub only, no traversal); archives are
   extracted safely; the demo endpoint is rate-limited and persists nothing.
2. **Findings produced.** The shared engine converts input into structured
   `Finding`s — no source code is stored, only metadata (file, line, family,
   severity).
3. **Persisted (authenticated scans only).** Scans and findings are written to the
   database (SQLite in dev, PostgreSQL in prod) and associated with a user.
4. **Served back.** The dashboard reads aggregates (`/overview`), history
   (`/scans`), detail (`/scans/{id}`), and the grouped migration plan
   (`/scans/{id}/migration`), and offers exports in six formats.
5. **Privacy.** GDPR-style endpoints let a user export (`/user/data`) or delete
   (`/user/account`) all of their data.

---

## 8. Deployment topology

```
   Vercel (static)              Render (web service)         Render Postgres
 ┌──────────────────┐  HTTPS  ┌──────────────────────┐     ┌──────────────┐
 │ frontend/  +     │ ──────► │ backend/  Flask API  │ ──► │ users/scans/ │
 │ config.js (API)  │  CORS   │ (gunicorn)           │     │ findings     │
 └──────────────────┘         └──────────────────────┘     └──────────────┘
   PyPI: pip install quantumsafe-scan → CLI runs anywhere, optionally syncs to the API
```

CORS is restricted to `FRONTEND_ORIGIN`; secrets come from environment variables;
the database schema self-heals at boot (adds missing columns, drops obsolete
ones) to survive migrations on hosts without shell access. See
[../DEPLOYMENT.md](../DEPLOYMENT.md).

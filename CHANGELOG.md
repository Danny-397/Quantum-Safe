# Changelog

All notable changes to QuantumSafe are documented here. This project follows
[Semantic Versioning](https://semver.org/).

## [0.2.0] — 2026-07-18

### Added
- **Cross-language usage-awareness.** String/comment masking now spans all
  supported languages (previously Python-only): a lexer-style state machine
  blanks comment and string content for JS/TS, Java, C#, C/C++, Rust, Kotlin,
  Swift, PHP, and Ruby, with **import-aware** handling for Go. A
  **string-argument recovery** pass preserves genuine usages named inside a
  string (e.g. `MessageDigest.getInstance("SHA-1")`). Removes 27 labeled false
  positives (was 14, Python-only).
- **Dependency + lockfile scanning (`dependencies.py`).** Parses manifests and
  lockfiles across pip/npm/go/maven/gem (`requirements.txt`, `pyproject.toml`,
  `package.json`, `go.mod`, `pom.xml`, `Gemfile`, `package-lock.json`,
  `yarn.lock`, `poetry.lock`, `Pipfile.lock`, `Gemfile.lock`, `go.sum`) and flags
  known quantum-vulnerable crypto libraries with **purl** and **direct/transitive
  scope**. On by default (`--no-deps` to disable).
- **Richer CBOM.** CycloneDX output now emits dependency `library` components
  (with purl + scope) alongside algorithm crypto-assets, linked by a
  `dependencies` graph.
- **Reachability ranking (`reachability.py`).** Labels each source finding
  `reachable` / `test-example` / `unreferenced` via a conservative Python call
  graph, sorting exploitable findings above dead/example code. On by default
  (`--no-rank` to disable).
- **Call-site remediation (`remediation.py`).** Every finding carries a concrete
  before/after for drop-ins (MD5/SHA-1 → SHA-256, 3DES/RC4 → AES-256-GCM, TLS →
  1.3) or a PQC migration pointer with a language-appropriate library for
  asymmetric families; surfaced in JSON, HTML, and SARIF help text.
- **Cross-file (whole-program) taint analysis (`callgraph.py`).** The `--taint`
  pass is no longer intra-module: it builds a program-wide Python call graph by
  resolving imports (absolute, relative, unique-suffix) to qualified symbols and
  propagates crypto taint to a fixpoint across files, so a wrapper defined in one
  module and called from another (no crypto keyword at the call site) is flagged,
  with provenance naming the resolving module. Edges are only created on a
  resolved import, so same-named functions can't create phantom taint.
- **Seeded recall benchmark (`benchmark/seeded.py`).** A mutation benchmark with
  ground truth by construction — 50 real quantum-vulnerable API calls across 7
  languages that must be detected, plus 50 comment/string decoys that must not
  be. Latest run: 100% recall, 100% mutation precision.

### Changed
- Labeled benchmark expanded to 18 files (added Java/JS/Go decoys); usage-aware
  engine holds 100% precision/recall while the naive baseline drops to 49.1%.
- Test suite grows to 97 tests.

## [0.1.0]

### Added
- **Quantum module (`quantum/`):** real Qiskit implementations of Shor's
  algorithm (quantum order-finding factors N and recovers an RSA key) and
  Grover's algorithm (key-search speedup), run on a quantum simulator.
- **Post-quantum module (`pqc/`):** a from-scratch lattice-based (LWE) key
  encapsulation mechanism — the foundation of NIST ML-KEM/Kyber — implementing
  the quantum-safe replacement the scanner recommends.
- **Evaluation (`benchmark/`):** labeled precision/recall benchmark (100% on 24
  findings across 9 languages, with comment/word-boundary decoys), enforced by
  tests; scanner now skips comment-only lines to cut false positives.
- **Detection engine:** AST (Python) + regex scanning across Python, JavaScript/
  TypeScript, Java, Go, Ruby, C#, PHP, Rust, C/C++, Kotlin, and Swift.
- **Output formats:** terminal, JSON, standalone HTML, **SARIF 2.1.0**,
  **CycloneDX CBOM**, and an embeddable **SVG risk badge**.
- **False-positive controls:** inline `# quantumsafe: ignore` suppression and
  `--exclude` glob patterns.
- **Backend:** Flask REST API (auth, scans, history, overview, migration plan,
  exports), JWT + bcrypt, hashed API keys, email alerts, rate limiting,
  CORS lockdown. Free, no paywall.
- **Dashboard:** dark Bloomberg-style UI; landing page with an in-browser live
  scanner; auth, overview, scans, findings, migration, settings.
- **Ecosystem:** reusable GitHub Action + code-scanning workflow, pre-commit hook.
- **Ops:** Docker + docker-compose, Render blueprint, Vercel config.
- **Legal/compliance:** Privacy Policy, Terms of Service, signup consent,
  security disclosure policy (SECURITY.md + security.txt).
- **Quality:** 45-test pytest suite, GitHub Actions CI, demo seed script.

[0.2.0]: https://github.com/Danny-397/Quantum-Safe-Scan/releases/tag/v0.2.0
[0.1.0]: https://github.com/Danny-397/Quantum-Safe-Scan/releases/tag/v0.1.0

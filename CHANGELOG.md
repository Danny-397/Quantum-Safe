# Changelog

All notable changes to QuantumSafe are documented here. This project follows
[Semantic Versioning](https://semver.org/).

## [Unreleased]

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

[Unreleased]: https://github.com/Danny-397/Quantum-Safe

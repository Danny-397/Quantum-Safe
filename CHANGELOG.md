# Changelog

All notable changes to QuantumSafe are documented here. This project follows
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- **Quantum module (`quantum/`):** real Qiskit implementations of Shor's
  algorithm (quantum order-finding factors N and recovers an RSA key) and
  Grover's algorithm (key-search speedup), run on a quantum simulator.
- **Detection engine:** AST (Python) + regex scanning across Python, JavaScript/
  TypeScript, Java, Go, Ruby, C#, PHP, Rust, C/C++, Kotlin, and Swift.
- **Output formats:** terminal, JSON, standalone HTML, **SARIF 2.1.0**,
  **CycloneDX CBOM**, and an embeddable **SVG risk badge**.
- **False-positive controls:** inline `# quantumsafe: ignore` suppression and
  `--exclude` glob patterns.
- **Backend:** Flask REST API (auth, scans, history, overview, migration plan,
  exports), JWT + bcrypt, hashed API keys, Stripe billing, Pro email alerts,
  rate limiting, CORS lockdown.
- **Dashboard:** dark Bloomberg-style UI; landing page with an in-browser live
  scanner; auth, overview, scans, findings, migration, settings, billing.
- **Ecosystem:** reusable GitHub Action + code-scanning workflow, pre-commit hook.
- **Ops:** Docker + docker-compose, Render blueprint, Vercel config.
- **Legal/compliance:** Privacy Policy, Terms of Service, signup consent,
  security disclosure policy (SECURITY.md + security.txt).
- **Quality:** 45-test pytest suite, GitHub Actions CI, demo seed script.

[Unreleased]: https://github.com/Danny-397/Quantamn-Safe

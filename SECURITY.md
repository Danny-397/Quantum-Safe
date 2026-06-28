# Security Policy

## Reporting a vulnerability

If you discover a security vulnerability in QuantumSafe, please report it
responsibly. **Do not open a public issue for security problems.**

- Email: **[security@YOUR-DOMAIN]** (replace with your contact address)
- Please include: a description, steps to reproduce, affected component
  (CLI / backend / dashboard), and impact.
- We aim to acknowledge reports within **3 business days** and to provide a
  remediation timeline after triage.

Please give us a reasonable opportunity to address the issue before any public
disclosure. We will credit reporters who wish to be acknowledged.

## Supported versions

This project is under active development; security fixes target the latest
`main`.

## Scope

QuantumSafe is a security-awareness tool that performs static analysis. It is
**not** a substitute for a professional cryptographic audit. Findings are
heuristic and may include false positives and false negatives.

## Handling of scanned code

- Uploaded archives are scanned in a temporary location and deleted immediately
  after the scan; only the resulting findings are stored.
- Repository URLs are validated and restricted to public `https://github.com`
  URLs to avoid SSRF / path-traversal.
- Passwords are hashed with bcrypt; CLI API keys are stored only as SHA-256
  hashes.

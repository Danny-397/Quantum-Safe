# PQC-readiness outreach — doing it responsibly

Running QuantumSafe against real projects and sharing what you find is the fastest
way to turn "I built a tool" into "my tool helped real maintainers." But this must
be done carefully, because **using RSA/ECC today is not a vulnerability** — it's a
migration concern. Treating it like a security bug ("responsible disclosure") and
mass-filing issues would be noise, would annoy maintainers, and would *hurt* your
and the tool's credibility. This guide is the responsible version.

## Principles

1. **It's readiness, not a CVE.** Frame every report as *post-quantum migration
   readiness*, never as an exploit or an emergency. No severity theatrics.
2. **Signal, not spam.** One thoughtful, well-scoped report to a project that
   welcomes it beats fifty drive-by issues. Quality is the whole point.
3. **Respect the project's process.** If there's a `SECURITY.md` or a security
   contact, use it. If issues are for bugs only, ask in Discussions first.
4. **Do the homework.** Open the `file:line` findings yourself. Filter out the
   library's *intended* crypto (a TLS library implementing ECDH is not news) and
   false positives before you send anything.
5. **Be useful.** Include the concrete migration path (the tool's call-site fix),
   not just "you use RSA."
6. **No unsolicited PRs that rip out crypto.** Offer; don't impose. Migration is
   the maintainer's decision.

## Picking good targets

Good candidates are **application / infrastructure projects** where legacy crypto
is incidental and a migration note is genuinely helpful — not crypto libraries
whose job is to implement these algorithms.

- ✅ A web app pinning `TLSv1.2`, using `MD5` for cache keys, or `RSA` for tokens.
- ✅ A CLI/tool using `SHA-1` or `3DES` for legacy compatibility.
- ❌ `cryptography`, `pyca`, `openssl` bindings, `bouncycastle` — they implement
     these on purpose. Reporting "you have RSA" is not helpful.

`python benchmark/realworld.py <package>` gives you a starting inventory with
`file:line` provenance to triage from.

## Generate the readiness report

Produce artifacts a maintainer can actually use:

```bash
# Human-readable, shareable HTML report
quantumsafe scan --repo https://github.com/<org>/<repo> --output readiness.html

# Machine-readable CBOM for their own inventory / SBOM pipeline
quantumsafe scan --repo https://github.com/<org>/<repo> --output readiness.cbom.json

# SARIF, if they use GitHub code scanning
quantumsafe scan --repo https://github.com/<org>/<repo> --output readiness.sarif
```

The HTML/CBOM already include per-finding call-site fixes and direct/transitive
dependency scope, so the report is actionable, not just a list.

## Message template

> **Subject:** Post-quantum migration readiness — a few notes for `<project>`
>
> Hi `<maintainers>`,
>
> I maintain [QuantumSafe](https://github.com/Danny-397/Quantum-Safe-Scan), an
> open-source scanner that inventories quantum-vulnerable cryptography and maps it
> to the NIST PQC standards (FIPS 203/204/205). **This isn't a vulnerability
> report** — everything below is standard crypto that's fine today; the point is a
> head start on the eventual migration ("harvest now, decrypt later" is why teams
> are inventorying early).
>
> I ran it against `<project>` and triaged the results by hand. A few that looked
> genuinely relevant (not intended library crypto):
>
> - `path/to/file.py:42` — `RSA` for `<what>` → ML-KEM/ML-DSA (FIPS 203/204)
> - `path/to/other.js:88` — `MD5` for `<what>` → SHA-256 (drop-in)
>
> Full report attached (HTML + CycloneDX CBOM). Happy to open a PR for the
> straightforward drop-ins (e.g. the MD5 → SHA-256 change) if that's welcome — no
> pressure, and I won't touch the asymmetric ones since those are a design call.
>
> Thanks for the project!

## After you send

- Keep a private log of what you reported and the response — this is the concrete,
  verifiable impact you can point to later.
- If a maintainer engages, offer the drop-in PR. Land one real change and you have
  a genuine open-source contribution story.

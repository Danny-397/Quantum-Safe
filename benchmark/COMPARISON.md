# QuantumSafe vs. other scanners

Why a *dedicated* post-quantum tool, when teams already run security scanners?
Because generic security tooling is **not quantum-aware**: it flags cryptography
that is *classically broken* (MD5, SHA-1, DES) but treats RSA, ECC, DSA, and
Diffie–Hellman as **secure** — which they are, until a cryptographically-relevant
quantum computer exists. On a post-quantum readiness task, that is exactly the
crypto you most need to find.

This page has two parts: a **measured** head-to-head on our labeled corpus, and a
**capability** comparison. Competitor numbers here are produced by actually
running the tool ([`comparison.py`](comparison.py)) — nothing is hand-entered.

## Measured: detection on the labeled corpus

`comparison.py` scores each installed tool against the same ground truth
(`labels.json` — 26 `(file, family)` pairs across 9 languages) and reports how
many quantum-relevant findings each catches:

```bash
pip install bandit          # optional competitor
python benchmark/comparison.py
```

| Tool | Caught / 26 | Recall | Families found | Notes |
|---|--:|--:|---|---|
| **QuantumSafe** | **26** | **100%** | rsa, ecc, dsa, dh, md5, sha1, sha256, 3des, rc4, aes128, tls_old | 9 languages |
| Bandit 1.8 | 2 | 8% | md5, sha1 | Python-only; flags weak hashes, **not** RSA/ECC/DSA/DH |
| Semgrep | _run it_ | — | — | multi-language, pattern-based; not quantum-specific by default |

**Reading the Bandit result fairly:** this is *not* a knock on Bandit — Bandit is
an excellent classical Python security linter and is doing exactly its job. It
catches MD5 and SHA-1 (classically broken) and deliberately says nothing about
RSA/ECC/DSA/DH, because those are not classical vulnerabilities. Its 2/26 is the
whole thesis in one number: **quantum readiness needs a quantum-aware tool.** It
also only sees the 2 Python files in the corpus; the other 24 findings live in
Java, JS, Go, C#, PHP, Ruby, Rust, and Swift, which Bandit doesn't scan at all.

## Capability comparison

Feature presence as documented by each tool (verify against current docs before
citing; captured 2026-07). QuantumSafe's design goal is to be the *integrated,
measured, lightweight* option rather than to beat dedicated enterprise suites on
any single axis.

| Capability | QuantumSafe | Bandit | Semgrep | SonarQube | CBOM/inventory tools¹ |
|---|:--:|:--:|:--:|:--:|:--:|
| Quantum risk model (Shor/Grover severity) | ✅ | ❌ | ❌ | ❌ | ~ |
| Flags RSA/ECC/DSA/DH (classically-secure) | ✅ | ❌ | ~² | ❌ | ✅ |
| Multi-language (11) | ✅ | ❌ (Py) | ✅ | ✅ | ~ |
| Usage-awareness (ignores crypto in comments/strings) | ✅ | ✅ | ~ | ✅ | ~ |
| Dependency + lockfile crypto scan | ✅ | ❌ | ❌ | ~ | ✅ |
| Reachability ranking (live vs dead/test) | ✅ | ❌ | ❌ | ~ | ❌ |
| Call-site PQC remediation (before/after) | ✅ | ❌ | ~ | ~ | ❌ |
| CycloneDX **CBOM** output | ✅ | ❌ | ❌ | ❌ | ✅ |
| SARIF output (GitHub code scanning) | ✅ | ✅ | ✅ | ✅ | ~ |
| Published precision **and** recall benchmark | ✅ | ~ | ~ | ~ | ~ |
| `pip install`, no server/account | ✅ | ✅ | ✅ | ❌ | ~ |

✅ yes · ~ partial / rule- or config-dependent / edition-dependent · ❌ no

¹ *CBOM / crypto-inventory tools* (e.g. CycloneDX generators, IBM CBOMKit, the
Sonar Cryptography plugin) are the closest category — some are genuinely
quantum-aware and produce excellent CBOMs. They generally focus on **inventory**
rather than shipping a severity model, call-site remediation, reachability, and a
measured precision/recall benchmark in one lightweight CLI. This is a
category-level characterization, not a benchmarked claim.

² Semgrep can be *extended* with custom rules to flag asymmetric crypto, but does
not do so out of the box; its default security packs target classical weaknesses.

## Honest framing

- The measured table only includes tools actually installed when `comparison.py`
  ran; install more (e.g. `semgrep`) and re-run to fill it in.
- The capability matrix is a documentation-based feature comparison, not a
  benchmark; competitors evolve, so treat it as a snapshot and verify.
- The corpus is small (26 findings) by design — it is a precision/recall
  regression set, complemented by the seeded recall benchmark
  ([RESULTS-seeded.md](RESULTS-seeded.md)) and the real-world discoveries
  ([RESULTS-realworld.md](RESULTS-realworld.md)).

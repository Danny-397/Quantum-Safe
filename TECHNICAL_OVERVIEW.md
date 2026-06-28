# QuantumSafe — Technical Overview

This document explains *how* QuantumSafe works, the reasoning behind the design,
the cryptography background, and an honest list of limitations. It's written so
the project can be understood and discussed in depth.

---

## 1. The problem: "harvest now, decrypt later"

Large-scale quantum computers threaten the public-key cryptography that secures
most of the internet. Two quantum algorithms matter:

- **Shor's algorithm** efficiently factors integers and computes discrete
  logarithms. This **completely breaks** RSA, Diffie-Hellman, and all
  elliptic-curve cryptography (ECDSA/ECDH/ECC), regardless of key size. A bigger
  RSA key does not help.
- **Grover's algorithm** gives a quadratic speedup for brute-force search. It
  does **not** break symmetric crypto or hashes, but it *halves their effective
  security*: AES-128 → ~64-bit, SHA-256 preimage → ~128-bit. The fix is to
  double the size (AES-256, SHA-384/512), not to abandon them.

The "harvest now, decrypt later" threat is why this matters *today*: an attacker
can record encrypted traffic now and decrypt it once quantum hardware exists. In
2024 NIST finalized the first post-quantum standards (FIPS 203/204/205), so the
migration target is now concrete.

This directly drives QuantumSafe's risk model:

| Class | Why | Risk |
|-------|-----|------|
| RSA, ECC, ECDSA, ECDH, DSA, Diffie-Hellman | Broken by Shor | HIGH |
| MD5, SHA-1 | Already classically broken (collisions) + Grover | HIGH |
| TLS 1.0/1.1, 3DES, RC4, RSA < 2048 | Deprecated / weak | MEDIUM |
| SHA-256, AES-128, TLS 1.2 | Only *weakened* by Grover, still safe | LOW |

---

## 2. Detection engine

The engine lives in one package (`cli/`, importable as `quantumsafe`) used by
both the CLI and the backend, so results never diverge.

### 2.1 Two complementary strategies

**Regex engine** (all languages: Python, JS/TS, Java, Go, Ruby).
Each rule is a `(family, algorithm, risk, why, pattern, languages)` tuple. Word
boundaries and language-specific idioms (e.g. `crypto.generateKeyPairSync('rsa'`,
`rsa.GenerateKey`, `OpenSSL::PKey::RSA`, `MessageDigest.getInstance("MD5")`)
reduce false positives. Regex is the only practical option for five languages
without five real parsers.

**AST engine** (Python only).
For Python we parse the file with the standard `ast` module and walk it, which
is far more precise than regex: it resolves `hashlib.md5(...)`,
`hashlib.new("sha1")`, and `rsa.generate_private_key(...)` as actual *calls* and
ignores matches inside comments. `_dotted_name()` reconstructs dotted attribute
chains (e.g. `hashlib.md5`) from the AST node.

If a Python file has a syntax error, the AST engine degrades gracefully and the
regex engine still runs.

### 2.2 De-duplication (a key design decision)

A single line like `rsa.generate_private_key(key_size=2048)` can match several
rules (the generic `RSA` rule, the `RSA-2048` rule, and possibly the AST rule).
Counting all of them would inflate the risk score.

The fix: every rule has a **family** (`rsa`, `ecc`, `md5`, …). Findings are
collapsed to **one per `(file, line, family)`**, keeping the highest-risk match.
So `RSA-1024` is reported once as the strongest applicable finding, not three
times. This is what makes the score meaningful instead of pattern-spam.

### 2.3 Scoring

The Quantum Risk Score is derived purely from findings (never hardcoded):

```
score = min(100, 15 * HIGH + 5 * MEDIUM + 1 * LOW)
```

Bands: 0–30 Low, 31–60 Medium, 61–80 High, 81–100 Critical. The weights encode
the threat model — a single Shor-breakable primitive (15) outweighs many
Grover-weakened ones (1).

### 2.4 Recommendations

`recommender.py` maps each family to a NIST-aligned replacement, the FIPS
reference, and an estimated migration complexity:

- Key exchange (RSA/ECDH/DH) → **ML-KEM / Kyber** (FIPS 203)
- Signatures (RSA/ECDSA/DSA) → **ML-DSA / Dilithium** (FIPS 204), or SPHINCS+ (FIPS 205)
- Hashes (MD5/SHA-1) → **SHA-3** or SHA-256
- Symmetric (3DES/RC4/AES-128) → **AES-256**

---

## 2b. Quantum module — implementing the attacks (`quantum/`)

The scanner's risk ratings are not asserted on faith; the `quantum/` module runs
the actual quantum algorithms that justify them, on a Qiskit simulator.

- **`shor.py` (why RSA/ECC = HIGH).** Implements quantum **order-finding**: a
  counting register in superposition, controlled modular-exponentiation
  (`a^(2^j) mod N`), and an inverse QFT — i.e. quantum phase estimation. Measuring
  gives `s/r`; continued fractions recover the order `r`; then
  `gcd(a^(r/2) ± 1, N)` yields the factors. The code factors `N=15`, then uses
  the factors to compute `φ(N)` and the RSA private exponent `d = e⁻¹ mod φ(N)`
  and decrypts a ciphertext — a complete, runnable RSA break.
- **`grover.py` (why AES/SHA = LOW).** Implements amplitude amplification
  (oracle reflection + diffuser, `≈(π/4)√N` iterations) to recover a hidden
  `k`-bit key in ~`√(2^k)` queries, demonstrating the quadratic speedup that
  halves effective key length.

**Engineering choice:** Qiskit is a heavy dependency, so the quantum module is
kept *out* of the lightweight CLI package and CI; it has its own
`quantum/requirements.txt`, and its tests `importorskip` Qiskit so the core suite
stays fast.

**Honest scope:** this is genuine quantum computation at the scale anyone can run
Shor end-to-end today. It is not a claim to factor RSA-2048 — that needs
fault-tolerant hardware that does not exist. The point is to demonstrate the real
mechanism, which is exactly what makes the migration case credible.

## 3. Architecture

```
                +------------------+
   pip install  |   quantumsafe    |  scanner.py / scorer.py /
   ───────────► |   (cli/ package) |  recommender.py / reporter.py
                +---------+--------+
                          │  (imported directly — one engine, no drift)
              ┌───────────┴───────────┐
              ▼                       ▼
       quantumsafe CLI         Flask backend (backend/)
       (terminal/JSON/HTML)    REST API + SQLAlchemy + JWT + Stripe
                                       │
                                       ▼
                            Static dashboard (frontend/)
                            vanilla JS, fetches the API
```

**Why share the engine?** The CLI and dashboard must produce identical findings.
Importing the same package guarantees that — there is exactly one place where
"what counts as vulnerable" is defined.

**Data flow for a dashboard scan:** upload `.zip` / repo URL → `scanner_service`
runs the shared engine → `build_report()` produces the canonical report dict →
persisted as `Scan` + `Finding` rows → API serializes the same shape the CLI
emits → the dashboard renders it.

---

## 4. Security decisions

- **Passwords:** bcrypt (salted, adaptive).
- **API keys:** generated as `qs_live_…`, but only a **SHA-256 hash** + a short
  display prefix are stored. A DB leak never exposes usable keys; the full key is
  shown exactly once.
- **Input safety:** repo URLs are restricted to `https://github.com/<org>/<repo>`
  (no SSH, no other hosts, no `..`); zip uploads are checked for "zip slip" path
  traversal before extraction.
- **Transport/abuse:** Flask-Limiter rate limits, CORS restricted to the
  dashboard origin, ORM-only queries (no string SQL).

---

## 5. Honest limitations

A good engineer knows what their tool *doesn't* do:

- **Static, not semantic.** It flags *mentions* of algorithms, not whether they
  are reachable, security-relevant, or already wrapped safely. False positives
  (e.g. an `RSA` string in a comment in a non-Python file) and false negatives
  (crypto via an unrecognized wrapper) are both possible.
- **No data-flow / taint analysis.** It can't tell a 2048-bit RSA key used for
  signing from one used for key transport, so signature-vs-KEM advice is offered
  jointly.
- **Language coverage is pattern-based** outside Python; only Python gets AST
  precision.
- **Not a substitute for a professional cryptographic audit** — it's an
  awareness/triage tool.

## 6. Ecosystem integration (shipped)

- **SARIF 2.1.0 output** (`--output report.sarif`) so findings load into GitHub's
  code-scanning **Security tab**, with per-rule `security-severity`.
- **Reusable GitHub Action** (`action.yml`) + a self-scan workflow that uploads
  SARIF on every push.
- **False-positive controls:** inline `# quantumsafe: ignore` suppression and
  `--exclude` glob patterns.

## 7. Possible future work

- AST/Tree-sitter parsing for JS/Go/Java (precision across all languages).
- CBOM (Cryptography Bill of Materials) export.
- Reachability analysis to rank findings by exploitability.

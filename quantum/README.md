# QuantumSafe — Quantum module

This is the half of QuantumSafe that **uses quantum computing directly.** It
implements the two quantum algorithms that motivate the entire post-quantum
migration the scanner recommends, and runs them on a real quantum simulator
(Qiskit Aer; the same circuits run on IBM Quantum hardware with a token).

The scanner answers *"where is my quantum-vulnerable crypto and what do I replace
it with?"* This module answers *"why is it vulnerable?"* — by running the actual
attack.

## What's here

| File | Algorithm | Demonstrates |
|------|-----------|--------------|
| `shor.py` | **Shor's algorithm** (quantum order-finding + QPE) | Factoring a semiprime and recovering an RSA private key — why RSA/ECC are **HIGH** risk |
| `grover.py` | **Grover's algorithm** | Quadratic search speedup — why AES-128 / SHA-256 are **LOW** risk (halved, not broken) |

## Run it

```bash
pip install -r quantum/requirements.txt
python quantum/shor.py      # factors N=15 via quantum order-finding, then breaks a toy RSA key
python quantum/grover.py    # recovers a hidden k-bit key in ~sqrt(2^k) steps
```

## The math (so the demos aren't a black box)

### Shor's algorithm (breaks RSA / ECC)
RSA's security rests on factoring being hard. Shor reduces factoring `N = p·q`
to **order-finding**: find the period `r` of `f(x) = aˣ mod N` for a random `a`
coprime to `N`. Classically that's exponential; quantumly it's efficient via
**Quantum Phase Estimation** on the modular-multiplication operator, followed by
an inverse QFT. Measuring yields `s/r`; continued fractions recover `r`. If `r`
is even and `a^(r/2) ≢ −1 (mod N)`, then `gcd(a^(r/2) ± 1, N)` are nontrivial
factors. With `p` and `q` the RSA private exponent `d ≡ e⁻¹ (mod φ(N))` falls out
— `shor.py` does exactly this and decrypts a message to prove it.

Shor breaks elliptic-curve crypto too (discrete-log is also order-finding), which
is why **ECDSA/ECDH/ECC are HIGH** in the scanner.

### Grover's algorithm (weakens symmetric crypto & hashes)
Searching `N` unstructured items classically takes ~`N` queries; Grover takes
~`√N` by amplitude amplification (oracle reflection + diffuser, repeated
`≈ (π/4)√N` times). For a `k`-bit key, `2^k → ~2^(k/2)` — effective strength is
**halved**. That weakens but doesn't break symmetric primitives, so the fix is to
double sizes: **AES-128 → AES-256**, **SHA-256 → SHA-384/512** — exactly the
scanner's LOW-risk guidance.

## Honest scope (this is the real state of the art, not a limitation we're hiding)

`shor.py` factors small `N` (15) and `grover.py` searches small key spaces. That
is genuinely as far as anyone can run these algorithms end-to-end today — Shor on
RSA-2048 needs millions of error-corrected qubits that **do not exist yet**.
That gap is the whole reason post-quantum migration is a *future-proofing* effort
and why "harvest now, decrypt later" is the threat: adversaries can store
ciphertext today and decrypt it once the hardware arrives. QuantumSafe exists to
get codebases migrated *before* that day.

## Running on real quantum hardware (optional)

The same circuits run on IBM Quantum: install `qiskit-ibm-runtime`, add your IBM
Quantum API token, and submit to a backend instead of `AerSimulator`. Results are
noisier (today's hardware isn't error-corrected), which is itself an honest
illustration of why large-scale Shor is still years away.

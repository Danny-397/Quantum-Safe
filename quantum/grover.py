"""Grover's algorithm - the quantum speedup that weakens symmetric crypto & hashes.

Grover's algorithm searches an unstructured space of size N in ~sqrt(N) steps
instead of ~N. Applied to brute-forcing a k-bit symmetric key, that turns 2^k
work into ~2^(k/2) - i.e. it *halves the effective key length*. That is exactly
why QuantumSafe rates AES-128 and SHA-256 as LOW (weakened but not broken: move
to AES-256 / SHA-384+) rather than HIGH.

This runs a real Grover search on a quantum simulator: we hide a secret k-bit
"key", build an oracle that recognizes it, and let Grover recover it in
~sqrt(2^k) iterations.

Run:  python quantum/grover.py
"""

from __future__ import annotations

import math

from qiskit import QuantumCircuit, transpile
from qiskit_aer import AerSimulator


def _mcz(qc: QuantumCircuit, qubits: list[int]) -> None:
    """Multi-controlled Z over `qubits` (phase flip on the all-ones state)."""
    *controls, target = qubits
    qc.h(target)
    if controls:
        qc.mcx(controls, target)
    else:
        qc.x(target)
    qc.h(target)


def grover_search(secret: str, shots: int = 1024):
    """Recover an n-bit `secret` string using Grover's algorithm on a simulator."""
    n = len(secret)
    N = 2 ** n
    iterations = max(1, round((math.pi / 4) * math.sqrt(N)))

    qc = QuantumCircuit(n, n)
    qc.h(range(n))  # uniform superposition over all 2^n keys

    for _ in range(iterations):
        # Oracle: phase-flip the state equal to `secret`.
        for i, bit in enumerate(secret):
            if bit == "0":
                qc.x(i)
        _mcz(qc, list(range(n)))
        for i, bit in enumerate(secret):
            if bit == "0":
                qc.x(i)
        # Diffuser: reflect about the uniform superposition.
        qc.h(range(n)); qc.x(range(n))
        _mcz(qc, list(range(n)))
        qc.x(range(n)); qc.h(range(n))

    qc.measure(range(n), range(n))
    sim = AerSimulator()
    counts = sim.run(transpile(qc, sim), shots=shots).result().get_counts()
    # Qiskit returns bitstrings little-endian; reverse to match input order.
    best = max(counts, key=counts.get)[::-1]
    confidence = counts[max(counts, key=counts.get)] / shots
    return best, confidence, iterations, N


def demo() -> None:
    print("Grover's algorithm - quantum search on a quantum simulator")
    print("=" * 60)
    secret = "1011"  # a hidden 4-bit "key"
    found, conf, iters, N = grover_search(secret)
    classical_avg = N // 2
    quantum_steps = iters
    print(f"  Secret {len(secret)}-bit key:        {secret}")
    print(f"  Grover recovered:           {found}  ({'OK' if found == secret else 'FAIL'}, p={conf:.0%})")
    print(f"  Search space (2^{len(secret)}):        {N}")
    print(f"  Classical avg queries:      ~{classical_avg}")
    print(f"  Grover queries:             {quantum_steps}  (~sqrt(N))")
    print()
    print("  Implication: a k-bit key needs ~2^(k/2) Grover steps, so quantum")
    print("  search HALVES effective key strength: AES-128 -> ~64-bit, AES-256 -> ~128-bit.")
    print("  This is why QuantumSafe says: keep AES but move 128 -> 256.")


if __name__ == "__main__":
    demo()

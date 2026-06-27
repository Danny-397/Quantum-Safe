"""NIST post-quantum migration recommendations.

Each cryptographic "family" detected by the scanner maps to a concrete,
NIST-aligned replacement, the relevant FIPS standard, and an estimated
migration complexity. This is referenced by both the CLI reporter and the
backend's Migration Plan endpoint, so the advice stays consistent everywhere.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Recommendation:
    replacement: str
    nist_reference: str
    complexity: str  # "Low" | "Medium" | "High"
    detail: str


# Keyed by the rule "family" used in scanner.py.
RECOMMENDATIONS: dict[str, Recommendation] = {
    "rsa": Recommendation(
        replacement="CRYSTALS-Kyber (ML-KEM) for key exchange / CRYSTALS-Dilithium (ML-DSA) for signatures",
        nist_reference="FIPS 203 (ML-KEM), FIPS 204 (ML-DSA)",
        complexity="High",
        detail=(
            "RSA is broken by Shor's algorithm on a sufficiently large quantum "
            "computer regardless of key size. Use ML-KEM (Kyber) where RSA is "
            "used for key transport/encryption, and ML-DSA (Dilithium) where RSA "
            "is used for digital signatures."
        ),
    ),
    "ecc": Recommendation(
        replacement="CRYSTALS-Kyber (ML-KEM) for ECDH / CRYSTALS-Dilithium (ML-DSA) for ECDSA",
        nist_reference="FIPS 203 (ML-KEM), FIPS 204 (ML-DSA)",
        complexity="High",
        detail=(
            "Elliptic-curve cryptography (ECDSA/ECDH/ECC) is broken by Shor's "
            "algorithm. Replace ECDH key agreement with ML-KEM (Kyber) and ECDSA "
            "signatures with ML-DSA (Dilithium)."
        ),
    ),
    "dsa": Recommendation(
        replacement="CRYSTALS-Dilithium (ML-DSA)",
        nist_reference="FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA / SPHINCS+)",
        complexity="High",
        detail=(
            "DSA signatures are broken by Shor's algorithm. Migrate to ML-DSA "
            "(Dilithium), or SLH-DSA (SPHINCS+) where a hash-based, "
            "conservative-assumption signature is preferred."
        ),
    ),
    "dh": Recommendation(
        replacement="CRYSTALS-Kyber (ML-KEM)",
        nist_reference="FIPS 203 (ML-KEM)",
        complexity="High",
        detail=(
            "Classic Diffie-Hellman key exchange is broken by Shor's algorithm. "
            "Replace with ML-KEM (Kyber), optionally in a hybrid construction "
            "with an existing classical KEX during transition."
        ),
    ),
    "md5": Recommendation(
        replacement="SHA-3 (SHA3-256) or SHA-256",
        nist_reference="FIPS 202 (SHA-3), FIPS 180-4 (SHA-2)",
        complexity="Low",
        detail=(
            "MD5 is cryptographically broken (practical collisions) and is "
            "further weakened by Grover's algorithm. Replace with SHA-3 or SHA-256."
        ),
    ),
    "sha1": Recommendation(
        replacement="SHA-3 (SHA3-256) or SHA-256",
        nist_reference="FIPS 202 (SHA-3), FIPS 180-4 (SHA-2)",
        complexity="Low",
        detail=(
            "SHA-1 is broken (practical collisions, e.g. SHAttered) and weakened "
            "by Grover's algorithm. Replace with SHA-3 or SHA-256."
        ),
    ),
    "tls_old": Recommendation(
        replacement="TLS 1.3",
        nist_reference="NIST SP 800-52 Rev. 2",
        complexity="Low",
        detail=(
            "TLS 1.0/1.1 are deprecated and use quantum-vulnerable key exchange. "
            "Upgrade to TLS 1.3 and plan for hybrid PQC key exchange."
        ),
    ),
    "3des": Recommendation(
        replacement="AES-256",
        nist_reference="FIPS 197 (AES), NIST SP 800-131A Rev. 2",
        complexity="Low",
        detail=(
            "3DES/Triple-DES is deprecated and its effective security is halved "
            "by Grover's algorithm. Replace with AES-256."
        ),
    ),
    "rc4": Recommendation(
        replacement="AES-256 (GCM)",
        nist_reference="FIPS 197 (AES), NIST SP 800-131A Rev. 2",
        complexity="Low",
        detail=(
            "RC4 is insecure and prohibited for TLS. Replace with AES-256 in an "
            "AEAD mode such as GCM."
        ),
    ),
    "sha256": Recommendation(
        replacement="SHA-256 (acceptable) - consider SHA-384/512 or SHA3 for long-term",
        nist_reference="FIPS 180-4 (SHA-2), FIPS 202 (SHA-3)",
        complexity="Low",
        detail=(
            "Grover's algorithm reduces SHA-256's preimage resistance to ~128 "
            "bits, which remains secure. Monitor; for long-lived data consider "
            "SHA-384/512 or SHA-3."
        ),
    ),
    "aes128": Recommendation(
        replacement="AES-256",
        nist_reference="FIPS 197 (AES)",
        complexity="Low",
        detail=(
            "Grover's algorithm halves AES-128's effective security to ~64 bits. "
            "Move to AES-256 for quantum-resistant symmetric encryption."
        ),
    ),
    "tls12": Recommendation(
        replacement="TLS 1.3",
        nist_reference="NIST SP 800-52 Rev. 2",
        complexity="Low",
        detail=(
            "TLS 1.2 is acceptable today but still relies on classical key "
            "exchange. Plan migration to TLS 1.3 with hybrid PQC key exchange."
        ),
    ),
}

_FALLBACK = Recommendation(
    replacement="Review against NIST PQC guidance",
    nist_reference="NIST IR 8547 (PQC transition)",
    complexity="Medium",
    detail="Manually review this usage against current NIST post-quantum guidance.",
)


def recommend(family: str) -> Recommendation:
    """Return the migration recommendation for a detection family."""
    return RECOMMENDATIONS.get(family, _FALLBACK)

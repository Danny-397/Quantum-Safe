"""Call-site-specific remediation.

:mod:`cli.recommender` answers *"what standard should replace this family?"* at
the level of a whole algorithm family. This module answers the next question an
engineer actually asks — *"what do I change on this line?"* — by pairing each
finding with a concrete before/after in the finding's own language.

Two shapes of fix:

* **Drop-in** (hashes, symmetric ciphers, TLS versions): a like-for-like swap
  exists — MD5/SHA-1 → SHA-256/SHA3, 3DES/RC4 → AES-256-GCM, AES-128 → AES-256,
  TLS 1.0/1.1/1.2 → TLS 1.3 — so we show the exact replacement pattern.
* **Migration** (RSA/ECC/DSA/DH): there is *no* like-for-like swap; these need a
  PQC scheme (ML-KEM / ML-DSA) and usually a hybrid during transition, so we give
  the target scheme, a language-appropriate library pointer, and an honest note
  that it is a design change, not a one-liner.

This module deliberately imports nothing from :mod:`cli.scanner` so it can be a
leaf dependency (the scanner imports *it*).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class Fix:
    action: str            # imperative one-line instruction
    drop_in: bool          # True if a like-for-like replacement exists
    before: str = ""       # representative vulnerable pattern
    after: str = ""        # representative safe replacement
    guidance: str = ""     # caveats / hybrid / migration notes
    library: str = ""      # suggested library where relevant

    def to_dict(self) -> dict:
        return asdict(self)


# --------------------------------------------------------------------------- #
# Drop-in replacements (per family, per language)
# --------------------------------------------------------------------------- #
#
# Keyed by family -> language -> (before, after). "" is the language-agnostic
# fallback used when we don't have a language-specific snippet.

_WEAK_HASH = {  # md5 + sha1 share the same replacement target
    "python":     ("hashlib.md5(data)", "hashlib.sha256(data)  # or hashlib.sha3_256(data)"),
    "javascript": ('crypto.createHash("md5")', 'crypto.createHash("sha256")'),
    "java":       ('MessageDigest.getInstance("MD5")', 'MessageDigest.getInstance("SHA-256")'),
    "go":         ("md5.New()  // crypto/md5", "sha256.New()  // crypto/sha256"),
    "ruby":       ("Digest::MD5.hexdigest(x)", "Digest::SHA256.hexdigest(x)"),
    "php":        ('md5($x)', 'hash("sha256", $x)'),
    "csharp":     ("MD5.Create()", "SHA256.Create()"),
    "":           ("an MD5/SHA-1 digest", "a SHA-256 or SHA3-256 digest"),
}

_WEAK_CIPHER = {  # 3des + rc4 -> AES-256-GCM
    "python":     ("Cipher(algorithms.TripleDES(key), modes.CBC(iv))",
                   "AESGCM(key)                      # cryptography.hazmat AEAD, 256-bit key"),
    "javascript": ('crypto.createCipheriv("des-ede3-cbc", key, iv)',
                   'crypto.createCipheriv("aes-256-gcm", key, iv)'),
    "java":       ('Cipher.getInstance("DESede/CBC/PKCS5Padding")',
                   'Cipher.getInstance("AES/GCM/NoPadding")   // 256-bit key'),
    "":           ("a 3DES/RC4 cipher", "AES-256 in an AEAD mode (GCM)"),
}

_AES128 = {
    "python":     ("AESGCM(key)  # 128-bit key", "AESGCM(key)  # use a 256-bit key"),
    "javascript": ('crypto.createCipheriv("aes-128-gcm", key, iv)',
                   'crypto.createCipheriv("aes-256-gcm", key, iv)'),
    "java":       ("new SecretKeySpec(key128, \"AES\")", "new SecretKeySpec(key256, \"AES\")"),
    "":           ("AES-128", "AES-256 (same API, 256-bit key)"),
}

_TLS = {
    "python":     ("ssl.PROTOCOL_TLSv1 / TLSv1_2",
                   "ctx.minimum_version = ssl.TLSVersion.TLSv1_3"),
    "javascript": ('secureProtocol: "TLSv1_method"',
                   'minVersion: "TLSv1.3"'),
    "java":       ('SSLContext.getInstance("TLSv1.2")',
                   'SSLContext.getInstance("TLSv1.3")'),
    "":           ("TLS 1.0 / 1.1 / 1.2", "TLS 1.3 (and plan hybrid PQC key exchange)"),
}

# Language -> PQC library pointer for the asymmetric migration path.
_PQC_LIB = {
    "python":     "liboqs-python (`oqs`) for ML-KEM/ML-DSA; pyca/cryptography for the hybrid classical half",
    "java":       "BouncyCastle PQC provider (`org.bouncycastle.pqc`)",
    "javascript": "@open-quantum-safe / liboqs Node bindings",
    "go":         "Cloudflare CIRCL (`github.com/cloudflare/circl`)",
    "rust":       "`pqcrypto` / `oqs` crates",
    "":           "an ML-KEM / ML-DSA implementation such as liboqs",
}

# Asymmetric families -> (target scheme, role description).
_ASYM = {
    "rsa": ("ML-KEM (Kyber) for key transport, ML-DSA (Dilithium) for signatures",
            "RSA is used for both encryption/key-transport and signatures; pick the "
            "PQC scheme matching each usage"),
    "ecc": ("ML-KEM (Kyber) for ECDH, ML-DSA (Dilithium) for ECDSA",
            "map ECDH key agreement to ML-KEM and ECDSA signatures to ML-DSA"),
    "dsa": ("ML-DSA (Dilithium), or SLH-DSA (SPHINCS+) for a hash-based option",
            "replace DSA signatures with a lattice or hash-based PQC signature"),
    "dh":  ("ML-KEM (Kyber)", "replace the Diffie-Hellman key exchange with an ML-KEM KEM"),
}


def _pick(table: dict, language: str) -> tuple[str, str]:
    return table.get(language) or table[""]


def remediate(family: str, language: str = "", snippet: str = "") -> Fix:
    """Return a concrete, language-aware :class:`Fix` for a detection family."""
    lang = language or ""

    if family in ("md5", "sha1"):
        before, after = _pick(_WEAK_HASH, lang)
        return Fix(
            action="Replace this weak hash with SHA-256 or SHA3-256.",
            drop_in=True, before=before, after=after,
            guidance="A like-for-like swap: same digest workflow, quantum-resistant "
                     "output size. Only re-hashing stored digests requires care.",
        )
    if family in ("3des", "rc4"):
        before, after = _pick(_WEAK_CIPHER, lang)
        return Fix(
            action="Replace this legacy cipher with AES-256 in an AEAD mode (GCM).",
            drop_in=True, before=before, after=after,
            guidance="Rotate keys to 256-bit and prefer GCM for authenticated encryption.",
        )
    if family == "aes128":
        before, after = _pick(_AES128, lang)
        return Fix(
            action="Move AES-128 to a 256-bit key (Grover halves the effective strength).",
            drop_in=True, before=before, after=after,
            guidance="Same API and mode; only the key length changes.",
        )
    if family in ("tls_old", "tls12"):
        before, after = _pick(_TLS, lang)
        return Fix(
            action="Require TLS 1.3 as the minimum protocol version.",
            drop_in=True, before=before, after=after,
            guidance="TLS 1.3 removes the legacy key exchanges; plan a hybrid PQC "
                     "key-exchange group as it becomes available in your stack.",
        )
    if family == "sha256":
        return Fix(
            action="No change required — SHA-256 stays ~128-bit secure under Grover.",
            drop_in=True,
            guidance="For very long-lived data you may prefer SHA-384/512 or SHA3.",
        )
    if family in _ASYM:
        target, role = _ASYM[family]
        return Fix(
            action=f"Migrate to {target}. This is a design change, not a drop-in.",
            drop_in=False,
            before=snippet.strip()[:120] if snippet else "",
            after=f"{target} (deploy in a hybrid with the existing classical scheme "
                  "during transition)",
            guidance=f"No like-for-like replacement exists: {role}. Adopt a hybrid "
                     "(classical + PQC) construction first so security never drops "
                     "below today's during rollout.",
            library=_PQC_LIB.get(lang) or _PQC_LIB[""],
        )
    return Fix(
        action="Review against current NIST PQC guidance.",
        drop_in=False,
        guidance="No specific remediation template for this family.",
    )

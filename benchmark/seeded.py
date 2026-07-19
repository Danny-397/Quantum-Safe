"""Seeded (mutation) benchmark — measures **recall** with ground truth by construction.

``evaluate.py`` measures precision on a small hand-labeled corpus. This harness
measures the complementary axis — *recall across the many idiomatic ways each
quantum-vulnerable primitive is actually written* — at a scale hand-labeling
can't reach, because the ground truth is known **by construction**: every seeded
snippet is a real vulnerable API call for a known family, so a miss is
unambiguously a false negative.

For each (language, family, variant) it:

1. embeds the vulnerable snippet in a minimal host file and scans it — the family
   MUST be detected (else it's a false negative → lowers recall);
2. embeds the *same algorithm name* only in a comment and a prose string — the
   family must NOT be detected (else it's a false positive under mutation).

Results are written to ``benchmark/RESULTS-seeded.md`` and ``seeded.json``.

    python benchmark/seeded.py

Honest scope: these are idiomatic single-call usages, so this measures recall
over API *variety*, not over deliberately obfuscated wrappers (that is the
`--taint` engine's job). It is a regression guard on detection breadth, not a
claim of perfect recall on arbitrary code.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from quantumsafe.scanner import scan_path  # noqa: E402

BASE = os.path.dirname(os.path.abspath(__file__))

# Minimal host per language ({SNIPPET} is replaced). Files need not compile — the
# engine is line/AST based — but they mirror realistic single-line usage.
_HOST = {
    "python":     "{SNIPPET}\n",
    "javascript": "{SNIPPET}\n",
    "java":       "class Demo {{ void run() throws Exception {{ {SNIPPET} }} }}\n",
    "go":         "package main\n\n{SNIPPET}\n",
    "ruby":       "{SNIPPET}\n",
    "php":        "<?php\n{SNIPPET}\n",
    "csharp":     "class Demo {{ void Run() {{ {SNIPPET} }} }}\n",
}
_EXT = {"python": "py", "javascript": "js", "java": "java", "go": "go",
        "ruby": "rb", "php": "php", "csharp": "cs"}

# Idiomatic vulnerable usages: language -> family -> [variants]. Every entry is a
# genuine call to the named primitive (the ground-truth positive).
CASES: dict[str, dict[str, list[str]]] = {
    "python": {
        "md5": ['h = hashlib.md5(b"x")', 'h = hashlib.new("md5")'],
        "sha1": ['h = hashlib.sha1(b"x")'],
        "sha256": ['h = hashlib.sha256(b"x")'],
        "rsa": ['k = rsa.generate_private_key(public_exponent=65537, key_size=2048)'],
        "ecc": ['k = ec.generate_private_key(ec.SECP256R1())'],
        "dsa": ['k = dsa.generate_private_key(key_size=2048)'],
        "dh": ['p = dh.generate_parameters(generator=2, key_size=2048)'],
        "3des": ['c = algorithms.TripleDES(key)'],
        "rc4": ['c = algorithms.ARC4(key)'],
        "tls_old": ['ctx = ssl.PROTOCOL_TLSv1'],
        "tls12": ['ctx = ssl.PROTOCOL_TLSv1_2'],
    },
    "javascript": {
        "md5": ['const h = crypto.createHash("md5");'],
        "sha1": ['const h = crypto.createHash("sha1");'],
        "sha256": ['const h = crypto.createHash("sha256");'],
        "rsa": ['crypto.generateKeyPairSync("rsa", {});'],
        "ecc": ['crypto.generateKeyPairSync("ec", {});'],
        "dsa": ['crypto.generateKeyPairSync("dsa", {});'],
        "3des": ['crypto.createCipheriv("des-ede3-cbc", key, iv);'],
        "rc4": ['crypto.createCipheriv("rc4", key, iv);'],
        "aes128": ['crypto.createCipheriv("aes-128-gcm", key, iv);'],
        "tls_old": ['const ctx = tls.createSecureContext({ secureProtocol: "TLSv1_method" });'],
    },
    "java": {
        "md5": ['MessageDigest d = MessageDigest.getInstance("MD5");'],
        "sha1": ['MessageDigest d = MessageDigest.getInstance("SHA-1");'],
        "rsa": ['KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");'],
        "ecc": ['KeyPairGenerator g = KeyPairGenerator.getInstance("EC");'],
        "dsa": ['KeyPairGenerator g = KeyPairGenerator.getInstance("DSA");'],
        "dh": ['KeyPairGenerator g = KeyPairGenerator.getInstance("DiffieHellman");'],
        "3des": ['Cipher c = Cipher.getInstance("DESede/CBC/PKCS5Padding");'],
        "rc4": ['Cipher c = Cipher.getInstance("RC4");'],
    },
    "go": {
        "md5": ['var h = md5.New()'],
        "sha1": ['var h = sha1.New()'],
        "rsa": ['k, _ := rsa.GenerateKey(rand.Reader, 2048)'],
        "ecc": ['import "crypto/ecdsa"'],
        "dsa": ['import "crypto/dsa"'],
        "3des": ['c, _ := des.NewTripleDESCipher(key)'],
        "rc4": ['c, _ := rc4.NewCipher(key)'],
    },
    "ruby": {
        "md5": ['d = Digest::MD5.hexdigest("a")'],
        "sha1": ['d = Digest::SHA1.hexdigest("a")'],
        "rsa": ['k = OpenSSL::PKey::RSA.new(2048)'],
        "3des": ['c = OpenSSL::Cipher.new("des-ede3-cbc")'],
        "rc4": ['c = OpenSSL::Cipher.new("RC4")'],
    },
    "php": {
        "md5": ['$h = md5($x);'],
        "sha1": ['$h = sha1($x);'],
        "sha256": ['$h = hash("sha256", $x);'],
        "rsa": ['$k = openssl_pkey_new(array("private_key_type" => OPENSSL_KEYTYPE_RSA));'],
    },
    "csharp": {
        "md5": ['var h = MD5.Create();'],
        "sha1": ['var h = SHA1.Create();'],
        "rsa": ['var r = new RSACryptoServiceProvider(2048);'],
        "3des": ['var t = new TripleDESCryptoServiceProvider();'],
    },
}

# Human-facing keyword per family, used to build the negative (decoy) mutation.
_DECOY_KW = {
    "md5": "MD5", "sha1": "SHA-1", "sha256": "SHA-256", "rsa": "RSA",
    "ecc": "ECDSA", "dsa": "DSA", "dh": "Diffie-Hellman", "3des": "3DES",
    "rc4": "RC4", "aes128": "AES-128", "tls_old": "TLSv1", "tls12": "TLS 1.2",
}
_DECOY_COMMENT = {
    "python": "# {kw}\n", "ruby": "# {kw}\n", "php": "// {kw}\n",
    "javascript": "// {kw}\n", "java": "// {kw}\n", "go": "// {kw}\n",
    "csharp": "// {kw}\n",
}


def _detect(tmp: str, lang: str, body: str) -> set[str]:
    path = os.path.join(tmp, f"case.{_EXT[lang]}")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(body)
    families = {f.family for f in scan_path(path)}
    os.remove(path)
    return families


def evaluate() -> dict:
    """Run all seeded cases; return recall/precision metrics (no files written)."""
    by_lang: dict[str, dict] = {}
    by_family: dict[str, dict] = {}
    misses: list[str] = []
    decoy_fps: list[str] = []
    total = detected = decoys = decoy_hits = 0

    with tempfile.TemporaryDirectory(prefix="qsseed_") as tmp:
        for lang, families in CASES.items():
            for family, variants in families.items():
                kw = _DECOY_KW[family]
                for variant in variants:
                    total += 1
                    by_lang.setdefault(lang, {"n": 0, "hit": 0})
                    by_family.setdefault(family, {"n": 0, "hit": 0})
                    by_lang[lang]["n"] += 1
                    by_family[family]["n"] += 1

                    body = _HOST[lang].format(SNIPPET=variant)
                    if family in _detect(tmp, lang, body):
                        detected += 1
                        by_lang[lang]["hit"] += 1
                        by_family[family]["hit"] += 1
                    else:
                        misses.append(f"{lang}/{family}: {variant}")

                    # Negative mutation: same keyword only in a comment + a string.
                    decoys += 1
                    comment = _DECOY_COMMENT[lang].format(kw=kw)
                    prose = _HOST[lang].format(SNIPPET=f'note = "{kw} was removed";')
                    if family in _detect(tmp, lang, comment + prose):
                        decoy_hits += 1
                        decoy_fps.append(f"{lang}/{family}")

    recall = detected / total if total else 1.0
    decoy_precision = 1 - (decoy_hits / decoys) if decoys else 1.0
    return {
        "total": total, "detected": detected, "recall": recall,
        "decoys": decoys, "decoy_false_positives": decoy_hits,
        "decoy_precision": decoy_precision,
        "by_language": {k: {**v, "recall": v["hit"] / v["n"]} for k, v in by_lang.items()},
        "by_family": {k: {**v, "recall": v["hit"] / v["n"]} for k, v in by_family.items()},
        "misses": misses, "decoy_fp_cases": decoy_fps,
    }


def _to_markdown(r: dict, generated_at: str) -> str:
    langs = "\n".join(
        f"| {k} | {v['n']} | {v['hit']} | {v['recall']:.0%} |"
        for k, v in sorted(r["by_language"].items())
    )
    fams = "\n".join(
        f"| {k} | {v['n']} | {v['hit']} | {v['recall']:.0%} |"
        for k, v in sorted(r["by_family"].items())
    )
    miss_block = ("\n".join(f"- `{m}`" for m in r["misses"])
                  if r["misses"] else "_none — every seeded variant was detected._")
    return f"""# Seeded (mutation) recall benchmark

Generated by [`seeded.py`](seeded.py). Ground truth is known **by construction**:
each case is a real quantum-vulnerable API call, so a miss is unambiguously a
false negative. Reproduce with:

```bash
python benchmark/seeded.py
```

_Generated: {generated_at}_

## Headline

- **Seeded positive cases:** {r['total']} across {len(r['by_language'])} languages
- **Detected (recall):** {r['detected']} / {r['total']} = **{r['recall']:.1%}**
- **Negative mutations (keyword in comment/string):** {r['decoys']}
- **False positives under mutation:** {r['decoy_false_positives']} \
(**{r['decoy_precision']:.1%}** precision)

## Recall by language

| Language | Cases | Detected | Recall |
|---|--:|--:|--:|
{langs}

## Recall by family

| Family | Cases | Detected | Recall |
|---|--:|--:|--:|
{fams}

## Missed cases (false negatives)

{miss_block}

> Scope: idiomatic single-call usages — this measures recall over API *variety*,
> complementing the precision figure in [RESULTS.md](RESULTS.md). Obfuscated
> wrapper chains are handled separately by the `--taint` data-flow engine.
"""


def main() -> int:
    r = evaluate()
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    with open(os.path.join(BASE, "seeded.json"), "w", encoding="utf-8") as fh:
        json.dump({"generated_at": generated_at, **r}, fh, indent=2)
    with open(os.path.join(BASE, "RESULTS-seeded.md"), "w", encoding="utf-8") as fh:
        fh.write(_to_markdown(r, generated_at))

    print("QuantumSafe scanner — seeded recall benchmark")
    print("=" * 60)
    print(f"  Positive cases: {r['total']}   Detected: {r['detected']}   "
          f"Recall: {r['recall']:.1%}")
    print(f"  Negative mutations: {r['decoys']}   False positives: "
          f"{r['decoy_false_positives']}   Precision: {r['decoy_precision']:.1%}")
    if r["misses"]:
        print("  Missed:")
        for m in r["misses"]:
            print(f"    - {m}")
    print(f"  Wrote {os.path.join(BASE, 'RESULTS-seeded.md')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

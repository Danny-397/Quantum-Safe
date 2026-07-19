"""Tests for the core detection engine."""

import pytest

from quantumsafe.scanner import (
    RISK_HIGH,
    RISK_LOW,
    _validate_repo_url,
    scan_path,
)


def _write(tmp_path, name, content):
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return p


def test_detects_rsa_md5_sha1_in_python(tmp_path):
    _write(tmp_path, "crypto.py",
           "import hashlib\n"
           "from cryptography.hazmat.primitives.asymmetric import rsa\n"
           "k = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
           "h = hashlib.md5(b'x')\n"
           "g = hashlib.sha1(b'y')\n")
    findings = scan_path(str(tmp_path))
    algos = {f.algorithm for f in findings}
    assert any("RSA" in a for a in algos)
    assert "MD5" in algos
    assert "SHA-1" in algos
    assert all(f.risk_level == RISK_HIGH for f in findings if f.algorithm in ("MD5", "SHA-1"))


def test_detects_across_languages(tmp_path):
    _write(tmp_path, "app.js", "const k = crypto.generateKeyPairSync('rsa', {});\n")
    _write(tmp_path, "Main.java", 'MessageDigest.getInstance("SHA-1");\n')
    _write(tmp_path, "main.go", 'import "crypto/ecdsa"\n')
    _write(tmp_path, "x.rb", "Digest::MD5.hexdigest('a')\n")
    families = {f.family for f in scan_path(str(tmp_path))}
    assert {"rsa", "sha1", "ecc", "md5"} <= families


def test_detects_extended_languages(tmp_path):
    _write(tmp_path, "a.cs", "var rsa = new RSACryptoServiceProvider(2048);\nvar md5 = MD5.Create();\n")
    _write(tmp_path, "b.php", "<?php $k = openssl_pkey_new(); $h = md5($data); ?>\n")
    _write(tmp_path, "c.rs", "use rsa::RsaPrivateKey;\nlet d = Sha1::new();\n")
    _write(tmp_path, "d.swift", "let digest = Insecure.MD5.hash(data: data)\n")
    families = {f.family for f in scan_path(str(tmp_path))}
    assert "rsa" in families
    assert "md5" in families
    assert "sha1" in families


def test_deduplicates_per_line_and_family(tmp_path):
    # This line matches the generic RSA rule, the RSA-2048 rule, AND the AST rule.
    _write(tmp_path, "c.py",
           "from cryptography.hazmat.primitives.asymmetric import rsa\n"
           "k = rsa.generate_private_key(public_exponent=3, key_size=2048)\n")
    findings = scan_path(str(tmp_path))
    line2 = [f for f in findings if f.line_number == 2 and f.family == "rsa"]
    assert len(line2) == 1, f"expected 1 deduped rsa finding, got {len(line2)}"


def test_clean_code_has_no_findings(tmp_path):
    _write(tmp_path, "ok.py", "def add(a, b):\n    return a + b\n")
    assert scan_path(str(tmp_path)) == []


def test_minified_files_are_skipped(tmp_path):
    # Same matching content: the normal file is flagged, the minified ones are not
    # (machine-generated bundles are skipped to avoid false positives).
    snippet = "const k = crypto.createCipheriv('rc4', key, iv);\n"
    _write(tmp_path, "net.js", snippet)              # detected
    _write(tmp_path, "net.min.js", snippet)          # skipped by name
    _write(tmp_path, "vendor-min.js", snippet)       # skipped by name
    _write(tmp_path, "app.bundle.js", snippet)       # skipped by name
    _write(tmp_path, "packed.js", "x();" + "a" * 2100 + snippet)  # skipped: huge line
    files = {f.file_path for f in scan_path(str(tmp_path))}
    assert files == {"net.js"}, f"expected only net.js, got {files}"


def test_python_string_and_comment_matches_are_ignored(tmp_path):
    # Crypto keywords inside docstrings, log messages, and exception strings are
    # documentation, not usage, and must not be flagged. Real usage in the same
    # file is still detected by the AST engine.
    _write(tmp_path, "svc.py",
           "import hashlib\n"
           "def rotate():\n"
           '    """This service no longer uses MD5 or RSA or ECDSA."""\n'
           '    logger.info("Disabling RSA and DSA fallback")\n'
           '    raise ValueError("SHA-1 is not allowed")\n'
           '    return hashlib.md5(b"x")   # real usage, still caught\n')
    algos = {f.algorithm for f in scan_path(str(tmp_path))}
    assert algos == {"MD5"}, f"expected only the real MD5 usage, got {algos}"


def test_string_masking_is_what_removes_false_positives(tmp_path):
    # Without masking (naive line regex) the same decoy yields false positives;
    # masking is what removes them. This guards the precision improvement.
    _write(tmp_path, "d.py",
           "def f():\n"
           '    """uses RSA and MD5"""\n'
           '    log("ECDSA here")\n')
    assert scan_path(str(tmp_path)) == []
    naive = {f.algorithm for f in scan_path(str(tmp_path), mask_strings=False)}
    assert {"RSA", "MD5", "ECDSA"} <= naive


def test_cross_language_string_and_comment_awareness(tmp_path):
    # Non-Python usage-awareness: crypto names in trailing/block comments and in
    # prose string literals must be ignored, while genuine usages whose algorithm
    # is named *inside* a string argument (getInstance("SHA-1")) are still caught.
    _write(tmp_path, "Legacy.java",
           "public class L {\n"
           "  int n = 2048; // was an RSA-2048 key\n"
           "  /* dropped MD5 and ECDSA long ago */\n"
           '  void run() throws Exception {\n'
           '    String note = "migrated off 3DES and RC4";\n'
           '    MessageDigest d = MessageDigest.getInstance("SHA-1");\n'
           '    Cipher c = Cipher.getInstance("DESede/CBC/PKCS5Padding");\n'
           "  }\n"
           "}\n")
    families = {f.family for f in scan_path(str(tmp_path))}
    # Real usages recovered from string arguments:
    assert "sha1" in families
    assert "3des" in families
    # Prose/comment mentions NOT flagged:
    assert "rsa" not in families
    assert "ecc" not in families
    assert "rc4" not in families  # only appeared inside a prose string
    assert "md5" not in families


def test_js_string_argument_usage_survives_masking(tmp_path):
    _write(tmp_path, "net.js",
           'const k = crypto.generateKeyPairSync("rsa", {});\n'
           'const ctx = tls.createSecureContext({ secureProtocol: "TLSv1_method" });\n'
           'const c = crypto.createCipheriv("aes-128-gcm", key, iv);\n'
           'console.log("never use MD5 or ECDSA");\n')
    families = {f.family for f in scan_path(str(tmp_path))}
    assert {"rsa", "tls_old", "aes128"} <= families
    assert "md5" not in families and "ecc" not in families


def test_go_import_strings_are_preserved_but_comments_masked(tmp_path):
    # Go's detection relies on import *strings*, so those must survive, while a
    # crypto name in a trailing comment must not be flagged.
    _write(tmp_path, "main.go",
           'package main\n'
           'import "crypto/ecdsa"\n'
           'var x = 1 // migrated off RSA\n')
    families = {f.family for f in scan_path(str(tmp_path))}
    assert "ecc" in families
    assert "rsa" not in families


def test_dependency_scanning_flags_known_crypto_packages(tmp_path):
    _write(tmp_path, "requirements.txt",
           "cryptography==42.0.5\nrsa==4.9\nrequests>=2.0\n# a comment\n")
    _write(tmp_path, "package.json",
           '{"dependencies": {"node-forge": "^1.3.1", "left-pad": "1.0.0"}}')

    findings = scan_path(str(tmp_path), scan_deps=True)
    deps = [f for f in findings if f.origin == "dependency"]
    assert deps, "expected dependency findings"

    components = {f.component for f in deps}
    assert {"cryptography", "rsa", "node-forge"} <= components
    # Non-crypto packages are never flagged.
    assert "requests" not in components and "left-pad" not in components

    # Findings carry a purl and a pinned version where available.
    crypto = next(f for f in deps if f.component == "cryptography")
    assert crypto.purl == "pkg:pypi/cryptography@42.0.5"
    assert crypto.version == "42.0.5"
    assert crypto.confidence == "medium"


def test_dependency_scanning_is_opt_in(tmp_path):
    _write(tmp_path, "requirements.txt", "cryptography==42.0.5\n")
    # Default (scan_deps=False) must not read manifests, so behavior is unchanged.
    assert all(f.origin == "source" for f in scan_path(str(tmp_path)))


def test_findings_carry_callsite_fix(tmp_path):
    # Drop-in families get a concrete before/after; asymmetric families get a
    # migration pointer instead of a false "just swap it" promise.
    _write(tmp_path, "h.py", "import hashlib\nh = hashlib.md5(b'x')\n")
    md5 = next(f for f in scan_path(str(tmp_path)) if f.family == "md5")
    assert md5.fix["drop_in"] is True
    assert md5.fix["before"] and md5.fix["after"]
    assert "sha256" in md5.fix["after"].lower()

    _write(tmp_path, "k.py", "from x import rsa\nk = rsa.generate_private_key()\n")
    rsa_f = next(f for f in scan_path(str(tmp_path)) if f.family == "rsa")
    assert rsa_f.fix["drop_in"] is False
    assert "ML-KEM" in rsa_f.fix["action"] or "ML-DSA" in rsa_f.fix["action"]
    assert rsa_f.fix["library"]


def test_reachability_ranking(tmp_path):
    _write(tmp_path, "live.py",
           "import hashlib\n"
           "top = hashlib.md5(b'x')\n"          # module-level -> reachable
           "def used():\n    return hashlib.sha1(b'y')\n"  # referenced below
           "def dead():\n    return hashlib.md5(b'z')\n"   # never referenced
           "print(used())\n")
    _write(tmp_path, "tests/test_it.py", "import hashlib\ndef t():\n    return hashlib.md5(b'x')\n")

    by_loc = {(f.file_path, f.line_number): f.reachability
              for f in scan_path(str(tmp_path), reachability=True)}
    assert by_loc[("live.py", 2)] == "reachable"       # module level
    assert by_loc[("live.py", 4)] == "reachable"       # used() is referenced
    assert by_loc[("live.py", 6)] == "unreferenced"    # dead()
    assert by_loc[("tests/test_it.py", 3)] == "test/example"


def test_reachability_is_opt_in(tmp_path):
    _write(tmp_path, "a.py", "import hashlib\nh = hashlib.md5(b'x')\n")
    assert all(f.reachability == "" for f in scan_path(str(tmp_path)))


def test_transitive_lockfile_dependencies(tmp_path):
    # A package pinned only in a lockfile is flagged as transitive; one also in a
    # manifest keeps its direct record (direct beats transitive on dedup).
    _write(tmp_path, "requirements.txt", "cryptography==42.0.5\n")
    _write(tmp_path, "poetry.lock",
           '[[package]]\nname = "cryptography"\nversion = "42.0.5"\n\n'
           '[[package]]\nname = "ecdsa"\nversion = "0.18.0"\n')

    deps = {f.component: f for f in scan_path(str(tmp_path), scan_deps=True)
            if f.origin == "dependency"}
    assert deps["cryptography"].scope == "direct"      # manifest wins
    assert deps["cryptography"].file_path == "requirements.txt"
    assert deps["ecdsa"].scope == "transitive"         # lockfile-only
    assert deps["ecdsa"].purl == "pkg:pypi/ecdsa@0.18.0"


def test_npm_package_lock_is_transitive(tmp_path):
    _write(tmp_path, "package-lock.json",
           '{"packages": {"node_modules/node-forge": {"version": "1.3.1"},'
           ' "node_modules/left-pad": {"version": "1.0.0"}}}')
    deps = {f.component for f in scan_path(str(tmp_path), scan_deps=True)
            if f.origin == "dependency"}
    assert "node-forge" in deps and "left-pad" not in deps


def test_findings_carry_confidence(tmp_path):
    _write(tmp_path, "c.py", "from x import rsa\nk = rsa.generate_private_key()\n")
    findings = scan_path(str(tmp_path))
    assert findings
    assert all(f.confidence in ("high", "medium") for f in findings)
    assert any(f.confidence == "high" for f in findings)


def test_low_risk_classification(tmp_path):
    _write(tmp_path, "s.py", "import hashlib\nh = hashlib.sha256(b'x')\n")
    findings = scan_path(str(tmp_path))
    assert any(f.algorithm == "SHA-256" and f.risk_level == RISK_LOW for f in findings)


def test_findings_are_enriched_with_recommendations(tmp_path):
    _write(tmp_path, "c.py", "from x import rsa\nrsa.generate_private_key()\n")
    findings = scan_path(str(tmp_path))
    assert findings
    f = findings[0]
    assert f.recommendation and f.nist_reference and f.complexity


@pytest.mark.parametrize("bad_url", [
    "https://evil.com/a/b",
    "http://github.com/a/b",
    "https://github.com/a/b/../../c",
    "git@github.com:a/b.git",
    "ftp://github.com/a/b",
])
def test_repo_url_validation_rejects_bad_urls(bad_url):
    with pytest.raises(ValueError):
        _validate_repo_url(bad_url)


def test_repo_url_validation_accepts_good_url():
    assert _validate_repo_url("https://github.com/org/app") == "https://github.com/org/app"

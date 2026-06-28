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

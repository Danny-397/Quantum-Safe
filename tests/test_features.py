"""Tests for SARIF output, inline suppression, and path exclusion."""

import json

from quantumsafe.reporter import build_report, to_badge_svg, to_cbom, to_sarif
from quantumsafe.scanner import scan_path


def _write(tmp_path, name, content):
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return p


def test_sarif_output_is_valid(tmp_path):
    _write(tmp_path, "c.py", "import hashlib\nh = hashlib.md5(b'x')\n")
    report = build_report(scan_path(str(tmp_path)), str(tmp_path))
    sarif = json.loads(to_sarif(report))

    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "QuantumSafe"
    assert len(run["results"]) >= 1
    result = run["results"][0]
    assert result["ruleId"] == "md5"
    assert result["level"] == "error"  # HIGH -> error
    assert result["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1
    # rule carries a security-severity for GitHub code scanning
    assert run["tool"]["driver"]["rules"][0]["properties"]["security-severity"]


def test_cbom_output_is_valid(tmp_path):
    _write(tmp_path, "c.py",
           "import hashlib\n"
           "from cryptography.hazmat.primitives.asymmetric import rsa\n"
           "k = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
           "h = hashlib.md5(b'x')\n")
    report = build_report(scan_path(str(tmp_path)), str(tmp_path))
    cbom = json.loads(to_cbom(report))
    assert cbom["bomFormat"] == "CycloneDX"
    assert cbom["specVersion"] == "1.6"
    assert len(cbom["components"]) >= 1
    comp = cbom["components"][0]
    assert comp["type"] == "cryptographic-asset"
    assert comp["evidence"]["occurrences"]
    assert "cryptoProperties" in comp


def test_cbom_includes_dependency_libraries(tmp_path):
    # A project that only *depends on* crypto libraries (no first-party crypto in
    # source) still yields a CBOM with library components carrying purls, plus a
    # dependency graph linking each library to the crypto assets it provides.
    _write(tmp_path, "requirements.txt", "cryptography==42.0.5\nrsa==4.9\n")
    _write(tmp_path, "app.py", "def add(a, b):\n    return a + b\n")

    report = build_report(scan_path(str(tmp_path), scan_deps=True), str(tmp_path))
    cbom = json.loads(to_cbom(report))

    libs = [c for c in cbom["components"] if c["type"] == "library"]
    assert libs, "expected library components for dependencies"
    names = {c["name"] for c in libs}
    assert {"cryptography", "rsa"} <= names

    crypto_lib = next(c for c in libs if c["name"] == "cryptography")
    assert crypto_lib["purl"] == "pkg:pypi/cryptography@42.0.5"
    assert crypto_lib["version"] == "42.0.5"

    # The dependency graph links libraries to the crypto assets they provide.
    assert cbom["dependencies"]
    crypto_refs = {c["bom-ref"] for c in cbom["components"]
                   if c["type"] == "cryptographic-asset"}
    for dep in cbom["dependencies"]:
        assert dep["provides"], "library should provide at least one crypto asset"
        assert all(ref in crypto_refs for ref in dep["provides"])


def test_badge_svg(tmp_path):
    _write(tmp_path, "c.py", "import hashlib\nh = hashlib.md5(b'x')\n")
    report = build_report(scan_path(str(tmp_path)), str(tmp_path))
    svg = to_badge_svg(report)
    assert svg.startswith("<svg")
    assert "quantum risk" in svg
    assert str(report["risk_score"]) in svg


def test_inline_suppression(tmp_path):
    _write(tmp_path, "c.py",
           "import hashlib\n"
           "a = hashlib.md5(b'x')  # quantumsafe: ignore\n"
           "b = hashlib.md5(b'y')\n")
    findings = scan_path(str(tmp_path))
    md5_lines = sorted(f.line_number for f in findings if f.family == "md5")
    assert md5_lines == [3]  # line 2 suppressed, line 3 reported


def test_exclude_globs(tmp_path):
    _write(tmp_path, "app.py", "import hashlib\nh = hashlib.md5(b'x')\n")
    _write(tmp_path, "tests/test_app.py", "import hashlib\nh = hashlib.md5(b'x')\n")

    all_files = {f.file_path for f in scan_path(str(tmp_path))}
    assert "tests/test_app.py" in all_files

    excluded = {f.file_path for f in scan_path(str(tmp_path), exclude=["tests/*"])}
    assert "tests/test_app.py" not in excluded
    assert "app.py" in excluded

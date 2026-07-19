"""Tests for the cross-module (whole-program) taint analysis."""

from quantumsafe.scanner import RISK_HIGH, scan_path


def _write(tmp_path, name, content):
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return p


def test_cross_file_wrapper_is_flagged_with_taint(tmp_path):
    # Wrapper lives in one module; the call site in another has no crypto keyword.
    _write(tmp_path, "cryptoutil.py",
           "import hashlib\n"
           "def legacy_digest(data):\n"
           "    return hashlib.md5(data).hexdigest()\n")
    _write(tmp_path, "app/handlers.py",
           "from cryptoutil import legacy_digest\n"
           "def handle(payload):\n"
           "    return legacy_digest(payload)\n")

    md5 = [f for f in scan_path(str(tmp_path), taint=True) if f.family == "md5"]
    files = {f.file_path: f for f in md5}
    assert "cryptoutil.py" in files                 # direct
    assert "app/handlers.py" in files               # cross-file indirect
    indirect = files["app/handlers.py"]
    assert indirect.confidence == "indirect"
    assert indirect.risk_level == RISK_HIGH
    assert "cryptoutil" in indirect.algorithm       # provenance names the module


def test_cross_file_taint_is_off_without_flag(tmp_path):
    _write(tmp_path, "cryptoutil.py",
           "import hashlib\ndef d(x):\n    return hashlib.md5(x)\n")
    _write(tmp_path, "use.py", "from cryptoutil import d\ndef run(x):\n    return d(x)\n")
    files = {f.file_path for f in scan_path(str(tmp_path)) if f.family == "md5"}
    assert files == {"cryptoutil.py"}               # only the direct hit


def test_cross_file_taint_propagates_multiple_hops(tmp_path):
    _write(tmp_path, "pkg/__init__.py", "")
    _write(tmp_path, "pkg/low.py", "import hashlib\ndef digest(x):\n    return hashlib.md5(x)\n")
    _write(tmp_path, "pkg/mid.py", "from .low import digest\ndef wrap(x):\n    return digest(x)\n")
    _write(tmp_path, "pkg/api.py", "from .mid import wrap\ndef run(x):\n    return wrap(x)\n")

    indirect = {f.file_path for f in scan_path(str(tmp_path), taint=True)
                if f.family == "md5" and f.confidence == "indirect"}
    # Taint reaches both hops through relative imports.
    assert {"pkg/mid.py", "pkg/api.py"} <= indirect


def test_cross_file_taint_no_false_positive_on_safe_wrapper(tmp_path):
    _write(tmp_path, "safe.py",
           "import hashlib\ndef strong(x):\n    return hashlib.sha3_256(x)\n")
    _write(tmp_path, "caller.py", "from safe import strong\ndef go(x):\n    return strong(x)\n")
    assert not [f for f in scan_path(str(tmp_path), taint=True) if f.confidence == "indirect"]


def test_cross_file_taint_does_not_guess_same_named_functions(tmp_path):
    # Two unrelated modules define digest(); the caller imports the SAFE one.
    # A name-only analysis would taint the call site from the vulnerable digest();
    # import resolution must not.
    _write(tmp_path, "vuln.py", "import hashlib\ndef digest(x):\n    return hashlib.md5(x)\n")
    _write(tmp_path, "safe.py", "import hashlib\ndef digest(x):\n    return hashlib.sha3_256(x)\n")
    _write(tmp_path, "caller.py", "from safe import digest\ndef go(x):\n    return digest(x)\n")

    indirect = [f for f in scan_path(str(tmp_path), taint=True)
                if f.confidence == "indirect" and f.file_path == "caller.py"]
    assert not indirect, "resolved to the safe digest(); must not taint the call site"

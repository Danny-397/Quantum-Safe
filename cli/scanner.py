"""Core cryptographic vulnerability detection.

Two complementary engines:

* A **regex engine** runs over Python, JavaScript/TypeScript, Java, Go and Ruby
  source files, matching known quantum-vulnerable algorithm usage.
* An **AST engine** parses Python files with the standard ``ast`` module to find
  ``hashlib`` / ``cryptography`` / ``pycryptodome`` usage precisely, avoiding the
  false positives a regex would hit inside comments.

Findings from both engines are merged and de-duplicated per (file, line, family)
so a single line of code never inflates the risk score twice.
"""

from __future__ import annotations

import ast
import io
import os
import re
import shutil
import subprocess
import tempfile
import tokenize
from dataclasses import dataclass, field
from urllib.parse import urlparse

from .recommender import recommend
from .remediation import remediate

# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #

RISK_HIGH = "HIGH"
RISK_MEDIUM = "MEDIUM"
RISK_LOW = "LOW"


@dataclass
class Finding:
    file_path: str
    line_number: int
    algorithm: str
    risk_level: str
    why: str
    family: str
    recommendation: str = ""
    nist_reference: str = ""
    complexity: str = ""
    snippet: str = ""
    # "high"  = precise AST match, or a match sitting on a real call/import line.
    # "medium" = a regex keyword match on a code line with no obvious usage signal.
    confidence: str = "medium"
    # "source"     = detected in first-party source code.
    # "dependency" = detected in a declared third-party dependency (see dependencies.py).
    origin: str = "source"
    component: str = ""   # dependency findings only: package name
    version: str = ""     # dependency findings only: pinned version (if known)
    purl: str = ""        # dependency findings only: package URL (purl)
    scope: str = ""       # dependency findings only: "direct" | "transitive"
    # Reachability ranking (see reachability.py): "reachable" | "test/example" |
    # "unreferenced". Empty when ranking was not requested.
    reachability: str = ""
    fix: dict = field(default_factory=dict)  # call-site remediation (see remediation.py)

    def enrich(self) -> "Finding":
        rec = recommend(self.family)
        self.recommendation = rec.replacement
        self.nist_reference = rec.nist_reference
        self.complexity = rec.complexity
        if not self.why:
            self.why = rec.detail
        lang = EXT_TO_LANG.get(os.path.splitext(self.file_path)[1].lower(), "")
        self.fix = remediate(self.family, lang, self.snippet).to_dict()
        return self

    def to_dict(self) -> dict:
        return {
            "file_path": self.file_path,
            "line_number": self.line_number,
            "algorithm": self.algorithm,
            "risk_level": self.risk_level,
            "why": self.why,
            "family": self.family,
            "recommendation": self.recommendation,
            "nist_reference": self.nist_reference,
            "complexity": self.complexity,
            "snippet": self.snippet,
            "confidence": self.confidence,
            "origin": self.origin,
            "component": self.component,
            "version": self.version,
            "purl": self.purl,
            "scope": self.scope,
            "reachability": self.reachability,
            "fix": self.fix,
        }


# --------------------------------------------------------------------------- #
# Rules
# --------------------------------------------------------------------------- #


@dataclass
class Rule:
    family: str
    algorithm: str
    risk: str
    why: str
    pattern: re.Pattern
    languages: set[str] | None = None  # None == all supported languages


def _r(
    family: str,
    algorithm: str,
    risk: str,
    why: str,
    regex: str,
    languages: set[str] | None = None,
) -> Rule:
    return Rule(family, algorithm, risk, why, re.compile(regex, re.IGNORECASE), languages)


# Order matters only for readability; de-duplication picks the highest risk per
# family per line. Patterns favor word boundaries to limit false positives.
RULES: list[Rule] = [
    # ---- HIGH ----
    _r("rsa", "RSA-2048", RISK_HIGH,
       "RSA-2048 key usage; broken by Shor's algorithm on a quantum computer.",
       r"\brsa[\s_\-]?2048\b|\b2048\b\s*(?:bit)?\s*rsa\b"),
    _r("rsa", "RSA-4096", RISK_HIGH,
       "RSA-4096 key usage; larger keys do not help against Shor's algorithm.",
       r"\brsa[\s_\-]?4096\b|\b4096\b\s*(?:bit)?\s*rsa\b"),
    _r("rsa", "RSA", RISK_HIGH,
       "RSA public-key cryptography is broken by Shor's algorithm.",
       r"\bRSA\b|generate_private_key.*rsa|crypto\.generateKeyPair(?:Sync)?\(\s*['\"]rsa['\"]|rsa\.GenerateKey|OpenSSL::PKey::RSA|RSACryptoServiceProvider|openssl_pkey_new|RsaKeyParameters"),
    _r("ecc", "ECDSA", RISK_HIGH,
       "ECDSA signatures are broken by Shor's algorithm.",
       r"\bECDSA\b|ecdsa\b"),
    _r("ecc", "ECDH", RISK_HIGH,
       "ECDH key exchange is broken by Shor's algorithm.",
       r"\bECDH\b|ecdh\b"),
    _r("ecc", "ECC", RISK_HIGH,
       "Elliptic-curve cryptography is broken by Shor's algorithm.",
       r"\bECC\b|elliptic[\s_\-]?curve|EllipticCurve|ec\.generate_private_key|crypto/ecdsa|secp256[rk]1|prime256v1|NIST P-256"),
    _r("dsa", "DSA", RISK_HIGH,
       "DSA signatures are broken by Shor's algorithm.",
       r"\bDSA\b|dsa\.generate_private_key|crypto/dsa"),
    _r("dh", "Diffie-Hellman", RISK_HIGH,
       "Classic Diffie-Hellman key exchange is broken by Shor's algorithm.",
       r"\bDiffie[\s\-]?Hellman\b|\bDH\b|dh\.generate_parameters|DHParameterSpec|crypto/dh"),
    _r("md5", "MD5", RISK_HIGH,
       "MD5 is collision-broken and weakened by Grover's algorithm.",
       r"\bMD5\b|hashlib\.md5|md5\(|md5_file|crypto\.createHash\(\s*['\"]md5['\"]|MessageDigest\.getInstance\(\s*['\"]MD5['\"]|Digest::MD5"),
    _r("sha1", "SHA-1", RISK_HIGH,
       "SHA-1 is collision-broken and weakened by Grover's algorithm.",
       r"\bSHA[\s\-_]?1\b|hashlib\.sha1|sha1\(|sha1_file|crypto\.createHash\(\s*['\"]sha1['\"]|MessageDigest\.getInstance\(\s*['\"]SHA-?1['\"]|Digest::SHA1"),

    # ---- MEDIUM ----
    _r("tls_old", "TLS 1.0", RISK_MEDIUM,
       "TLS 1.0 is deprecated and uses quantum-vulnerable key exchange.",
       r"TLSv1(?:\.0)?\b|PROTOCOL_TLSv1\b|TLS1_0|SSLv3|TLSv1_method"),
    _r("tls_old", "TLS 1.1", RISK_MEDIUM,
       "TLS 1.1 is deprecated and uses quantum-vulnerable key exchange.",
       r"TLSv1\.1\b|PROTOCOL_TLSv1_1\b|TLS1_1|TLSv1_1_method"),
    _r("3des", "3DES / Triple DES", RISK_MEDIUM,
       "3DES is deprecated; Grover's algorithm halves its effective strength.",
       r"\b3DES\b|Triple[\s_\-]?DES\b|DESede|DES3|TripleDES|des_ede3"),
    _r("rc4", "RC4", RISK_MEDIUM,
       "RC4 is insecure and prohibited in TLS.",
       r"\bRC4\b|\bARC4\b|Cipher\.getInstance\(\s*['\"]RC4['\"]"),
    _r("rsa", "RSA <2048 (weak key size)", RISK_MEDIUM,
       "RSA key size below 2048 bits is weak even against classical attacks.",
       r"key_size\s*=\s*(?:512|768|1024)\b|RSA.{0,12}\b(?:512|768|1024)\b|\b(?:512|768|1024)\b.{0,12}RSA"),

    # ---- LOW ----
    _r("sha256", "SHA-256", RISK_LOW,
       "Grover's algorithm weakens SHA-256 to ~128-bit security (still safe).",
       r"\bSHA[\s\-_]?256\b|hashlib\.sha256|crypto\.createHash\(\s*['\"]sha256['\"]|Digest::SHA256"),
    _r("aes128", "AES-128", RISK_LOW,
       "Grover's algorithm halves AES-128 to ~64-bit security.",
       r"\bAES[\s\-_]?128\b|AES.{0,8}\b128\b"),
    _r("tls12", "TLS 1.2", RISK_LOW,
       "TLS 1.2 is acceptable but still relies on classical key exchange.",
       r"TLSv1\.2\b|PROTOCOL_TLSv1_2\b|TLS1_2|TLSv1_2_method"),
]

# Risk ranking used when collapsing multiple matches in the same family/line.
_RISK_RANK = {RISK_HIGH: 3, RISK_MEDIUM: 2, RISK_LOW: 1}

EXT_TO_LANG = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "javascript",
    ".tsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".java": "java",
    ".go": "go",
    ".rb": "ruby",
    ".cs": "csharp",
    ".php": "php",
    ".rs": "rust",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".swift": "swift",
}

_SKIP_DIRS = {
    ".git", "node_modules", "venv", ".venv", "env", "__pycache__",
    "dist", "build", ".tox", ".mypy_cache", "site-packages", ".idea", ".vscode",
}

_MAX_FILE_BYTES = 2_000_000  # skip very large/minified files

# Minified / bundled assets are machine-generated, not first-party source. A
# "crypto" match inside a packed line is almost always a false positive (e.g. the
# substring "rc4"/"sha1" inside a minified library), so we skip them. Detected by
# name OR by a single absurdly long line (only minified/generated code does that).
_MINIFIED_RE = re.compile(r"(?:[.\-]min)\.(?:js|mjs|cjs)$|\.bundle\.js$", re.IGNORECASE)
_MINIFIED_MAX_LINE = 2000


def _looks_minified(name: str, lines: list[str]) -> bool:
    if _MINIFIED_RE.search(name):
        return True
    return any(len(ln) > _MINIFIED_MAX_LINE for ln in lines)


# --------------------------------------------------------------------------- #
# AST engine (Python only)
# --------------------------------------------------------------------------- #

_AST_HASH = {
    "md5": ("md5", "MD5", RISK_HIGH, "MD5 is collision-broken and weakened by Grover's algorithm."),
    "sha1": ("sha1", "SHA-1", RISK_HIGH, "SHA-1 is collision-broken and weakened by Grover's algorithm."),
    "sha256": ("sha256", "SHA-256", RISK_LOW, "Grover's algorithm weakens SHA-256 to ~128-bit security (still safe)."),
}

_AST_ASYM = {
    "rsa": ("rsa", "RSA", RISK_HIGH, "RSA public-key cryptography is broken by Shor's algorithm."),
    "ec": ("ecc", "ECC", RISK_HIGH, "Elliptic-curve cryptography is broken by Shor's algorithm."),
    "dsa": ("dsa", "DSA", RISK_HIGH, "DSA signatures are broken by Shor's algorithm."),
    "dh": ("dh", "Diffie-Hellman", RISK_HIGH, "Classic Diffie-Hellman key exchange is broken by Shor's algorithm."),
}


def _ast_scan_python(source: str, rel_path: str, lines: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return findings  # fall back to regex engine only

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        dotted = _dotted_name(func)
        if not dotted:
            continue
        low = dotted.lower()
        lineno = getattr(node, "lineno", 0)
        snippet = lines[lineno - 1].strip() if 0 < lineno <= len(lines) else ""

        # hashlib.md5() / hashlib.sha1() / hashlib.sha256()
        for key, (family, algo, risk, why) in _AST_HASH.items():
            if low.endswith("hashlib." + key) or low == key:
                findings.append(Finding(rel_path, lineno, algo, risk, why, family, snippet=snippet, confidence="high"))

        # hashlib.new("md5") style
        if low.endswith("hashlib.new") and node.args:
            arg0 = node.args[0]
            if isinstance(arg0, ast.Constant) and isinstance(arg0.value, str):
                name = arg0.value.lower().replace("-", "")
                if name in _AST_HASH:
                    family, algo, risk, why = _AST_HASH[name]
                    findings.append(Finding(rel_path, lineno, algo, risk, why, family, snippet=snippet, confidence="high"))

        # asymmetric key generation: rsa.generate_private_key, ec.generate_private_key, etc.
        for key, (family, algo, risk, why) in _AST_ASYM.items():
            if re.search(rf"\b{key}\.generate_(?:private_key|parameters)$", low):
                findings.append(Finding(rel_path, lineno, algo, risk, why, family, snippet=snippet, confidence="high"))
    return findings


def _dotted_name(node: ast.AST) -> str:
    """Reconstruct a dotted attribute/name path from an AST node."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


# --------------------------------------------------------------------------- #
# Regex engine (all languages)
# --------------------------------------------------------------------------- #


# Line-comment markers per language, used to skip comment-only lines (a major
# source of false positives — a `# TODO: drop MD5` line shouldn't be flagged).
_LINE_COMMENT = {
    "python": ("#",), "ruby": ("#",),
    "javascript": ("//", "/*", "*"), "java": ("//", "/*", "*"),
    "go": ("//", "/*", "*"), "c": ("//", "/*", "*"), "cpp": ("//", "/*", "*"),
    "csharp": ("//", "/*", "*"), "rust": ("//", "/*", "*"),
    "kotlin": ("//", "/*", "*"), "swift": ("//", "/*", "*"),
    "php": ("#", "//", "/*", "*"),
}


def _is_comment_line(line: str, lang: str) -> bool:
    s = line.lstrip()
    return bool(s) and s.startswith(_LINE_COMMENT.get(lang, ()))


# Token types whose text is *content*, not code, and should be masked out before
# the Python regex pass (string literals, comments, and — on 3.12+ — the literal
# segments of f-strings; the ``{expr}`` interpolations stay as real code).
_PY_MASK_TYPES = {tokenize.STRING, tokenize.COMMENT}
for _name in ("FSTRING_START", "FSTRING_MIDDLE", "FSTRING_END"):
    _t = getattr(tokenize, _name, None)
    if _t is not None:
        _PY_MASK_TYPES.add(_t)


def _mask_python_strings(source: str, lines: list[str]) -> list[str]:
    """Blank the characters inside Python string/comment tokens (positions kept).

    This is a lightweight, precise form of usage-awareness: a keyword like "RSA"
    or "MD5" sitting inside a docstring, log message, or exception string is
    documentation, not usage, so it should not be flagged by the regex engine.
    Genuine string-argument usage (e.g. ``hashlib.new("md5")``) is still caught
    by the AST engine, which runs on the original source. Falls back to the
    unmodified lines if the file does not tokenize.
    """
    masked = [list(ln) for ln in lines]
    try:
        for tok in tokenize.generate_tokens(io.StringIO(source).readline):
            if tok.type not in _PY_MASK_TYPES:
                continue
            (srow, scol), (erow, ecol) = tok.start, tok.end
            for row in range(srow, erow + 1):
                idx = row - 1
                if not (0 <= idx < len(masked)):
                    continue
                buf = masked[idx]
                start = scol if row == srow else 0
                end = ecol if row == erow else len(buf)
                for c in range(start, min(end, len(buf))):
                    buf[c] = " "
    except (tokenize.TokenError, IndentationError, SyntaxError, ValueError):
        return lines
    return ["".join(buf) for buf in masked]


# --------------------------------------------------------------------------- #
# Generic (non-Python) string/comment masking
# --------------------------------------------------------------------------- #
#
# Python gets precise masking from the ``tokenize`` module above. Every other
# language is handled by a small, lexer-style state machine that blanks the
# *content* of comments and string literals (positions preserved) so the regex
# engine ignores crypto keywords that live in prose — trailing comments, block
# comments, log/exception messages — exactly the false positives the naive
# line-regex baseline suffers from. Genuine string-argument usage (e.g. Java's
# ``getInstance("SHA-1")``) is recovered separately by ``_string_arg_scan``,
# which mirrors the role the Python AST engine plays.


@dataclass
class _LexConfig:
    line_comments: tuple[str, ...]
    block: tuple[str, str] | None   # (open, close) or None if unsupported
    strings: tuple[str, ...]        # quote characters that open a string
    backtick: bool                  # backtick template/raw string (JS, Go)
    mask_string_content: bool       # blank string interiors (all supported langs)
    import_aware: bool = False      # preserve strings on import lines (Go)


# Go is special: its import paths ("crypto/dsa", "crypto/ecdsa") are *string
# literals* the rules must still read. So Go masks string content everywhere
# EXCEPT on import lines (``import_aware``), which keeps import-based detection
# while still removing crypto keywords that appear in ordinary Go strings.
_LEX: dict[str, _LexConfig] = {
    "javascript": _LexConfig(("//",), ("/*", "*/"), ('"', "'"), True, True),
    "java":       _LexConfig(("//",), ("/*", "*/"), ('"', "'"), False, True),
    "csharp":     _LexConfig(("//",), ("/*", "*/"), ('"', "'"), False, True),
    "c":          _LexConfig(("//",), ("/*", "*/"), ('"', "'"), False, True),
    "cpp":        _LexConfig(("//",), ("/*", "*/"), ('"', "'"), False, True),
    "rust":       _LexConfig(("//",), ("/*", "*/"), ('"',), False, True),
    "kotlin":     _LexConfig(("//",), ("/*", "*/"), ('"', "'"), False, True),
    "swift":      _LexConfig(("//",), ("/*", "*/"), ('"',), False, True),
    "php":        _LexConfig(("//", "#"), ("/*", "*/"), ('"', "'"), False, True),
    "ruby":       _LexConfig(("#",), None, ('"', "'"), False, True),
    "go":         _LexConfig(("//",), ("/*", "*/"), ('"', "'"), True, True, import_aware=True),
}

# Languages whose string literals are masked, and therefore need the
# string-argument recovery pass to keep their genuine crypto usages.
_STRING_MASK_LANGS = {k for k, v in _LEX.items() if v.mask_string_content}


def _mask_generic(lines: list[str], cfg: _LexConfig) -> list[str]:
    """Blank comment/string content across ``lines`` using a small state machine.

    Handles line comments (including trailing), block comments spanning lines,
    and single/backtick string literals with backslash escapes. For
    ``import_aware`` languages (Go), string content on import lines is preserved
    so import-path detection keeps working. Robust by design: anything it cannot
    classify is left as code, so a parse quirk can only cost precision, never a
    crash.
    """
    out: list[str] = []
    state = "code"          # "code" | "block" | "string"
    delim = ""              # active string delimiter when state == "string"
    in_import = False       # inside a Go `import ( ... )` block
    for line in lines:
        buf = list(line)
        # Decide whether string content is masked on THIS line.
        mask_str = cfg.mask_string_content
        if cfg.import_aware and state != "block":
            stripped = line.strip()
            if stripped.startswith("import ("):
                in_import = True
            if in_import or stripped.startswith("import "):
                mask_str = False
            if in_import and stripped.startswith(")"):
                in_import = False
        i, n = 0, len(line)
        while i < n:
            if state == "code":
                if cfg.block and line.startswith(cfg.block[0], i):
                    state = "block"
                    _blank(buf, i, i + len(cfg.block[0]))
                    i += len(cfg.block[0])
                    continue
                if any(line.startswith(lc, i) for lc in cfg.line_comments):
                    _blank(buf, i, n)   # trailing/whole-line comment → EOL
                    i = n
                    continue
                ch = line[i]
                if ch in cfg.strings or (cfg.backtick and ch == "`"):
                    state, delim = "string", ch
                    if mask_str:
                        buf[i] = " "
                    i += 1
                    continue
                i += 1
            elif state == "block":
                assert cfg.block is not None
                if line.startswith(cfg.block[1], i):
                    _blank(buf, i, i + len(cfg.block[1]))
                    i += len(cfg.block[1])
                    state = "code"
                    continue
                buf[i] = " "
                i += 1
            else:  # state == "string"
                ch = line[i]
                if ch == "\\" and delim != "`":   # escape (not in raw backtick)
                    if mask_str:
                        _blank(buf, i, min(i + 2, n))
                    i += 2
                    continue
                if ch == delim:
                    if mask_str:
                        buf[i] = " "
                    state, delim = "code", ""
                    i += 1
                    continue
                if mask_str:
                    buf[i] = " "
                i += 1
        # Line comments and (non-backtick) strings do not continue across lines.
        if state == "string" and delim != "`":
            state, delim = "code", ""
        out.append("".join(buf))
    return out


def _blank(buf: list[str], start: int, end: int) -> None:
    for c in range(start, min(end, len(buf))):
        buf[c] = " "


# --------------------------------------------------------------------------- #
# String-argument recovery (non-Python analogue of the Python AST engine)
# --------------------------------------------------------------------------- #
#
# Once string literals are masked, usages that name the algorithm *inside* a
# string — Java's ``MessageDigest.getInstance("SHA-1")``, Node's
# ``crypto.createCipheriv("aes-128-gcm", ...)`` — would be lost. This pass finds
# them on the original source, but only when (a) the callee is a known crypto
# factory and (b) the argument normalizes to a recognized algorithm token, so it
# stays precise and never re-introduces the prose false positives masking removed.

_FACTORY_ARG_RE = re.compile(
    r"(?P<caller>createHash|createHmac|createCipheriv|createDecipheriv|createCipher"
    r"|createDecipher|generateKeyPairSync|generateKeyPair|getInstance|CreateFromName"
    r"|Digest\.new|Cipher\.new|hash)\s*\(\s*['\"](?P<arg>[^'\"]+)['\"]",
    re.IGNORECASE,
)

# Unambiguous protocol constants — never appear in prose, so they are safe to
# recover from a string literal on sight (subject to a comment check).
_TLS_TOKEN_RE = [
    (re.compile(r"\b(?:TLSv1(?:_1)?_method|SSLv3_method|SSLv23_method"
                r"|PROTOCOL_TLSv1(?:_1)?|TLS1_0|TLS1_1)\b|\bSSLv3\b"), "tls_old"),
    (re.compile(r"\b(?:TLSv1_2_method|PROTOCOL_TLSv1_2|TLS1_2)\b"), "tls12"),
]

# family -> (algorithm label, risk, why) for recovered findings.
_ALGO_INFO: dict[str, tuple[str, str, str]] = {
    "rsa": ("RSA", RISK_HIGH, "RSA public-key cryptography is broken by Shor's algorithm."),
    "ecc": ("ECC", RISK_HIGH, "Elliptic-curve cryptography is broken by Shor's algorithm."),
    "dsa": ("DSA", RISK_HIGH, "DSA signatures are broken by Shor's algorithm."),
    "dh": ("Diffie-Hellman", RISK_HIGH, "Classic Diffie-Hellman key exchange is broken by Shor's algorithm."),
    "md5": ("MD5", RISK_HIGH, "MD5 is collision-broken and weakened by Grover's algorithm."),
    "sha1": ("SHA-1", RISK_HIGH, "SHA-1 is collision-broken and weakened by Grover's algorithm."),
    "sha256": ("SHA-256", RISK_LOW, "Grover's algorithm weakens SHA-256 to ~128-bit security (still safe)."),
    "3des": ("3DES / Triple DES", RISK_MEDIUM, "3DES is deprecated; Grover's algorithm halves its effective strength."),
    "rc4": ("RC4", RISK_MEDIUM, "RC4 is insecure and prohibited in TLS."),
    "aes128": ("AES-128", RISK_LOW, "Grover's algorithm halves AES-128 to ~64-bit security."),
    "tls_old": ("TLS 1.0/1.1", RISK_MEDIUM, "Deprecated TLS versions use quantum-vulnerable key exchange."),
    "tls12": ("TLS 1.2", RISK_LOW, "TLS 1.2 still relies on classical key exchange."),
}


def _map_algo_string(s: str) -> str | None:
    """Map a crypto factory's string argument to a detection family, or None.

    Rejects anything with whitespace (prose, not an algorithm identifier) and
    keys off the first path segment so Java transformations like
    ``DESede/CBC/PKCS5Padding`` resolve to their cipher.
    """
    s = s.strip()
    if not s or " " in s or "\t" in s:
        return None
    norm = re.sub(r"[-_]", "", s.split("/")[0]).lower()
    if norm.startswith("aes128") or re.fullmatch(r"aes128.*", norm):
        return "aes128"
    if norm.startswith("desede") or norm in ("des3", "3des", "tripledes"):
        return "3des"
    if norm in ("rc4", "arc4"):
        return "rc4"
    if norm == "md5":
        return "md5"
    if norm in ("sha1", "sha1withrsa", "sha1withdsa"):
        return "sha1"
    if norm == "sha256":
        return "sha256"
    if norm == "rsa":
        return "rsa"
    if norm in ("ec", "ecc", "ecdsa", "ecdh"):
        return "ecc"
    if norm == "dsa":
        return "dsa"
    if norm in ("dh", "diffiehellman"):
        return "dh"
    return None


def _string_arg_scan(orig_lines: list[str], masked_lines: list[str],
                     lang: str, rel_path: str) -> list[Finding]:
    """Recover crypto usages whose algorithm is named inside a string literal.

    Runs on the original source but uses the masked line to confirm the code is
    real: if the callee/token position was blanked, it lived in a comment or an
    outer string and is ignored.
    """
    findings: list[Finding] = []
    for idx, orig in enumerate(orig_lines):
        masked = masked_lines[idx] if idx < len(masked_lines) else orig
        snippet = orig.strip()

        for m in _FACTORY_ARG_RE.finditer(orig):
            start = m.start("caller")
            if start < len(masked) and masked[start] == " ":
                continue  # callee was inside a comment/string → not real code
            family = _map_algo_string(m.group("arg"))
            if family:
                algo, risk, why = _ALGO_INFO[family]
                findings.append(Finding(rel_path, idx + 1, algo, risk, why, family,
                                        snippet=snippet, confidence="high"))

        # Protocol constants living in string values (e.g. secureProtocol).
        comment_cut = _comment_start(orig, lang)
        for token_re, family in _TLS_TOKEN_RE:
            tm = token_re.search(orig)
            if tm and (comment_cut is None or tm.start() < comment_cut):
                algo, risk, why = _ALGO_INFO[family]
                findings.append(Finding(rel_path, idx + 1, algo, risk, why, family,
                                        snippet=snippet, confidence="high"))
    return findings


def _comment_start(line: str, lang: str) -> int | None:
    """Column where a line comment begins, or None. Used to reject trailing-comment
    matches without a full re-lex (the protocol tokens are the only consumer)."""
    best: int | None = None
    for marker in _LINE_COMMENT.get(lang, ()):
        if marker in ("/*", "*"):
            continue
        pos = line.find(marker)
        if pos != -1 and (best is None or pos < best):
            best = pos
    return best


# A match sits on "real usage" when its line looks like a call, an import, or a
# known crypto constructor — as opposed to a bare keyword mention.
_USAGE_SIGNAL = re.compile(
    r"\w\s*\(|^\s*(?:import|from|require|use|using|package|#include)\b"
    r"|getInstance|createHash|generateKey|Cipher|PKey|new\s+\w",
    re.IGNORECASE,
)


def _confidence_for(line: str) -> str:
    return "high" if _USAGE_SIGNAL.search(line) else "medium"


def _regex_scan(match_lines: list[str], orig_lines: list[str],
                lang: str, rel_path: str) -> list[Finding]:
    """Scan ``match_lines`` (possibly string-masked) but report the original code."""
    findings: list[Finding] = []
    for i, raw in enumerate(match_lines, start=1):
        line = raw.rstrip("\n")
        if not line.strip() or _is_comment_line(line, lang):
            continue
        orig = orig_lines[i - 1].strip() if i - 1 < len(orig_lines) else line.strip()
        for rule in RULES:
            if rule.languages and lang not in rule.languages:
                continue
            if rule.pattern.search(line):
                findings.append(
                    Finding(rel_path, i, rule.algorithm, rule.risk, rule.why,
                            rule.family, snippet=orig, confidence=_confidence_for(orig))
                )
    return findings


# --------------------------------------------------------------------------- #
# De-duplication
# --------------------------------------------------------------------------- #


def _dedupe(findings: list[Finding]) -> list[Finding]:
    """Keep one finding per (file, line, family), preferring the highest risk."""
    best: dict[tuple[str, int, str], Finding] = {}
    for f in findings:
        key = (f.file_path, f.line_number, f.family)
        cur = best.get(key)
        if cur is None or _RISK_RANK[f.risk_level] > _RISK_RANK[cur.risk_level]:
            best[key] = f
    out = list(best.values())
    out.sort(key=lambda f: (f.file_path, f.line_number, -_RISK_RANK[f.risk_level]))
    return out


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #


def scan_file(abs_path: str, rel_path: str, mask_strings: bool = True,
              taint: bool = False) -> list[Finding]:
    ext = os.path.splitext(abs_path)[1].lower()
    lang = EXT_TO_LANG.get(ext)
    if lang is None:
        return []
    try:
        if os.path.getsize(abs_path) > _MAX_FILE_BYTES:
            return []
        with open(abs_path, "r", encoding="utf-8", errors="ignore") as fh:
            source = fh.read()
    except (OSError, UnicodeError):
        return []

    lines = source.splitlines()
    if _looks_minified(os.path.basename(abs_path), lines):
        return []

    # Usage-awareness: mask string/comment *content* so the regex engine ignores
    # crypto keywords that live in prose. Python uses precise tokenizer masking
    # plus the AST engine; every other language uses the generic lexer masker
    # plus the string-argument recovery pass (its AST-engine analogue).
    cfg = _LEX.get(lang)
    if lang == "python":
        match_lines = _mask_python_strings(source, lines) if mask_strings else lines
    elif mask_strings and cfg is not None:
        match_lines = _mask_generic(lines, cfg)
    else:
        match_lines = lines

    findings = _regex_scan(match_lines, lines, lang, rel_path)
    if lang == "python":
        findings += _ast_scan_python(source, rel_path, lines)
        if taint:
            # Interprocedural data-flow pass: crypto reached through wrappers.
            from .taint import taint_scan_python
            findings += taint_scan_python(source, rel_path, lines)
    elif mask_strings and lang in _STRING_MASK_LANGS:
        # Recover genuine crypto usages whose algorithm was named inside a
        # (now-masked) string literal — e.g. getInstance("SHA-1").
        findings += _string_arg_scan(lines, match_lines, lang, rel_path)

    # Honor inline suppressions: a line containing "quantumsafe: ignore".
    if findings:
        findings = [
            f for f in findings
            if not (0 < f.line_number <= len(lines) and _SUPPRESS_RE.search(lines[f.line_number - 1]))
        ]
    return _dedupe(findings)


# Inline suppression marker, e.g.  key = rsa.generate(...)  # quantumsafe: ignore
_SUPPRESS_RE = re.compile(r"quantumsafe:\s*ignore", re.IGNORECASE)


def _is_excluded(rel_path: str, patterns: list[str] | None) -> bool:
    if not patterns:
        return False
    import fnmatch
    return any(fnmatch.fnmatch(rel_path, pat) for pat in patterns)


def scan_path(path: str, exclude: list[str] | None = None,
              mask_strings: bool = True, taint: bool = False,
              scan_deps: bool = False, reachability: bool = False) -> list[Finding]:
    """Recursively scan a local directory (or single file) for vulnerabilities.

    ``exclude`` is an optional list of glob patterns (matched against the path
    relative to ``path``, using forward slashes) to skip. ``mask_strings``
    (default on) enables the string/comment-aware pass across all languages; set
    it False to measure the naive line-regex baseline (used by the benchmark).
    ``taint`` (default off) enables the experimental interprocedural data-flow
    pass for Python wrapper functions. ``scan_deps`` (default off) additionally
    inspects declared dependency manifests (requirements.txt, package.json,
    go.mod, pom.xml, Gemfile, pyproject.toml) plus their lockfiles for
    quantum-vulnerable crypto libraries, producing dependency-origin findings for
    the CBOM. ``reachability`` (default off) labels each source finding as
    ``reachable`` / ``test/example`` / ``unreferenced`` so reports can rank
    exploitable findings above noise.
    """
    path = os.path.abspath(path)
    if not os.path.exists(path):
        raise FileNotFoundError(f"Path does not exist: {path}")

    findings: list[Finding] = []
    if os.path.isfile(path):
        findings = scan_file(path, os.path.basename(path), mask_strings, taint)
    else:
        for root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
            for name in files:
                abs_path = os.path.join(root, name)
                rel_path = os.path.relpath(abs_path, path).replace(os.sep, "/")
                if _is_excluded(rel_path, exclude):
                    continue
                findings.extend(scan_file(abs_path, rel_path, mask_strings, taint))

    if taint and os.path.isdir(path):
        # Whole-program pass: crypto reached through a wrapper in *another* file.
        # (The per-file pass above handles intra-module wrappers.)
        from .callgraph import cross_file_taint
        findings.extend(cross_file_taint(path))

    if scan_deps and os.path.isdir(path):
        from .dependencies import scan_dependencies
        findings.extend(scan_dependencies(path, exclude=exclude))

    findings = _dedupe(findings)
    for f in findings:
        f.enrich()
    if reachability:
        from .reachability import annotate_reachability
        annotate_reachability(findings, path)
    return findings


_GITHUB_RE = re.compile(r"^https://(www\.)?github\.com/[\w.\-]+/[\w.\-]+/?$")


def _validate_repo_url(url: str) -> str:
    """Allow only well-formed public https GitHub URLs (no SSH, no traversal)."""
    url = url.strip()
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.netloc.lower() not in ("github.com", "www.github.com"):
        raise ValueError("Only https://github.com/<org>/<repo> URLs are supported.")
    if ".." in url or " " in url:
        raise ValueError("Invalid repository URL.")
    if not _GITHUB_RE.match(url):
        raise ValueError("Repository URL must look like https://github.com/<org>/<repo>.")
    return url


def scan_repo(url: str, exclude: list[str] | None = None, taint: bool = False,
              scan_deps: bool = False, reachability: bool = False) -> list[Finding]:
    """Shallow-clone a public GitHub repo to a temp dir, scan it, then clean up."""
    url = _validate_repo_url(url)
    if shutil.which("git") is None:
        raise RuntimeError("git is required to scan remote repositories but was not found on PATH.")

    tmp = tempfile.mkdtemp(prefix="quantumsafe_")
    try:
        result = subprocess.run(
            ["git", "clone", "--depth", "1", "--quiet", url, tmp],
            capture_output=True, text=True, timeout=180,
        )
        if result.returncode != 0:
            raise RuntimeError(f"Failed to clone repository: {result.stderr.strip()}")
        return scan_path(tmp, exclude=exclude, taint=taint, scan_deps=scan_deps,
                         reachability=reachability)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

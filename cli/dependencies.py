"""Dependency-level cryptographic exposure detection.

Source scanning finds crypto your *own* code writes; but most real exposure
arrives through third-party libraries. This module parses a project's declared
dependency manifests and flags packages known to implement quantum-vulnerable
cryptography, so the CBOM reflects the crypto a project actually pulls in — the
direction post-quantum inventory (NIST IR 8547, CISA) is moving.

Dependency findings are reported at *capability* granularity: a library that
provides RSA is flagged for RSA whether or not a given call site is reached.
They are therefore marked ``origin="dependency"`` and ``confidence="medium"`` so
consumers can distinguish "we ship a library that can do RSA" from "we call RSA"
(the latter is what source scanning reports). Each carries a package URL (purl)
so it maps cleanly onto a CycloneDX ``library`` component.
"""

from __future__ import annotations

import json
import os
import re

from .scanner import (
    RISK_HIGH,
    RISK_LOW,
    RISK_MEDIUM,
    _ALGO_INFO,
    _SKIP_DIRS,
    Finding,
    _is_excluded,
)


# --------------------------------------------------------------------------- #
# Curated catalog of crypto-relevant packages
# --------------------------------------------------------------------------- #
#
# Keyed by ecosystem, then by lowercased package name. ``primitives`` lists the
# quantum-relevant detection families the package is known to implement. Maven
# entries carry ``group`` for the purl. This is intentionally conservative:
# password-hashing-only libraries (bcrypt, argon2) are omitted — they are not a
# quantum concern and flagging them would erode trust.

_PKG = "primitives"

KNOWN_CRYPTO_PACKAGES: dict[str, dict[str, dict]] = {
    "pypi": {
        "cryptography":   {_PKG: ["rsa", "ecc", "dsa", "dh"]},
        "pycryptodome":   {_PKG: ["rsa", "ecc", "dsa", "dh"]},
        "pycryptodomex":  {_PKG: ["rsa", "ecc", "dsa", "dh"]},
        "pycrypto":       {_PKG: ["rsa", "dsa"]},
        "rsa":            {_PKG: ["rsa"]},
        "ecdsa":          {_PKG: ["ecc"]},
        "pyopenssl":      {_PKG: ["rsa", "ecc", "dsa"]},
        "paramiko":       {_PKG: ["rsa", "ecc"]},
        "pynacl":         {_PKG: ["ecc"]},
        "pyjwt":          {_PKG: ["rsa", "ecc"]},
        "python-jose":    {_PKG: ["rsa", "ecc"]},
        "jwcrypto":       {_PKG: ["rsa", "ecc"]},
        "oscrypto":       {_PKG: ["rsa", "ecc", "dsa"]},
    },
    "npm": {
        "node-forge":     {_PKG: ["rsa", "ecc", "dsa"]},
        "crypto-js":      {_PKG: ["md5", "sha1", "3des", "rc4"]},
        "elliptic":       {_PKG: ["ecc"]},
        "jsrsasign":      {_PKG: ["rsa", "ecc"]},
        "jsonwebtoken":   {_PKG: ["rsa", "ecc"]},
        "sshpk":          {_PKG: ["rsa", "ecc", "dsa"]},
    },
    "golang": {
        "golang.org/x/crypto": {_PKG: ["ecc"]},
    },
    "maven": {
        "bcprov-jdk18on": {_PKG: ["rsa", "ecc", "dsa", "dh"], "group": "org.bouncycastle"},
        "bcprov-jdk15on": {_PKG: ["rsa", "ecc", "dsa", "dh"], "group": "org.bouncycastle"},
        "java-jwt":       {_PKG: ["rsa", "ecc"], "group": "com.auth0"},
    },
    "gem": {
        "openssl":        {_PKG: ["rsa", "ecc", "dsa", "dh"]},
        "jwt":            {_PKG: ["rsa", "ecc"]},
    },
}

# Ecosystem -> purl type (they happen to differ from our internal names).
_PURL_TYPE = {"pypi": "pypi", "npm": "npm", "golang": "golang", "maven": "maven", "gem": "gem"}


# --------------------------------------------------------------------------- #
# Manifest parsers  (each returns list of (name, version_or_"", line_number))
# --------------------------------------------------------------------------- #

_REQ_LINE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(?:==\s*([^\s;,#]+))?")


def _parse_requirements(text: str) -> list[tuple[str, str, int]]:
    out: list[tuple[str, str, int]] = []
    for i, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith(("#", "-", "git+", "http://", "https://")):
            continue
        m = _REQ_LINE.match(line)
        if m:
            out.append((m.group(1), m.group(2) or "", i))
    return out


def _parse_pyproject(text: str) -> list[tuple[str, str, int]]:
    try:
        import tomllib  # Python 3.11+
    except ModuleNotFoundError:
        return _pep508_fallback(text)
    try:
        data = tomllib.loads(text)
    except Exception:
        return _pep508_fallback(text)

    names: list[str] = []
    proj = data.get("project", {})
    for spec in proj.get("dependencies", []) or []:
        names.append(spec)
    for group in (proj.get("optional-dependencies", {}) or {}).values():
        names.extend(group or [])
    poetry = data.get("tool", {}).get("poetry", {})
    for section in ("dependencies", "dev-dependencies"):
        names.extend((poetry.get(section, {}) or {}).keys())

    out: list[tuple[str, str, int]] = []
    for spec in names:
        m = re.match(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)", spec)
        if m:
            out.append((m.group(1), "", _line_of(text, m.group(1))))
    return out


def _pep508_fallback(text: str) -> list[tuple[str, str, int]]:
    """Best-effort scan of a pyproject when TOML parsing is unavailable."""
    out: list[tuple[str, str, int]] = []
    for i, raw in enumerate(text.splitlines(), start=1):
        m = re.match(r"""^\s*["']([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:[<>=!~].*)?["']""", raw)
        if m:
            out.append((m.group(1), "", i))
    return out


def _parse_package_json(text: str) -> list[tuple[str, str, int]]:
    try:
        data = json.loads(text)
    except ValueError:
        return []
    out: list[tuple[str, str, int]] = []
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        deps = data.get(section, {})
        if isinstance(deps, dict):
            for name, ver in deps.items():
                version = re.sub(r"^[\^~>=<\s]+", "", str(ver)) if ver else ""
                out.append((name, version, _line_of(text, f'"{name}"')))
    return out


_GOMOD_LINE = re.compile(r"^\s*(?:require\s+)?([A-Za-z0-9._~\-/.]+\.[A-Za-z0-9._~\-/.]+)\s+v(\S+)")


def _parse_go_mod(text: str) -> list[tuple[str, str, int]]:
    out: list[tuple[str, str, int]] = []
    for i, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if line.startswith("//") or line in ("require (", ")"):
            continue
        m = _GOMOD_LINE.match(raw)
        if m:
            out.append((m.group(1), m.group(2), i))
    return out


def _parse_pom(text: str) -> list[tuple[str, str, int]]:
    """Parse Maven <dependency> artifactIds. Returns (artifactId, version, line)."""
    import xml.etree.ElementTree as ET

    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return []
    out: list[tuple[str, str, int]] = []

    def _local(tag: str) -> str:
        return tag.rsplit("}", 1)[-1]

    for dep in root.iter():
        if _local(dep.tag) != "dependency":
            continue
        artifact = version = ""
        for child in dep:
            if _local(child.tag) == "artifactId":
                artifact = (child.text or "").strip()
            elif _local(child.tag) == "version":
                version = (child.text or "").strip()
        if artifact:
            out.append((artifact, version, _line_of(text, f"<artifactId>{artifact}")))
    return out


_GEM_LINE = re.compile(r"""^\s*gem\s+["']([A-Za-z0-9._-]+)["']\s*(?:,\s*["']([^"']+)["'])?""")


def _parse_gemfile(text: str) -> list[tuple[str, str, int]]:
    out: list[tuple[str, str, int]] = []
    for i, raw in enumerate(text.splitlines(), start=1):
        m = _GEM_LINE.match(raw)
        if m:
            version = re.sub(r"^[~>=<\s]+", "", m.group(2)) if m.group(2) else ""
            out.append((m.group(1), version, i))
    return out


def _line_of(text: str, needle: str) -> int:
    """1-based line where ``needle`` first appears (for manifest evidence); 1 if absent."""
    for i, raw in enumerate(text.splitlines(), start=1):
        if needle in raw:
            return i
    return 1


# --------------------------------------------------------------------------- #
# Lockfile parsers  (transitive closure — same (name, version, line) shape)
# --------------------------------------------------------------------------- #


def _parse_package_lock(text: str) -> list[tuple[str, str, int]]:
    """npm package-lock.json (v1 'dependencies' and v2/v3 'packages')."""
    try:
        data = json.loads(text)
    except ValueError:
        return []
    seen: dict[str, str] = {}

    # v2/v3: {"packages": {"node_modules/foo": {"version": "..."}}}
    for path, meta in (data.get("packages", {}) or {}).items():
        if not path or not isinstance(meta, dict):
            continue
        name = path.split("node_modules/")[-1]
        if name:
            seen.setdefault(name, meta.get("version", ""))

    # v1: nested {"dependencies": {"foo": {"version": ..., "dependencies": {...}}}}
    def _walk(deps: dict) -> None:
        for name, meta in (deps or {}).items():
            if isinstance(meta, dict):
                seen.setdefault(name, meta.get("version", ""))
                _walk(meta.get("dependencies", {}))

    _walk(data.get("dependencies", {}))
    return [(n, v, _line_of(text, f'"{n}"')) for n, v in seen.items()]


_YARN_KEY = re.compile(r'^"?((?:@[^/@\s"]+/)?[^@/\s"]+)@')
_YARN_VER = re.compile(r'^\s+version:?\s+"?([^"\s]+)"?')


def _parse_yarn_lock(text: str) -> list[tuple[str, str, int]]:
    """yarn.lock (v1 classic and v2+ berry): map each entry to its resolved version."""
    out: list[tuple[str, str, int]] = []
    name: str | None = None
    name_line = 0
    for i, raw in enumerate(text.splitlines(), start=1):
        if raw and not raw[0].isspace() and raw.rstrip().endswith(":"):
            m = _YARN_KEY.match(raw.strip())
            name, name_line = (m.group(1) if m else None), i
        elif name:
            vm = _YARN_VER.match(raw)
            if vm:
                out.append((name, vm.group(1), name_line))
                name = None
    return out


def _parse_poetry_lock(text: str) -> list[tuple[str, str, int]]:
    """poetry.lock: [[package]] tables with name/version."""
    try:
        import tomllib
        data = tomllib.loads(text)
        return [(p.get("name", ""), p.get("version", ""),
                 _line_of(text, f'name = "{p.get("name", "")}"'))
                for p in data.get("package", []) if p.get("name")]
    except Exception:
        # Fallback: line scan for name = "..." / version = "..." pairs.
        out, cur = [], None
        for i, raw in enumerate(text.splitlines(), start=1):
            nm = re.match(r'\s*name\s*=\s*"([^"]+)"', raw)
            vm = re.match(r'\s*version\s*=\s*"([^"]+)"', raw)
            if nm:
                cur = (nm.group(1), i)
            elif vm and cur:
                out.append((cur[0], vm.group(1), cur[1]))
                cur = None
        return out


def _parse_pipfile_lock(text: str) -> list[tuple[str, str, int]]:
    """Pipfile.lock: {"default": {"pkg": {"version": "==x"}}, "develop": {...}}."""
    try:
        data = json.loads(text)
    except ValueError:
        return []
    out: list[tuple[str, str, int]] = []
    for section in ("default", "develop"):
        for name, meta in (data.get(section, {}) or {}).items():
            version = ""
            if isinstance(meta, dict):
                version = re.sub(r"^[=~><\s]+", "", str(meta.get("version", "")))
            out.append((name, version, _line_of(text, f'"{name}"')))
    return out


_GEMLOCK_SPEC = re.compile(r"^    ([A-Za-z0-9._-]+) \(([^)]+)\)")


def _parse_gemfile_lock(text: str) -> list[tuple[str, str, int]]:
    """Gemfile.lock: the GEM `specs:` block (4-space indented `name (version)`)."""
    out: list[tuple[str, str, int]] = []
    in_specs = False
    for i, raw in enumerate(text.splitlines(), start=1):
        stripped = raw.strip()
        if stripped == "specs:":
            in_specs = True
            continue
        if in_specs:
            m = _GEMLOCK_SPEC.match(raw)
            if m:
                out.append((m.group(1), m.group(2), i))
            elif stripped and not raw.startswith(" "):
                in_specs = False
    return out


_GOSUM = re.compile(r"^(\S+)\s+v(\S+?)(?:/go\.mod)?\s+h1:")


def _parse_go_sum(text: str) -> list[tuple[str, str, int]]:
    """go.sum: the full transitive module list (deduped, /go.mod suffix stripped)."""
    seen: dict[tuple[str, str], int] = {}
    for i, raw in enumerate(text.splitlines(), start=1):
        m = _GOSUM.match(raw)
        if m:
            seen.setdefault((m.group(1), m.group(2)), i)
    return [(name, ver, line) for (name, ver), line in seen.items()]


# Manifest/lockfile filename -> (ecosystem, parser_key, scope). Manifests declare
# *direct* dependencies; lockfiles pin the full *transitive* closure.
def _is_manifest(name: str) -> tuple[str, str, str] | None:
    lower = name.lower()
    # Lockfiles (transitive) first — they are the more specific filenames.
    if lower == "package-lock.json":
        return "npm", "package_lock", "transitive"
    if lower == "yarn.lock":
        return "npm", "yarn_lock", "transitive"
    if lower == "poetry.lock":
        return "pypi", "poetry_lock", "transitive"
    if lower == "pipfile.lock":
        return "pypi", "pipfile_lock", "transitive"
    if lower == "gemfile.lock":
        return "gem", "gemfile_lock", "transitive"
    if lower == "go.sum":
        return "golang", "go_sum", "transitive"
    # Manifests (direct).
    if lower == "requirements.txt" or (lower.startswith("requirements") and lower.endswith(".txt")):
        return "pypi", "requirements", "direct"
    if lower == "pyproject.toml":
        return "pypi", "pyproject", "direct"
    if lower == "package.json":
        return "npm", "package_json", "direct"
    if lower == "go.mod":
        return "golang", "go_mod", "direct"
    if lower == "pom.xml":
        return "maven", "pom", "direct"
    if lower == "gemfile":
        return "gem", "gemfile", "direct"
    return None


_PARSERS = {
    "requirements": _parse_requirements,
    "pyproject": _parse_pyproject,
    "package_json": _parse_package_json,
    "go_mod": _parse_go_mod,
    "pom": _parse_pom,
    "gemfile": _parse_gemfile,
    "package_lock": _parse_package_lock,
    "yarn_lock": _parse_yarn_lock,
    "poetry_lock": _parse_poetry_lock,
    "pipfile_lock": _parse_pipfile_lock,
    "gemfile_lock": _parse_gemfile_lock,
    "go_sum": _parse_go_sum,
}

# When a package appears in both a manifest and a lockfile, keep the better
# record: direct scope wins, and a concrete version wins over an empty one.
_SCOPE_RANK = {"direct": 2, "transitive": 1, "": 0}


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #


def _purl(ecosystem: str, name: str, version: str, info: dict) -> str:
    ptype = _PURL_TYPE[ecosystem]
    ref = name
    if ecosystem == "maven" and info.get("group"):
        ref = f"{info['group']}/{name}"
    purl = f"pkg:{ptype}/{ref}"
    if version:
        purl += f"@{version}"
    return purl


def scan_dependencies(root: str, exclude: list[str] | None = None) -> list[Finding]:
    """Parse dependency manifests + lockfiles under ``root`` and flag crypto packages.

    Manifests (requirements.txt, package.json, go.mod, …) contribute *direct*
    dependencies; lockfiles (package-lock.json, poetry.lock, go.sum, …) contribute
    the *transitive* closure. A package seen in both keeps its direct record.
    Returns one dependency-origin :class:`Finding` per (package, primitive), with
    ``component``, ``version``, ``purl`` and ``scope`` populated for the CBOM.
    """
    # Collect the best record per (ecosystem, lowercased name).
    records: dict[tuple[str, str], dict] = {}
    for dir_root, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for name in files:
            manifest = _is_manifest(name)
            if manifest is None:
                continue
            ecosystem, parser_key, scope = manifest
            abs_path = os.path.join(dir_root, name)
            rel_path = os.path.relpath(abs_path, root).replace(os.sep, "/")
            if _is_excluded(rel_path, exclude):
                continue
            try:
                with open(abs_path, "r", encoding="utf-8", errors="ignore") as fh:
                    text = fh.read()
            except OSError:
                continue

            catalog = KNOWN_CRYPTO_PACKAGES.get(ecosystem, {})
            for pkg_name, version, lineno in _PARSERS[parser_key](text):
                info = catalog.get(pkg_name.lower())
                if info is None:
                    continue
                key = (ecosystem, pkg_name.lower())
                cand = {"ecosystem": ecosystem, "name": pkg_name, "version": version,
                        "scope": scope, "info": info, "rel_path": rel_path, "line": lineno}
                if _prefer(cand, records.get(key)):
                    records[key] = cand

    findings: list[Finding] = []
    for rec in records.values():
        purl = _purl(rec["ecosystem"], rec["name"], rec["version"], rec["info"])
        scope_note = "a direct" if rec["scope"] == "direct" else "a transitive"
        for family in rec["info"][_PKG]:
            algo, risk, why = _ALGO_INFO[family]
            findings.append(Finding(
                file_path=rec["rel_path"],
                line_number=rec["line"],
                algorithm=algo,
                risk_level=risk,
                why=(f"{scope_note.capitalize()} dependency '{rec['name']}' provides "
                     f"{algo}, which is quantum-vulnerable. {why}"),
                family=family,
                snippet=f"{rec['name']}{'==' + rec['version'] if rec['version'] else ''}",
                confidence="medium",
                origin="dependency",
                component=rec["name"],
                version=rec["version"],
                purl=purl,
                scope=rec["scope"],
            ))
    return findings


def _prefer(cand: dict, cur: dict | None) -> bool:
    """True if ``cand`` is a better record than the current one (direct > transitive,
    and a concrete version breaks ties)."""
    if cur is None:
        return True
    cs, ps = _SCOPE_RANK.get(cand["scope"], 0), _SCOPE_RANK.get(cur["scope"], 0)
    if cs != ps:
        return cs > ps
    return bool(cand["version"]) and not cur["version"]

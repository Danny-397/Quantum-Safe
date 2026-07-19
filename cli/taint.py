"""Interprocedural data-flow (taint) analysis for Python.

The core scanner (:mod:`cli.scanner`) finds *direct* uses of quantum-vulnerable
cryptography — a line that literally calls ``hashlib.md5(...)`` or
``rsa.generate_private_key(...)``. But real codebases routinely hide the
primitive behind a wrapper, so the dangerous *call sites* contain no crypto
keyword at all::

    def _legacy_digest(data):            # wraps MD5 ...
        return hashlib.md5(data).hexdigest()

    def sign_request(payload):           # ... and re-exposes it one hop up
        return _legacy_digest(payload)

    token = sign_request(body)           # <-- the real blast radius: no "md5" in sight

A pattern/AST scan flags the ``hashlib.md5`` line but is blind to
``sign_request`` and to ``token = sign_request(body)``. This module closes that
gap: any function that *transitively* reaches a vulnerable primitive becomes
**tainted**, and every call site of a tainted function is reported as an
**indirect** finding, so an auditor sees where the weak crypto is actually
reachable from.

Design + guardrails (in security tooling, precision is the product):

* **Python only.** This module handles the **intra-module** case (wrapper and
  call site in the same file). The companion :mod:`cli.callgraph` handles the
  **cross-file** case with real import resolution, so the two compose: intra-file
  wrappers here, cross-module wrappers there, with no double-reporting.
* Taint roots must be **high-confidence** primitives — the same AST-detected
  calls the core scanner trusts — never a bare keyword mention.
* An indirect finding is only emitted when the call-site line does **not**
  already contain the crypto keyword (otherwise the direct scan owns it). Taint
  findings are therefore strictly *additive* and never overlap direct ones.
* The whole pass is **opt-in** (off by default) so it can never regress the
  precision benchmark.

The result is a small but genuine interprocedural analysis: a call graph, a
fixpoint taint propagation over it, and provenance (the wrapper chain) attached
to every finding.
"""

from __future__ import annotations

import ast
from collections import defaultdict

from .scanner import RISK_HIGH, RISK_LOW, Finding, _dotted_name

# Vulnerable primitives recognised as taint *roots*, mirroring the AST engine in
# :mod:`cli.scanner`. Maps the trailing dotted call to (family, algorithm, risk).
_HASH_ROOTS = {
    "md5": ("md5", "MD5", RISK_HIGH),
    "sha1": ("sha1", "SHA-1", RISK_HIGH),
    "sha256": ("sha256", "SHA-256", RISK_LOW),
}
_ASYM_ROOTS = {
    "rsa": ("rsa", "RSA", RISK_HIGH),
    "ec": ("ecc", "ECC", RISK_HIGH),
    "dsa": ("dsa", "DSA", RISK_HIGH),
    "dh": ("dh", "Diffie-Hellman", RISK_HIGH),
}

# Crypto keywords per family — used only to *suppress* an indirect finding when
# the direct scanner would already flag the same call-site line.
_FAMILY_KEYWORDS = {
    "md5": ("md5",),
    "sha1": ("sha1", "sha-1", "sha_1"),
    "sha256": ("sha256", "sha-256", "sha_256"),
    "rsa": ("rsa",),
    "ecc": ("ecc", "ecdsa", "ecdh", "elliptic", "secp256", "prime256"),
    "dsa": ("dsa",),
    "dh": ("diffie", "diffie-hellman"),
}


def _classify_root(node: ast.Call, dotted: str) -> tuple[str, str, str] | None:
    """Return (family, algorithm, risk) if this call is a vulnerable primitive."""
    low = dotted.lower()
    # hashlib.md5() / hashlib.sha1() / hashlib.sha256() or a bare md5()/sha1()
    for key, meta in _HASH_ROOTS.items():
        if low.endswith("hashlib." + key) or low == key:
            return meta
    # hashlib.new("md5")
    if low.endswith("hashlib.new") and node.args:
        arg0 = node.args[0]
        if isinstance(arg0, ast.Constant) and isinstance(arg0.value, str):
            name = arg0.value.lower().replace("-", "")
            if name in _HASH_ROOTS:
                return _HASH_ROOTS[name]
    # rsa/ec/dsa/dh.generate_private_key() / .generate_parameters()
    for key, meta in _ASYM_ROOTS.items():
        if low.endswith(key + ".generate_private_key") or low.endswith(key + ".generate_parameters"):
            return meta
    return None


def _callee_name(func: ast.AST) -> str | None:
    """Local name a call resolves to: ``foo()`` -> "foo", ``self.foo()`` -> "foo"."""
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        if func.value.id in ("self", "cls"):
            return func.attr
    return None


class _CallGraph(ast.NodeVisitor):
    """One pass over a module: collect per-function crypto roots and call edges."""

    def __init__(self) -> None:
        self._stack: list[str] = []
        # function name -> {(family, algorithm, risk)} it *directly* invokes
        self.direct: dict[str, set[tuple[str, str, str]]] = defaultdict(set)
        # call edges + call sites: (caller_or_None, callee_name, lineno)
        self.calls: list[tuple[str | None, str, int]] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        self._stack.append(node.name)
        self.generic_visit(node)
        self._stack.pop()

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        caller = self._stack[-1] if self._stack else None
        dotted = _dotted_name(node.func)
        if dotted:
            root = _classify_root(node, dotted)
            if root and caller is not None:
                self.direct[caller].add(root)
        callee = _callee_name(node.func)
        if callee is not None:
            self.calls.append((caller, callee, getattr(node, "lineno", 0)))
        self.generic_visit(node)


def _propagate(direct: dict[str, set], calls: list[tuple[str | None, str, int]]) -> dict[str, set]:
    """Fixpoint: a function inherits the taint of every local function it calls."""
    tainted: dict[str, set] = {name: set(roots) for name, roots in direct.items()}
    local_funcs = {c for _, c, _ in calls} | set(direct)
    changed = True
    while changed:
        changed = False
        for caller, callee, _ in calls:
            if caller is None or callee not in local_funcs:
                continue
            src = tainted.get(callee)
            if not src:
                continue
            new = src - tainted.get(caller, set())
            if new:
                tainted.setdefault(caller, set()).update(new)
                changed = True
    return tainted


def taint_scan_python(source: str, rel_path: str, lines: list[str]) -> list[Finding]:
    """Return *indirect* findings for crypto reached through wrapper functions.

    Findings are marked ``confidence="indirect"`` and carry the wrapper name in
    the algorithm/``why`` so the propagation chain is auditable. Returns an empty
    list if the module does not parse.
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []

    graph = _CallGraph()
    graph.visit(tree)
    tainted = _propagate(graph.direct, graph.calls)
    if not tainted:
        return []

    findings: list[Finding] = []
    for caller, callee, lineno in graph.calls:
        roots = tainted.get(callee)
        if not roots:
            continue
        line = lines[lineno - 1] if 0 < lineno <= len(lines) else ""
        low = line.lower()
        for family, algo, risk in roots:
            # Skip if the direct scanner already owns this line for this family.
            if any(kw in low for kw in _FAMILY_KEYWORDS.get(family, ())):
                continue
            findings.append(
                Finding(
                    file_path=rel_path,
                    line_number=lineno,
                    algorithm=f"{algo} (via {callee}())",
                    risk_level=risk,
                    why=(f"Calls {callee}(), which reaches quantum-vulnerable {algo} "
                         f"through a wrapper (data-flow analysis)."),
                    family=family,
                    snippet=line.strip(),
                    confidence="indirect",
                )
            )
    return findings

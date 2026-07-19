"""Cross-module (whole-program) call graph for Python, with import resolution.

The intra-module taint pass in :mod:`cli.taint` finds crypto reached through a
wrapper *within one file*. But real blast radius crosses files: a helper in
``crypto/legacy.py`` that wraps MD5, called from ``api/handlers.py``, leaves no
crypto keyword at the call site **and lives in a different module**, so a
per-file analysis is blind to it.

This module closes that gap. It builds a **program-wide call graph** across every
scanned ``.py`` file by resolving imports to qualified symbols (``module.func``),
propagates crypto taint to a fixpoint over that graph, and reports each *cross-file*
call site that reaches a quantum-vulnerable primitive through a wrapper defined in
another module.

Precision guardrails (in security tooling, precision is the product):

* A call edge is only created when it **resolves** to a function we actually
  indexed — absolute imports, relative imports, and a *unique* suffix match.
  Ambiguous names are dropped, never guessed, so an unrelated same-named function
  can't create a phantom edge.
* Taint roots are the same high-confidence AST-detected primitives the core
  scanner trusts (reused from :mod:`cli.taint`).
* Only **cross-file** call sites are emitted here; intra-file wrappers remain the
  job of :mod:`cli.taint`, so the two passes never double-report a line.

The result is a genuine whole-program static analysis: an import-resolved call
graph, a fixpoint over it, and provenance (the resolved wrapper + its module) on
every finding.
"""

from __future__ import annotations

import ast
import os
from collections import defaultdict, deque
from dataclasses import dataclass, field

from .scanner import EXT_TO_LANG, Finding, _dotted_name
from .taint import _FAMILY_KEYWORDS, _classify_root


@dataclass
class _Func:
    qname: str                      # e.g. "pkg.mod.func" or "pkg.mod.Class.method"
    rel_path: str
    lineno: int
    end_lineno: int
    roots: set[tuple[str, str, str]] = field(default_factory=set)


@dataclass
class _CallSite:
    rel_path: str
    lineno: int
    line_text: str
    caller: str | None              # enclosing function qname, or None (module level)
    target: str | None = None       # resolved callee qname (filled in resolution)


def _module_qname(rel_path: str) -> str:
    """Map a repo-relative .py path to a dotted module name."""
    parts = rel_path.replace("\\", "/").split("/")
    if parts[-1] == "__init__.py":
        parts = parts[:-1]
    else:
        parts[-1] = parts[-1][:-3]  # strip .py
    return ".".join(p for p in parts if p)


class _ModuleVisitor(ast.NodeVisitor):
    """Collect a module's import table, function defs, and raw call sites."""

    def __init__(self, module_qname: str, rel_path: str):
        self.module = module_qname
        self.rel_path = rel_path
        self.pkg = module_qname.rsplit(".", 1)[0] if "." in module_qname else ""
        # local name -> dotted module path (for `import x`, `import x.y as z`)
        self.module_aliases: dict[str, str] = {}
        # local name -> (dotted module, original symbol) for `from m import f`
        self.symbol_imports: dict[str, tuple[str, str]] = {}
        self.funcs: dict[str, _Func] = {}
        self.calls: list[_CallSite] = []
        self.lines: list[str] = []
        self._func_stack: list[str] = []
        self._class_stack: list[str] = []

    # -- imports ----------------------------------------------------------- #
    def visit_Import(self, node: ast.Import) -> None:  # noqa: N802
        for alias in node.names:
            self.module_aliases[alias.asname or alias.name.split(".")[0]] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:  # noqa: N802
        if node.level:  # relative import: resolve against this module's package
            base = self.pkg.split(".") if self.pkg else []
            up = node.level - 1
            base = base[: len(base) - up] if up else base
            mod = ".".join(base + ([node.module] if node.module else []))
        else:
            mod = node.module or ""
        for alias in node.names:
            self.symbol_imports[alias.asname or alias.name] = (mod, alias.name)
        self.generic_visit(node)

    # -- defs -------------------------------------------------------------- #
    def _qual(self, name: str) -> str:
        prefix = ".".join([self.module, *self._class_stack])
        return f"{prefix}.{name}"

    def visit_ClassDef(self, node: ast.ClassDef) -> None:  # noqa: N802
        self._class_stack.append(node.name)
        self.generic_visit(node)
        self._class_stack.pop()

    def _visit_func(self, node: ast.AST) -> None:
        # Only index top-level functions and one level of class methods (not
        # closures) — that is where crypto wrappers realistically live.
        if self._func_stack:
            self.generic_visit(node)
            return
        qname = self._qual(node.name)
        self.funcs[qname] = _Func(
            qname=qname, rel_path=self.rel_path, lineno=node.lineno,
            end_lineno=getattr(node, "end_lineno", node.lineno),
        )
        self._func_stack.append(qname)
        self.generic_visit(node)
        self._func_stack.pop()

    visit_FunctionDef = _visit_func       # type: ignore[assignment]
    visit_AsyncFunctionDef = _visit_func  # type: ignore[assignment]

    # -- calls ------------------------------------------------------------- #
    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        caller = self._func_stack[-1] if self._func_stack else None
        # crypto root directly invoked here?
        dotted = _dotted_name(node.func)
        if dotted and caller is not None:
            root = _classify_root(node, dotted)
            if root and caller in self.funcs:
                self.funcs[caller].roots.add(root)
        # record the call site for later resolution
        line = self.lines[node.lineno - 1] if 0 < node.lineno <= len(self.lines) else ""
        cs = _CallSite(self.rel_path, getattr(node, "lineno", 0), line, caller)
        cs._raw = node.func  # type: ignore[attr-defined]
        cs._class = self._class_stack[-1] if self._class_stack else None  # type: ignore[attr-defined]
        self.calls.append(cs)
        self.generic_visit(node)


class CallGraph:
    """Whole-program call graph over the scanned Python files."""

    def __init__(self) -> None:
        self.funcs: dict[str, _Func] = {}
        self.calls: list[_CallSite] = []
        self._modules: set[str] = set()
        self._by_suffix: dict[str, list[str]] = defaultdict(list)

    # -- construction ------------------------------------------------------ #
    @classmethod
    def build(cls, files: dict[str, str]) -> "CallGraph":
        g = cls()
        visitors: list[_ModuleVisitor] = []
        for rel_path, source in files.items():
            try:
                tree = ast.parse(source)
            except (SyntaxError, ValueError):
                continue
            mod = _module_qname(rel_path)
            v = _ModuleVisitor(mod, rel_path)
            v.lines = source.splitlines()
            v.visit(tree)
            visitors.append(v)
            g._modules.add(mod)
            g._by_suffix[mod.rsplit(".", 1)[-1]].append(mod)
            g.funcs.update(v.funcs)
        for v in visitors:
            for cs in v.calls:
                cs.target = g._resolve(v, cs)
                g.calls.append(cs)
        return g

    def _resolve_module(self, dotted: str) -> str | None:
        if not dotted:
            return None
        if dotted in self._modules:
            return dotted
        cands = [m for m in self._modules if m == dotted or m.endswith("." + dotted)]
        return cands[0] if len(cands) == 1 else None

    def _resolve(self, v: _ModuleVisitor, cs: _CallSite) -> str | None:
        func = cs._raw  # type: ignore[attr-defined]
        # foo()
        if isinstance(func, ast.Name):
            name = func.id
            if name in v.symbol_imports:
                mod, orig = v.symbol_imports[name]
                m = self._resolve_module(mod)
                if m and f"{m}.{orig}" in self.funcs:
                    return f"{m}.{orig}"
            local = f"{v.module}.{name}"
            return local if local in self.funcs else None
        # obj.meth()
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            obj, meth = func.value.id, func.attr
            if obj in ("self", "cls") and cs._class:  # type: ignore[attr-defined]
                q = f"{v.module}.{cs._class}.{meth}"  # type: ignore[attr-defined]
                return q if q in self.funcs else None
            if obj in v.module_aliases:
                m = self._resolve_module(v.module_aliases[obj])
                if m and f"{m}.{meth}" in self.funcs:
                    return f"{m}.{meth}"
            if obj in v.symbol_imports:  # `from pkg import mod; mod.meth()`
                mod, orig = v.symbol_imports[obj]
                m = self._resolve_module(f"{mod}.{orig}" if mod else orig)
                if m and f"{m}.{meth}" in self.funcs:
                    return f"{m}.{meth}"
        return None

    # -- taint ------------------------------------------------------------- #
    def _propagate(self) -> dict[str, set[tuple[str, str, str]]]:
        tainted = {q: set(f.roots) for q, f in self.funcs.items()}
        edges: dict[str, set[str]] = defaultdict(set)
        for cs in self.calls:
            if cs.caller in self.funcs and cs.target in self.funcs:
                edges[cs.caller].add(cs.target)
        # Fixpoint: a function inherits the taint of everything it calls.
        changed = True
        while changed:
            changed = False
            for caller, callees in edges.items():
                for callee in callees:
                    new = tainted[callee] - tainted[caller]
                    if new:
                        tainted[caller] |= new
                        changed = True
        return tainted

    def cross_file_taint_findings(self) -> list[Finding]:
        """Indirect findings for call sites that reach crypto through a wrapper in
        another file. Only cross-file sites are emitted (intra-file is taint.py's job)."""
        tainted = self._propagate()
        findings: list[Finding] = []
        seen: set[tuple[str, int, str]] = set()
        for cs in self.calls:
            if cs.target is None:
                continue
            roots = tainted.get(cs.target)
            if not roots:
                continue
            target = self.funcs[cs.target]
            if target.rel_path == cs.rel_path:
                continue  # same file → owned by the intra-module taint pass
            low = cs.line_text.lower()
            callee = cs.target.rsplit(".", 1)[-1]
            target_mod = _module_qname(target.rel_path)
            for family, algo, risk in sorted(roots):
                if any(kw in low for kw in _FAMILY_KEYWORDS.get(family, ())):
                    continue  # direct scan already owns this line
                key = (cs.rel_path, cs.lineno, family)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(Finding(
                    file_path=cs.rel_path,
                    line_number=cs.lineno,
                    algorithm=f"{algo} (via {callee}() in {target_mod})",
                    risk_level=risk,
                    why=(f"Calls {callee}(), which reaches quantum-vulnerable {algo} "
                         f"through a wrapper in module '{target_mod}' "
                         f"(cross-file data-flow analysis)."),
                    family=family,
                    snippet=cs.line_text.strip(),
                    confidence="indirect",
                ))
        return findings


def _collect_python_sources(root: str) -> dict[str, str]:
    from .scanner import _SKIP_DIRS
    files: dict[str, str] = {}
    for dir_root, dirs, names in os.walk(root):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for name in names:
            if EXT_TO_LANG.get(os.path.splitext(name)[1].lower()) != "python":
                continue
            abs_path = os.path.join(dir_root, name)
            rel = os.path.relpath(abs_path, root).replace(os.sep, "/")
            try:
                with open(abs_path, "r", encoding="utf-8", errors="ignore") as fh:
                    files[rel] = fh.read()
            except OSError:
                continue
    return files


def cross_file_taint(root: str) -> list[Finding]:
    """Build the program-wide call graph under ``root`` and return cross-file
    indirect crypto findings. Returns [] for a single file (nothing is cross-file)."""
    if not os.path.isdir(root):
        return []
    files = _collect_python_sources(root)
    if len(files) < 2:
        return []
    return CallGraph.build(files).cross_file_taint_findings()

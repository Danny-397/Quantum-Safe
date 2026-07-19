"""Reachability ranking for findings.

A raw finding list treats every hit equally, but an `RSA` call in a dead helper
or an example script is not the same risk as one on a live request path. This
module attaches a **reachability** label so reports can rank exploitable findings
above noise — directly addressing the capability-vs-usage gap that dependency and
pattern scanning otherwise leave open.

Three labels, most to least reachable:

* ``reachable``     — module-level code (runs on import) or inside a function that
  is referenced somewhere in the scanned tree (or is decorated / an entrypoint).
* ``test/example``  — the finding lives under a test, example, docs, or fixture
  path; real but rarely shipped.
* ``unreferenced``  — Python only: the enclosing top-level function's name never
  appears anywhere else in the scanned tree and it carries no decorator, i.e.
  dead code by a conservative definition.

The Python signal is intentionally **conservative**: a function counts as
referenced if its name appears *anywhere* as a load or attribute (not only as a
direct call), so callbacks and framework hooks are never mislabeled dead. The
whole pass only ever *demotes* confidence in ranking — it never drops a finding.
"""

from __future__ import annotations

import ast
import os

from .scanner import EXT_TO_LANG, Finding

REACHABLE = "reachable"
TEST_EXAMPLE = "test/example"
UNREFERENCED = "unreferenced"

# Ranking weight (lower = surfaced first).
RANK = {REACHABLE: 0, "": 0, TEST_EXAMPLE: 1, UNREFERENCED: 2}

# Path segments / filename patterns that mark non-production code.
_TEST_DIRS = {
    "test", "tests", "__tests__", "spec", "specs", "example", "examples",
    "doc", "docs", "sample", "samples", "fixture", "fixtures",
    "benchmark", "benchmarks", "demo", "demos",
}
_ENTRYPOINTS = {"main", "__main__", "handler", "lambda_handler", "setup", "run"}


def _is_test_path(rel_path: str) -> bool:
    parts = rel_path.replace("\\", "/").lower().split("/")
    if any(seg in _TEST_DIRS for seg in parts[:-1]):
        return True
    fname = parts[-1]
    return (
        fname == "conftest.py"
        or fname.startswith("test_")
        or fname.startswith("test.")
        or "_test." in fname
        or ".test." in fname
        or ".spec." in fname
    )


class _PyIndex(ast.NodeVisitor):
    """Collect, for one module: referenced names and top-level function ranges."""

    def __init__(self) -> None:
        self.referenced: set[str] = set()          # names used as load/attr anywhere
        self.decorated: set[str] = set()           # top-level funcs with a decorator
        # (name, start_line, end_line) for each top-level function.
        self.funcs: list[tuple[str, int, int]] = []
        self._depth = 0

    def _visit_func(self, node: ast.AST) -> None:
        top_level = self._depth == 0
        if top_level:
            end = getattr(node, "end_lineno", None) or node.lineno
            self.funcs.append((node.name, node.lineno, end))
            if node.decorator_list:
                self.decorated.add(node.name)
        self._depth += 1
        self.generic_visit(node)
        self._depth -= 1

    visit_FunctionDef = _visit_func       # type: ignore[assignment]
    visit_AsyncFunctionDef = _visit_func  # type: ignore[assignment]

    def visit_Name(self, node: ast.Name) -> None:  # noqa: N802
        if isinstance(node.ctx, ast.Load):
            self.referenced.add(node.id)
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:  # noqa: N802
        self.referenced.add(node.attr)
        self.generic_visit(node)


def annotate_reachability(findings: list[Finding], root: str) -> list[Finding]:
    """Set ``.reachability`` on each source finding in place; returns the list.

    Dependency findings are left untouched (their scope already conveys direct vs
    transitive). Non-Python source findings get the path-based signal only.
    """
    if not os.path.isdir(root):
        # Single-file scans still get the path heuristic.
        for f in findings:
            if f.origin == "source":
                f.reachability = TEST_EXAMPLE if _is_test_path(f.file_path) else REACHABLE
        return findings

    # Pass 1: index every Python file once — global referenced names + per-file
    # function ranges. Reading is cheap relative to the scan already done.
    py_index: dict[str, _PyIndex] = {}
    global_referenced: set[str] = set()
    py_files = {f.file_path for f in findings
                if f.origin == "source" and EXT_TO_LANG.get(
                    os.path.splitext(f.file_path)[1].lower()) == "python"}
    for rel in py_files:
        try:
            with open(os.path.join(root, rel), "r", encoding="utf-8", errors="ignore") as fh:
                tree = ast.parse(fh.read())
        except (OSError, SyntaxError, ValueError):
            continue
        idx = _PyIndex()
        idx.visit(tree)
        py_index[rel] = idx
        global_referenced |= idx.referenced

    # Pass 2: label.
    for f in findings:
        if f.origin != "source":
            continue
        if _is_test_path(f.file_path):
            f.reachability = TEST_EXAMPLE
            continue
        idx = py_index.get(f.file_path)
        if idx is None:
            f.reachability = REACHABLE   # non-Python or unparsed: path signal only
            continue
        func = _enclosing_func(idx.funcs, f.line_number)
        if func is None:
            f.reachability = REACHABLE   # module-level code runs on import
        elif func in global_referenced or func in idx.decorated or func in _ENTRYPOINTS:
            f.reachability = REACHABLE
        else:
            f.reachability = UNREFERENCED
    return findings


def _enclosing_func(funcs: list[tuple[str, int, int]], line: int) -> str | None:
    """Name of the top-level function whose line range contains ``line``, else None."""
    for name, start, end in funcs:
        if start <= line <= end:
            return name
    return None

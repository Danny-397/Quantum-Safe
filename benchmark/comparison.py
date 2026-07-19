"""Head-to-head comparison against other scanners on the labeled corpus.

The point QuantumSafe exists to make is that **generic security scanners are not
quantum-aware**: they flag classically-broken crypto (MD5, SHA-1, DES) but treat
RSA/ECC/DSA/DH as *secure*, because those are only broken by a quantum computer.
So on a post-quantum readiness task they miss most of what matters.

This harness measures that concretely and reproducibly. It scores each available
tool against the SAME hand-labeled ground truth (`labels.json`, the
`(file, family)` pairs in `benchmark/positive/`) and reports how many each tool
detects, plus its language/family coverage.

* **QuantumSafe** — always run (it's this repo).
* **Bandit** — run if installed (`pip install bandit`); a widely-used Python
  security linter. Python-only, and by design flags weak hashes/ciphers, not
  quantum-vulnerable asymmetric crypto.
* **Semgrep** — run if on PATH; results parsed from its JSON.

No competitor numbers are hard-coded: a tool that isn't installed is reported as
"not run", never guessed. Run:  python benchmark/comparison.py
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from quantumsafe.scanner import scan_path  # noqa: E402

BASE = os.path.dirname(os.path.abspath(__file__))
_PY_EXT = ".py"


def _labels() -> dict[str, list[str]]:
    with open(os.path.join(BASE, "labels.json"), encoding="utf-8") as fh:
        return json.load(fh)


def _ground_truth_pairs(labels: dict) -> set[tuple[str, str]]:
    return {(fp, fam) for fp, fams in labels.items() for fam in fams}


# --------------------------------------------------------------------------- #
# Tool runners: each returns the set of (rel_path, family) pairs it detects.
# --------------------------------------------------------------------------- #


def run_quantumsafe(labels: dict) -> set[tuple[str, str]]:
    detected: set[tuple[str, str]] = set()
    for f in scan_path(BASE):
        rel = f.file_path.replace("\\", "/")
        # scan_path is run over BASE; keep the corpus-relative tail.
        for key in labels:
            if rel.endswith(key):
                detected.add((key, f.family))
    return detected


# Map a competitor's free-text finding to our family vocabulary (conservative).
def _map_text_to_family(text: str) -> str | None:
    t = text.lower()
    if "md5" in t:
        return "md5"
    if "sha1" in t or "sha-1" in t:
        return "sha1"
    if "3des" in t or "triple des" in t or "des3" in t or "des " in t:
        return "3des"
    if "rc4" in t or "arc4" in t:
        return "rc4"
    if "rsa" in t:
        return "rsa"
    if "dsa" in t:
        return "dsa"
    if "ecdsa" in t or "elliptic" in t or "ecc" in t:
        return "ecc"
    return None


def _bandit_cmd() -> list[str] | None:
    """Prefer the console script; fall back to ``python -m bandit`` (not on PATH)."""
    if shutil.which("bandit"):
        return ["bandit"]
    try:
        import bandit  # noqa: F401
        return [sys.executable, "-m", "bandit"]
    except ModuleNotFoundError:
        return None


def run_bandit(labels: dict) -> set[tuple[str, str]] | None:
    cmd = _bandit_cmd()
    if cmd is None:
        return None
    proc = subprocess.run(
        [*cmd, "-r", "-f", "json", "-q", BASE],
        capture_output=True, text=True,
    )
    try:
        data = json.loads(proc.stdout)
    except ValueError:
        return set()
    detected: set[tuple[str, str]] = set()
    for res in data.get("results", []):
        rel = res.get("filename", "").replace("\\", "/")
        fam = _map_text_to_family(res.get("issue_text", "") + " " + res.get("test_name", ""))
        if not fam:
            continue
        for key in labels:
            if rel.endswith(key):
                detected.add((key, fam))
    return detected


def run_semgrep(labels: dict) -> set[tuple[str, str]] | None:
    if shutil.which("semgrep") is None:
        return None
    proc = subprocess.run(
        ["semgrep", "--config", "p/r2c-security-audit", "--json", "--quiet", BASE],
        capture_output=True, text=True,
    )
    try:
        data = json.loads(proc.stdout)
    except ValueError:
        return set()
    detected: set[tuple[str, str]] = set()
    for res in data.get("results", []):
        rel = res.get("path", "").replace("\\", "/")
        msg = (res.get("extra", {}) or {}).get("message", "") + " " + res.get("check_id", "")
        fam = _map_text_to_family(msg)
        if not fam:
            continue
        for key in labels:
            if rel.endswith(key):
                detected.add((key, fam))
    return detected


def _score(detected: set, truth: set) -> dict:
    tp = detected & truth
    fams = sorted({fam for _, fam in tp})
    langs = sorted({os.path.splitext(fp)[1] for fp, _ in tp})
    return {"caught": len(tp), "total": len(truth), "recall": len(tp) / len(truth),
            "families": fams, "file_types": langs}


def evaluate() -> dict:
    labels = _labels()
    truth = _ground_truth_pairs(labels)
    results: dict[str, dict | None] = {}

    results["QuantumSafe"] = _score(run_quantumsafe(labels), truth)
    for name, runner in (("Bandit", run_bandit), ("Semgrep", run_semgrep)):
        detected = runner(labels)
        results[name] = _score(detected, truth) if detected is not None else None
    return {"ground_truth": len(truth), "results": results}


def main() -> int:
    r = evaluate()
    print("QuantumSafe — comparison on the labeled corpus")
    print("=" * 60)
    print(f"  Ground-truth (file, family) pairs: {r['ground_truth']}")
    print("-" * 60)
    for tool, s in r["results"].items():
        if s is None:
            print(f"  {tool:12} not run (not installed)")
            continue
        print(f"  {tool:12} caught {s['caught']}/{s['total']} "
              f"({s['recall']:.0%})  families={s['families']}")
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    with open(os.path.join(BASE, "comparison.json"), "w", encoding="utf-8") as fh:
        json.dump({"generated_at": generated_at, **r}, fh, indent=2)
    print(f"  Wrote {os.path.join(BASE, 'comparison.json')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

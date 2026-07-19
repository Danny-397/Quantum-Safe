"""Evaluate the QuantumSafe scanner against a labeled benchmark.

Ground truth is at (file, detection-family) granularity in labels.json. We run
the real scanner over benchmark/positive (known-vulnerable code) and
benchmark/negative (safe code + decoys: comments, word-boundary traps) and report
precision, recall, and F1 — including the exact false positives / false negatives
so the numbers are auditable, not asserted.

Run:  python benchmark/evaluate.py
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from quantumsafe.scanner import scan_path  # noqa: E402

BASE = os.path.dirname(os.path.abspath(__file__))


def _score(labels: dict[str, list[str]], mask_strings: bool) -> dict:
    detected: dict[str, set[str]] = {}
    for f in scan_path(BASE, mask_strings=mask_strings):
        if f.file_path in labels:
            detected.setdefault(f.file_path, set()).add(f.family)

    expected_pairs = {(fp, fam) for fp, fams in labels.items() for fam in fams}
    detected_pairs = {(fp, fam) for fp, fams in detected.items() for fam in fams}

    tp = expected_pairs & detected_pairs
    fp = detected_pairs - expected_pairs
    fn = expected_pairs - detected_pairs

    precision = len(tp) / (len(tp) + len(fp)) if (tp or fp) else 1.0
    recall = len(tp) / (len(tp) + len(fn)) if (tp or fn) else 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {
        "precision": precision, "recall": recall, "f1": f1,
        "tp": sorted(tp), "fp": sorted(fp), "fn": sorted(fn),
    }


def evaluate() -> dict:
    labels: dict[str, list[str]] = json.load(open(os.path.join(BASE, "labels.json")))
    return {
        "improved": _score(labels, mask_strings=True),
        "naive": _score(labels, mask_strings=False),
        "files": len(labels),
        "positives": sum(1 for v in labels.values() if v),
        "negatives": sum(1 for v in labels.values() if not v),
    }


def _report(name: str, r: dict) -> None:
    print(f"  [{name}]")
    print(f"    True positives:  {len(r['tp'])}")
    print(f"    False positives: {len(r['fp'])}  {r['fp'] if r['fp'] else ''}")
    print(f"    False negatives: {len(r['fn'])}  {r['fn'] if r['fn'] else ''}")
    print(f"    Precision: {r['precision']:.1%}   Recall: {r['recall']:.1%}   F1: {r['f1']:.1%}")


def main() -> None:
    r = evaluate()
    print("QuantumSafe scanner — benchmark evaluation")
    print("=" * 60)
    print(f"  Files: {r['files']}  ({r['positives']} positive, {r['negatives']} negative/decoy)")
    print("-" * 60)
    _report("naive line-regex baseline (masking off)", r["naive"])
    print()
    _report("QuantumSafe (string/comment-aware)", r["improved"])
    print("-" * 60)
    fp_removed = len(r["naive"]["fp"]) - len(r["improved"]["fp"])
    print(f"  False positives removed by usage-awareness: {fp_removed}")


if __name__ == "__main__":
    main()

"""Run the seeded (mutation) recall benchmark as part of the suite.

Guards detection *breadth*: ground truth is known by construction, so a drop in
recall means a real regression in how many idiomatic crypto usages we catch.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "benchmark"))

from seeded import evaluate  # noqa: E402


def test_seeded_recall_is_high():
    r = evaluate()
    # Thresholds sit below the current 100% to leave honest headroom while still
    # catching a real regression in detection breadth.
    assert r["total"] >= 40, "expected a corpus of meaningful size"
    assert r["recall"] >= 0.9, f"recall regressed; missed: {r['misses']}"


def test_seeded_mutation_precision_is_high():
    r = evaluate()
    # The same algorithm name in a comment/string must not be flagged.
    assert r["decoy_precision"] >= 0.95, f"mutation FPs: {r['decoy_fp_cases']}"

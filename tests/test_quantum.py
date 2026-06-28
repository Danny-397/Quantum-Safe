"""Tests for the quantum module.

Skipped automatically when Qiskit isn't installed (it's an optional, heavy
dependency kept out of the core/CI requirements).
"""

import os
import sys

import pytest

pytest.importorskip("qiskit")
pytest.importorskip("qiskit_aer")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from quantum.grover import grover_search  # noqa: E402
from quantum.shor import factor_15, quantum_order_finding  # noqa: E402


def test_grover_recovers_secret_key():
    found, conf, iters, N = grover_search("101")
    assert found == "101"
    assert conf > 0.5


def test_quantum_order_finding_period():
    # a=4 mod 15 has order 2 (4^2 = 16 = 1 mod 15).
    assert quantum_order_finding(4) == 2


def test_shor_factors_15():
    factors = factor_15(verbose=False)
    assert factors is not None
    assert sorted(factors) == [3, 5]

"""Quantum Risk Score calculation.

The score is derived purely from real findings — never hardcoded:

    HIGH   finding  -> +15 points
    MEDIUM finding  -> +5 points
    LOW    finding  -> +1 point

The total is capped at 100. Bands:

    0-30   Low      — good quantum hygiene
    31-60  Medium   — plan migration
    61-80  High     — prioritize migration
    81-100 Critical — immediate action required
"""

from __future__ import annotations

from .scanner import RISK_HIGH, RISK_LOW, RISK_MEDIUM, Finding

POINTS = {RISK_HIGH: 15, RISK_MEDIUM: 5, RISK_LOW: 1}
MAX_SCORE = 100


def count_by_severity(findings: list[Finding]) -> dict[str, int]:
    counts = {RISK_HIGH: 0, RISK_MEDIUM: 0, RISK_LOW: 0}
    for f in findings:
        if f.risk_level in counts:
            counts[f.risk_level] += 1
    return counts


def calculate_score(findings: list[Finding]) -> int:
    total = sum(POINTS.get(f.risk_level, 0) for f in findings)
    return min(total, MAX_SCORE)


def risk_band(score: int) -> str:
    if score <= 30:
        return "Low"
    if score <= 60:
        return "Medium"
    if score <= 80:
        return "High"
    return "Critical"


def band_message(band: str) -> str:
    return {
        "Low": "Good quantum hygiene.",
        "Medium": "Plan migration.",
        "High": "Prioritize migration.",
        "Critical": "Immediate action required.",
    }.get(band, "")

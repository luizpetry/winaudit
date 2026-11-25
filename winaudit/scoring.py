"""Calculo da nota de seguranca."""
from __future__ import annotations

from .models import CheckResult, Severity, Status

WEIGHTS = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 15,
    Severity.MEDIUM: 8,
    Severity.LOW: 3,
    Severity.NONE: 0,
}

# WARN conta metade da penalidade de um FAIL
STATUS_FACTOR = {Status.FAIL: 1.0, Status.WARN: 0.5}


def compute_score(results: list[CheckResult]) -> int:
    penalty = 0.0
    for r in results:
        for f in r.findings:
            penalty += WEIGHTS[f.severity] * STATUS_FACTOR.get(f.status, 0)
    return max(0, round(100 - penalty))


def grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"

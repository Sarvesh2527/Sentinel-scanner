"""
scoring.py -- combines all check results into a single overall security score.

Model: every check starts the site with full marks. A failing check subtracts
points weighted by its severity; a warning subtracts a smaller amount. The final
score is clamped to 0-100 and mapped to a letter grade. This gives users one
headline number plus a familiar A-F grade.
"""

from __future__ import annotations

from ._common import (
    STATUS_FAIL, STATUS_WARN,
    SEV_HIGH, SEV_MEDIUM, SEV_LOW, SEV_INFO,
)

# Points removed for a hard FAIL, by severity.
FAIL_PENALTY = {
    SEV_HIGH: 22,
    SEV_MEDIUM: 12,
    SEV_LOW: 6,
    SEV_INFO: 0,
}

# Warnings are softer -- roughly a third of the fail penalty.
WARN_PENALTY = {
    SEV_HIGH: 8,
    SEV_MEDIUM: 4,
    SEV_LOW: 2,
    SEV_INFO: 0,
}


def _grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 55:
        return "D"
    if score >= 40:
        return "E"
    return "F"


def _rating(score: int) -> str:
    if score >= 90:
        return "Excellent"
    if score >= 75:
        return "Good"
    if score >= 55:
        return "Fair"
    if score >= 40:
        return "Poor"
    return "Critical"


def compute_score(results: list[dict]) -> dict:
    """
    Take the list of check result dicts and return a score summary:
        { score, grade, rating, passed, failed, warned, total }
    """
    score = 100
    passed = failed = warned = 0

    for r in results:
        status = r.get("status")
        sev = r.get("severity", SEV_INFO)
        if status == STATUS_FAIL:
            failed += 1
            score -= FAIL_PENALTY.get(sev, 0)
        elif status == STATUS_WARN:
            warned += 1
            score -= WARN_PENALTY.get(sev, 0)
        elif status == "pass":
            passed += 1
        # "info" results (couldn't determine) don't move the score.

    score = max(0, min(100, score))

    return {
        "score": score,
        "grade": _grade(score),
        "rating": _rating(score),
        "passed": passed,
        "failed": failed,
        "warned": warned,
        "total": len(results),
    }

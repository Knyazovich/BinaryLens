"""Severity aggregation.

This module deliberately does NOT produce a single numeric "risk score"
or malware probability. It reports how many findings fell into each
severity bucket, plus a short, heavily-hedged qualitative note. Anyone
wanting a defensible verdict has to look at the findings themselves.
"""

from __future__ import annotations

from typing import Dict, List

from binarylens.models import SEVERITY_LEVELS, Finding


def summarize(findings: List[Finding]) -> Dict[str, int]:
    counts = {level: 0 for level in SEVERITY_LEVELS}
    for f in findings:
        if f.severity in counts:
            counts[f.severity] += 1
    return counts


def assessment_note(summary: Dict[str, int]) -> str:
    """A short, deliberately hedged qualitative note. Never a percentage,
    never the word "malware", never a confident verdict."""
    high = summary.get("HIGH", 0)
    medium = summary.get("MEDIUM", 0)
    low = summary.get("LOW", 0)

    if high > 0:
        return (
            "One or more strongly correlated indicators were found. "
            "Manual review in a full analysis environment is recommended."
        )
    if medium > 0:
        return (
            "Some correlated indicators were found that may warrant a closer look. "
            "This is not a determination of malicious intent."
        )
    if low > 0:
        return "A small number of weak indicators were found; no strong correlation was observed."
    return "No significant anomalies were identified by static analysis."

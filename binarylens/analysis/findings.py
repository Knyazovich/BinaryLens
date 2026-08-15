"""Factory helpers for building Capability and Finding objects.

Centralizing construction here keeps severity values consistent across
every rule module in `analysis/indicators/`, and gives one place to
change how evidence/confidence get attached to a Finding.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from binarylens.models import SEVERITY_LEVELS, Capability, Finding


def new_capability(category: str, apis: List[str]) -> Capability:
    return Capability(category=category, apis=sorted(set(apis)))


def new_finding(
    severity: str,
    name: str,
    description: str,
    evidence: Optional[List[str]] = None,
    confidence: Optional[str] = None,
    category: Optional[str] = None,
    **extra_details: Any,
) -> Finding:
    """Build a Finding with a validated severity.

    `category` (when given) is stored in details["category"] so the
    correlation engine can later suppress a redundant informational
    capability-level finding once a stronger, evidence-backed finding for
    the same category has already been produced.
    """
    severity = severity.upper()
    if severity not in SEVERITY_LEVELS:
        raise ValueError(f"Invalid severity '{severity}'. Must be one of {SEVERITY_LEVELS}.")

    details: Dict[str, Any] = dict(extra_details)
    if category is not None:
        details["category"] = category

    return Finding(
        severity=severity,
        name=name,
        description=description,
        evidence=sorted(set(evidence)) if evidence else [],
        confidence=confidence,
        details=details,
    )


def severity_rank(severity: str) -> int:
    """Higher is more severe. Useful for sorting findings for display."""
    try:
        return SEVERITY_LEVELS.index(severity.upper())
    except ValueError:
        return -1


def sort_findings(findings: List[Finding]) -> List[Finding]:
    """Sort findings from most to least severe, stable on original order
    within the same severity."""
    return sorted(findings, key=lambda f: severity_rank(f.severity), reverse=True)

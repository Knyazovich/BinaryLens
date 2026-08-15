"""Anti-debugging / anti-analysis correlation rules.

Timing APIs (QueryPerformanceCounter, GetTickCount, ...) are extremely
common for entirely benign reasons (profiling, animation, rate limiting)
and are never treated as anti-debugging evidence by themselves. Only
actual debugger-detection APIs count as evidence here, and even those
only escalate to a MEDIUM finding once more than one distinct mechanism
is present.
"""

from __future__ import annotations

from typing import List

from binarylens.analysis import imports as api
from binarylens.analysis.findings import new_finding
from binarylens.analysis.indicators.api_categories import CATEGORY_ANTI_DEBUG
from binarylens.models import Finding


def detect_anti_debug_patterns(found_apis: set) -> List[Finding]:
    debugger_checks = sorted(found_apis & api.DEBUGGER_DETECTION_APIS)

    if not debugger_checks:
        return []

    if len(debugger_checks) == 1:
        return [
            new_finding(
                severity="LOW",
                name="Debugger detection API present",
                description=(
                    "The binary imports a single API capable of detecting the "
                    "presence of a debugger. This alone is common in licensing "
                    "checks, crash reporters, and anti-tamper code in ordinary "
                    "software, and is not treated as a strong signal by itself."
                ),
                evidence=debugger_checks,
                confidence="Low",
                category=CATEGORY_ANTI_DEBUG,
            )
        ]

    return [
        new_finding(
            severity="MEDIUM",
            name="Multiple anti-debugging indicators detected",
            description=(
                "The binary imports more than one distinct API used to detect "
                "debuggers or analysis environments. A single check is common in "
                "legitimate software, but multiple independent debugger-detection "
                "mechanisms together are a stronger signal of deliberate "
                "anti-analysis behavior."
            ),
            evidence=debugger_checks,
            confidence="Medium",
            category=CATEGORY_ANTI_DEBUG,
        )
    ]

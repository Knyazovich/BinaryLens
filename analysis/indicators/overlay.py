"""Overlay (trailing data appended after the last section) analysis.

An overlay is not inherently suspicious -- installers routinely append
tens or hundreds of megabytes of bundled payload data, and digital
signatures are also stored as overlay data. This module reports overlay
size/ratio as informational context, and only softens or drops findings
when installer context is present rather than escalating.
"""

from __future__ import annotations

from typing import Dict, List

from binarylens.analysis.findings import new_finding
from binarylens.models import Finding

# An overlay bigger than this fraction of total file size is called out
# as "large" in the informational note. This is a description threshold,
# not a severity threshold -- it never escalates the finding to WARNING
# by itself.
LARGE_OVERLAY_RATIO = 0.5
LARGE_OVERLAY_MIN_BYTES = 5 * 1024 * 1024  # 5 MB


def analyze_overlay(overlay_size: int, file_size: int, looks_like_installer: bool) -> tuple:
    """Return (overlay_info_dict, findings)."""
    if overlay_size <= 0:
        return {"present": False, "size_bytes": 0, "ratio": 0.0}, []

    ratio = overlay_size / file_size if file_size else 0.0
    info = {"present": True, "size_bytes": overlay_size, "ratio": round(ratio, 4)}

    is_large = overlay_size >= LARGE_OVERLAY_MIN_BYTES and ratio >= LARGE_OVERLAY_RATIO

    findings: List[Finding] = []

    if is_large:
        if looks_like_installer:
            description = (
                "A large amount of data is appended after the last defined "
                "section. Combined with other characteristics of this binary, "
                "this is consistent with bundled installer payload data rather "
                "than an anomaly."
            )
        else:
            description = (
                "A large amount of data is appended after the last defined "
                "section. This can be bundled installer/archive payload data, "
                "an embedded signature, or (less commonly) hidden data. No "
                "installer-framework characteristics were otherwise detected "
                "for this binary."
            )
        findings.append(
            new_finding(
                severity="INFO",
                name="Large overlay detected",
                description=description,
                evidence=[f"size_bytes={overlay_size}", f"ratio={ratio:.2f}"],
                confidence="Low",
            )
        )
    else:
        findings.append(
            new_finding(
                severity="INFO",
                name="Overlay present",
                description=(
                    "Extra data exists after the last defined section. This is "
                    "commonly used for appended installer payloads, digital "
                    "signatures, or self-extracting archive data."
                ),
                evidence=[f"size_bytes={overlay_size}"],
                confidence="Low",
            )
        )

    return info, findings

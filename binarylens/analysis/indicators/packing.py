"""Packing likelihood correlation.

High entropy alone is not packing -- compressed resources, embedded
archives, and encrypted-at-rest license data all produce high entropy
in an entirely ordinary binary. This module only raises a finding when
several independent signals line up together.
"""

from __future__ import annotations

from typing import List

from binarylens.analysis.findings import new_finding
from binarylens.analysis.indicators.sections import CLASS_POTENTIALLY_SUSPICIOUS
from binarylens.models import Finding, ImportEntry, SectionInfo

HIGH_ENTROPY_THRESHOLD = 7.0
MIN_SECTION_SIZE_FOR_ENTROPY = 64
SMALL_IMPORT_TABLE_THRESHOLD = 3


def detect_packing_indicators(
    sections: List[SectionInfo],
    imports: List[ImportEntry],
    section_classifications: dict,
    fmt: str,
) -> List[Finding]:
    high_entropy_sections = [
        s for s in sections if s.entropy >= HIGH_ENTROPY_THRESHOLD and s.raw_size >= MIN_SECTION_SIZE_FOR_ENTROPY
    ]

    total_imported_functions = sum(len(e.functions) for e in imports)
    small_import_table = fmt == "PE" and total_imported_functions <= SMALL_IMPORT_TABLE_THRESHOLD

    packer_named_sections = [
        name for name, cls in section_classifications.items() if cls == CLASS_POTENTIALLY_SUSPICIOUS
    ]

    signals = []
    if high_entropy_sections:
        signals.append("high-entropy section(s)")
    if small_import_table:
        signals.append("unusually small import table")
    if packer_named_sections:
        signals.append("packer-associated section name")

    # Always surface a purely informational note about high entropy on
    # its own -- but only as INFO, and only if nothing stronger applies.
    findings: List[Finding] = []

    if len(signals) >= 2:
        evidence = [f"section={s.name} entropy={s.entropy:.2f}" for s in high_entropy_sections]
        if small_import_table:
            evidence.append(f"imported_functions={total_imported_functions}")
        evidence.extend(f"section={n}" for n in packer_named_sections)

        findings.append(
            new_finding(
                severity="MEDIUM",
                name="Possible packing indicators",
                description=(
                    "Multiple independent signals commonly associated with packed "
                    "or protected binaries were observed together: "
                    + ", ".join(signals)
                    + ". This is a heuristic combination, not confirmation that the "
                    "binary is packed."
                ),
                evidence=evidence,
                confidence="Medium",
            )
        )
    elif high_entropy_sections:
        evidence = [f"section={s.name} entropy={s.entropy:.2f}" for s in high_entropy_sections]
        findings.append(
            new_finding(
                severity="INFO",
                name="High entropy section",
                description=(
                    "One or more sections show high entropy, which is typical of "
                    "compressed, encrypted, or embedded resource data. On its own "
                    "this is common in ordinary binaries and is not evidence of "
                    "packing."
                ),
                evidence=evidence,
                confidence="Low",
            )
        )

    return findings

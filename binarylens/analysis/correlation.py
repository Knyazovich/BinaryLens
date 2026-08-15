"""Correlation engine orchestrator.

This is the only module that assembles the final capabilities/findings
for an AnalysisResult. It:

1. Builds the [Capabilities] inventory from imported APIs (informational,
   never scored).
2. Runs each correlation rule module and collects the Findings they
   produce, each already carrying an evidence-backed severity.
3. Adds a small number of low-noise INFO findings for capability
   categories that historically caused false positives (dynamic linking,
   process management, registry) -- but only when a stronger, more
   specific finding for that same category hasn't already been produced.
4. Adds structural/metadata findings that are unrelated to the API
   false-positive problem this refactor targets (missing sections,
   missing imports, zero timestamp).

Every rule module is independent and testable on its own; this file only
wires them together and de-duplicates by category.
"""

from __future__ import annotations

from typing import List

from binarylens.analysis.findings import new_finding, sort_findings
from binarylens.analysis.scoring import assessment_note, summarize
from binarylens.analysis.indicators import (
    anti_debug,
    api_categories,
    injection,
    installers,
    overlay as overlay_rules,
    packing,
    persistence,
    sections as section_rules,
)
from binarylens.models import AnalysisResult, Capability, Finding

# Categories that get a low-noise INFO "capability present" finding when
# no stronger, more specific finding already covers them. Deliberately a
# short, curated list -- see module docstring.
_AUTO_INFO_CATEGORIES = {
    api_categories.CATEGORY_DYNAMIC_LINKING: (
        "Dynamic API resolution capability",
        "The binary imports APIs used to resolve function addresses or load "
        "libraries at runtime rather than statically. This is extremely "
        "common in legitimate software and is provided as context only.",
    ),
    api_categories.CATEGORY_PROCESS_MANAGEMENT: (
        "Process management capability",
        "The binary imports APIs that can start or interact with other "
        "processes. This is common in installers, launchers, and many "
        "ordinary applications and is provided as context only.",
    ),
    api_categories.CATEGORY_REGISTRY: (
        "Registry manipulation capability",
        "The binary imports APIs that can read or write Windows registry "
        "keys/values. This is common in installers and configuration-storing "
        "applications and is provided as context only.",
    ),
}


def _categories_already_covered(findings: List[Finding]) -> set:
    covered = set()
    for f in findings:
        category = f.details.get("category")
        if category:
            covered.add(category)
    return covered


def _add_auto_info_findings(capabilities: List[Capability], existing_findings: List[Finding]) -> List[Finding]:
    covered = _categories_already_covered(existing_findings)
    by_category = {c.category: c for c in capabilities}

    added = []
    for category, (name, description) in _AUTO_INFO_CATEGORIES.items():
        if category in covered:
            continue
        capability = by_category.get(category)
        if not capability:
            continue
        added.append(
            new_finding(
                severity="INFO",
                name=name,
                description=description,
                evidence=capability.apis,
                confidence="Low",
                category=category,
            )
        )
    return added


def _structural_findings(result: AnalysisResult) -> List[Finding]:
    findings: List[Finding] = []

    if not result.sections:
        findings.append(
            new_finding(
                severity="LOW",
                name="No sections found",
                description="No sections were found in the binary, which is unusual for a typical executable.",
                confidence="Low",
            )
        )

    if result.file_info.format == "PE" and not result.imports:
        findings.append(
            new_finding(
                severity="LOW",
                name="No imports found",
                description=(
                    "No imported functions were found. This is unusual for a typical "
                    "Windows executable, though it can occur in statically-linked or "
                    "minimal binaries."
                ),
                confidence="Low",
            )
        )

    if result.file_info.format == "PE" and result.headers.get("compile_timestamp_raw") == 0:
        findings.append(
            new_finding(
                severity="INFO",
                name="Zero compile timestamp",
                description=(
                    "The PE compilation timestamp is zero, which can indicate a "
                    "stripped, reproducible, or manually crafted build. This is "
                    "common and not inherently suspicious."
                ),
                confidence="Low",
            )
        )

    if result.file_info.format == "PE":
        characteristics = result.headers.get("characteristics_flags", [])
        if characteristics and "IMAGE_FILE_EXECUTABLE_IMAGE" not in characteristics:
            findings.append(
                new_finding(
                    severity="LOW",
                    name="Executable image flag not set",
                    description=(
                        "The PE 'executable image' characteristic flag is not set, "
                        "which is unusual for a runnable binary."
                    ),
                    evidence=characteristics,
                    confidence="Low",
                )
            )

    return findings


def run_detection_engine(result: AnalysisResult) -> None:
    """Populate result.capabilities, result.findings, result.packaging_notes,
    and result.overlay in place."""
    found_apis = result.imported_function_names()

    capabilities = api_categories.categorize_imports(result.imports)

    packaging_notes, looks_like_installer = installers.detect_installer_context(
        result.sections, result.strings
    )

    findings: List[Finding] = []
    findings.extend(injection.detect_injection_patterns(found_apis))
    findings.extend(anti_debug.detect_anti_debug_patterns(found_apis))
    findings.extend(persistence.detect_persistence_patterns(found_apis))

    section_classifications, section_findings = section_rules.evaluate_sections(
        result.sections, result.file_info.format, looks_like_installer
    )
    findings.extend(section_findings)

    findings.extend(
        packing.detect_packing_indicators(
            result.sections, result.imports, section_classifications, result.file_info.format
        )
    )

    overlay_size = result.headers.get("overlay_size", 0)
    overlay_info, overlay_findings = overlay_rules.analyze_overlay(
        overlay_size, result.file_info.size, looks_like_installer
    )
    findings.extend(overlay_findings)

    findings.extend(_structural_findings(result))
    findings.extend(_add_auto_info_findings(capabilities, findings))

    for section in result.sections:
        section.classification = section_classifications.get(section.name)

    result.capabilities = capabilities
    result.findings = sort_findings(findings)
    result.packaging_notes = packaging_notes
    result.overlay = overlay_info
    result.assessment_note = assessment_note(summarize(result.findings))

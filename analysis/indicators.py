"""Rule-based static analysis engine.

Every rule here produces an *indicator*, not a verdict. BinaryLens never
declares a file to be malware -- it surfaces individual, individually
explained observations and lets the analyst draw their own conclusions.
Each function below inspects one aspect of the parsed binary and appends
zero or more Indicator objects.
"""

from __future__ import annotations

from typing import List

from binarylens.analysis.imports import (
    DYNAMIC_RESOLUTION_APIS,
    MEMORY_APIS,
    NETWORK_APIS,
    PROCESS_EXECUTION_APIS,
    PROCESS_INJECTION_APIS,
    ANTI_ANALYSIS_APIS,
    REGISTRY_APIS,
)
from binarylens.models import AnalysisResult, Indicator

HIGH_ENTROPY_THRESHOLD = 7.0
MIN_SECTION_SIZE_FOR_ENTROPY = 64  # skip entropy indicator noise on tiny sections

COMMON_PE_SECTION_NAMES = {
    ".text", ".data", ".rdata", ".rsrc", ".reloc", ".idata", ".edata",
    ".pdata", ".tls", ".bss", ".debug", ".didat", ".xdata", ".gfids",
    ".00cfg", ".sxdata",
}

COMMON_ELF_SECTION_NAMES = {
    ".text", ".data", ".bss", ".rodata", ".init", ".fini", ".plt",
    ".got", ".got.plt", ".dynamic", ".dynsym", ".dynstr", ".symtab",
    ".strtab", ".comment", ".note.gnu.build-id", ".gnu.hash", ".hash",
    ".eh_frame", ".eh_frame_hdr", ".interp", ".init_array", ".fini_array",
    ".shstrtab",
}

KNOWN_PACKER_SECTION_HINTS = {
    "upx0", "upx1", "upx2", ".upx", ".aspack", ".adata", ".packed",
    ".themida", ".vmp0", ".vmp1", ".enigma1", ".enigma2", ".nsp0", ".nsp1",
    ".mpress1", ".mpress2",
}


def _find_imported_functions(result: AnalysisResult, watchlist: set) -> List[str]:
    found = []
    for entry in result.imports:
        for func in entry.functions:
            base = func.split("@")[0]
            if base in watchlist:
                found.append(base)
    return sorted(set(found))


def check_high_entropy_sections(result: AnalysisResult) -> List[Indicator]:
    indicators = []
    for section in result.sections:
        if section.raw_size < MIN_SECTION_SIZE_FOR_ENTROPY:
            continue
        if section.entropy >= HIGH_ENTROPY_THRESHOLD:
            indicators.append(
                Indicator(
                    name="High entropy section detected",
                    description=(
                        "This section's data is close to statistically random, "
                        "which is typical of compressed, encrypted, or packed "
                        "content. This is an indicator only, not proof of packing."
                    ),
                    details={"section": section.name, "entropy": round(section.entropy, 2)},
                )
            )
    return indicators


def check_writable_executable_sections(result: AnalysisResult) -> List[Indicator]:
    indicators = []
    for section in result.sections:
        if "W" in section.permissions and "X" in section.permissions:
            indicators.append(
                Indicator(
                    name="Executable + writable section",
                    description=(
                        "A section that is both writable and executable can "
                        "indicate self-modifying code, a packer stub, or JIT "
                        "compilation. Some legitimate runtimes also do this."
                    ),
                    details={"section": section.name, "permissions": section.permissions},
                )
            )
    return indicators


def check_suspicious_apis(result: AnalysisResult) -> List[Indicator]:
    indicators = []

    dynamic = _find_imported_functions(result, DYNAMIC_RESOLUTION_APIS)
    if dynamic:
        indicators.append(
            Indicator(
                name="Dynamic API resolution",
                description=(
                    "The binary imports APIs commonly used to resolve function "
                    "addresses or load libraries at runtime rather than "
                    "statically. This can be used to obscure functionality but "
                    "is also extremely common in legitimate software."
                ),
                details={"apis": dynamic},
            )
        )

    memory = _find_imported_functions(result, MEMORY_APIS)
    if memory:
        indicators.append(
            Indicator(
                name="Executable memory allocation API",
                description=(
                    "The binary imports APIs that can allocate or change the "
                    "protection of memory regions, which is required for "
                    "techniques like manual code mapping or JIT, but is also "
                    "used by many legitimate applications and language runtimes."
                ),
                details={"apis": memory},
            )
        )

    injection = _find_imported_functions(result, PROCESS_INJECTION_APIS)
    if injection:
        indicators.append(
            Indicator(
                name="Process interaction / injection APIs detected",
                description=(
                    "The binary imports APIs that can read, write, or inject "
                    "code into the memory of another process. These are used "
                    "by debuggers and security tools as well as malware."
                ),
                details={"apis": injection},
            )
        )

    execution = _find_imported_functions(result, PROCESS_EXECUTION_APIS)
    if execution:
        indicators.append(
            Indicator(
                name="Process execution API detected",
                description=(
                    "The binary imports APIs capable of launching other "
                    "processes or commands."
                ),
                details={"apis": execution},
            )
        )

    network = _find_imported_functions(result, NETWORK_APIS)
    if network:
        indicators.append(
            Indicator(
                name="Network capability APIs detected",
                description=(
                    "The binary imports APIs associated with making network "
                    "connections or HTTP requests."
                ),
                details={"apis": network},
            )
        )

    anti_analysis = _find_imported_functions(result, ANTI_ANALYSIS_APIS)
    if anti_analysis:
        indicators.append(
            Indicator(
                name="Anti-analysis / anti-debugging APIs detected",
                description=(
                    "The binary imports APIs commonly used to detect debuggers "
                    "or analysis environments. Some legitimate software also "
                    "uses these for licensing or crash-reporting checks."
                ),
                details={"apis": anti_analysis},
            )
        )

    registry = _find_imported_functions(result, REGISTRY_APIS)
    if registry:
        indicators.append(
            Indicator(
                name="Registry manipulation APIs detected",
                description=(
                    "The binary imports APIs that can read or write Windows "
                    "registry keys/values. Very common in legitimate installers "
                    "and configuration-storing applications."
                ),
                details={"apis": registry},
            )
        )

    return indicators


def check_unusual_section_names(result: AnalysisResult) -> List[Indicator]:
    indicators = []
    fmt = result.file_info.format
    common = COMMON_PE_SECTION_NAMES if fmt == "PE" else COMMON_ELF_SECTION_NAMES

    for section in result.sections:
        normalized = section.name.strip().lower()
        if not normalized:
            continue
        if normalized in KNOWN_PACKER_SECTION_HINTS:
            indicators.append(
                Indicator(
                    name="Possible packing indicator",
                    description=(
                        "This section name is associated with a known packer or "
                        "protector. This is a naming heuristic only."
                    ),
                    details={"section": section.name},
                )
            )
        elif normalized not in common:
            indicators.append(
                Indicator(
                    name="Unusual section name",
                    description=(
                        "This section name does not match common compiler or "
                        "linker conventions for this file format."
                    ),
                    details={"section": section.name},
                )
            )
    return indicators


def check_packing_heuristics(result: AnalysisResult) -> List[Indicator]:
    """A lightweight combined heuristic: very few imports together with at
    least one high-entropy section can suggest the real import table is
    hidden behind a packer stub. This is explicitly heuristic and weak."""
    indicators = []
    total_imported_functions = sum(len(e.functions) for e in result.imports)
    has_high_entropy = any(
        s.entropy >= HIGH_ENTROPY_THRESHOLD and s.raw_size >= MIN_SECTION_SIZE_FOR_ENTROPY
        for s in result.sections
    )
    if result.file_info.format == "PE" and total_imported_functions <= 2 and has_high_entropy and result.sections:
        indicators.append(
            Indicator(
                name="Possible packing indicator",
                description=(
                    "The import table is unusually small while at least one "
                    "section shows high entropy. This combination is often "
                    "seen with packed or protected binaries, but can also "
                    "occur in minimal or statically-linked programs."
                ),
                details={"imported_functions": total_imported_functions},
            )
        )
    return indicators


def check_missing_metadata(result: AnalysisResult) -> List[Indicator]:
    indicators = []
    if not result.sections:
        indicators.append(
            Indicator(
                name="Missing expected metadata",
                description="No sections were found in the binary, which is unusual for a normal executable.",
                details={},
            )
        )
    if result.file_info.format == "PE" and not result.imports:
        indicators.append(
            Indicator(
                name="Missing expected metadata",
                description="No imported functions were found, which is unusual for a typical Windows executable.",
                details={},
            )
        )
    timestamp = result.headers.get("compile_timestamp_raw")
    if result.file_info.format == "PE" and timestamp == 0:
        indicators.append(
            Indicator(
                name="Missing expected metadata",
                description="The PE compilation timestamp is zero, which can indicate a stripped, "
                "reproducible, or manually crafted build.",
                details={},
            )
        )
    return indicators


def check_overlay_data(result: AnalysisResult) -> List[Indicator]:
    indicators = []
    overlay_size = result.headers.get("overlay_size", 0)
    if overlay_size and overlay_size > 0:
        indicators.append(
            Indicator(
                name="Overlay data present",
                description=(
                    "Extra data exists after the last defined section/segment. "
                    "This is often used to append installer payloads, "
                    "self-extracting archives, or signatures, but can also be "
                    "used to hide additional data."
                ),
                details={"overlay_size_bytes": overlay_size},
            )
        )
    return indicators


def check_abnormal_characteristics(result: AnalysisResult) -> List[Indicator]:
    indicators = []
    if result.file_info.format != "PE":
        return indicators

    characteristics = result.headers.get("characteristics_flags", [])
    if "IMAGE_FILE_EXECUTABLE_IMAGE" not in characteristics:
        indicators.append(
            Indicator(
                name="Abnormal PE characteristics",
                description="The PE 'executable image' flag is not set, which is unusual for a runnable binary.",
                details={"characteristics": characteristics},
            )
        )
    if "IMAGE_FILE_DLL" in characteristics and result.file_info.entry_point in (None, "0x00000000"):
        indicators.append(
            Indicator(
                name="Abnormal PE characteristics",
                description="The file is marked as a DLL but has no entry point defined.",
                details={},
            )
        )
    return indicators


def run_all_checks(result: AnalysisResult) -> List[Indicator]:
    """Run every indicator rule against the analysis result and return the
    combined, ordered list of indicators."""
    indicators: List[Indicator] = []
    indicators.extend(check_high_entropy_sections(result))
    indicators.extend(check_writable_executable_sections(result))
    indicators.extend(check_suspicious_apis(result))
    indicators.extend(check_unusual_section_names(result))
    indicators.extend(check_packing_heuristics(result))
    indicators.extend(check_missing_metadata(result))
    indicators.extend(check_overlay_data(result))
    indicators.extend(check_abnormal_characteristics(result))
    return indicators

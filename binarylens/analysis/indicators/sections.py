"""Section-name and section-characteristic classification.

An uncommon section name is not, by itself, evidence of anything -- it
just means the compiler/linker/packaging tool used a name outside the
small set BinaryLens recognizes. A finding is only produced when the
section is *both* unrecognized/packer-flagged *and* shows an actually
unusual structural characteristic (writable+executable, high entropy
combined with an odd size ratio, etc).
"""

from __future__ import annotations

from typing import Dict, List, Tuple

from binarylens.analysis.findings import new_finding
from binarylens.models import Finding, SectionInfo

CLASS_KNOWN_COMMON = "Known / Common"
CLASS_KNOWN_TOOLCHAIN = "Known Toolchain"
CLASS_KNOWN_INSTALLER = "Known Installer"
CLASS_POTENTIALLY_SUSPICIOUS = "Potentially Suspicious"
CLASS_UNKNOWN = "Unknown"

COMMON_PE_SECTION_NAMES = {
    ".text", ".data", ".rdata", ".rsrc", ".reloc", ".idata", ".edata",
    ".pdata", ".tls", ".bss",
}

COMMON_ELF_SECTION_NAMES = {
    ".text", ".data", ".bss", ".rodata", ".init", ".fini", ".plt",
    ".got", ".got.plt", ".dynamic", ".dynsym", ".dynstr", ".symtab",
    ".strtab", ".comment", ".note.gnu.build-id", ".gnu.hash", ".hash",
    ".eh_frame", ".eh_frame_hdr", ".interp", ".init_array", ".fini_array",
    ".shstrtab",
}

# Compiler/linker/runtime generated sections that are unusual to a naive
# "common names" list but are entirely standard toolchain output.
KNOWN_TOOLCHAIN_SECTION_NAMES = {
    ".debug", ".didat", ".xdata", ".gfids", ".00cfg", ".sxdata", ".CRT",
    ".gehcont", ".retplne", ".rtc$",
}

# Section names strongly associated with a specific, common installer
# framework (kept in sync conceptually with indicators/installers.py).
KNOWN_INSTALLER_SECTION_NAMES = {
    ".wixburn", ".taggant", ".ndata",
}

KNOWN_PACKER_SECTION_HINTS = {
    "upx0", "upx1", "upx2", ".upx", ".aspack", ".adata", ".packed",
    ".themida", ".vmp0", ".vmp1", ".enigma1", ".enigma2", ".nsp0", ".nsp1",
    ".mpress1", ".mpress2",
}


def classify_section_name(name: str, fmt: str) -> str:
    normalized = name.strip().lower()
    if not normalized:
        return CLASS_UNKNOWN

    common = COMMON_PE_SECTION_NAMES if fmt == "PE" else COMMON_ELF_SECTION_NAMES
    if normalized in common:
        return CLASS_KNOWN_COMMON
    if normalized in KNOWN_TOOLCHAIN_SECTION_NAMES:
        return CLASS_KNOWN_TOOLCHAIN
    if normalized in KNOWN_INSTALLER_SECTION_NAMES:
        return CLASS_KNOWN_INSTALLER
    if normalized in KNOWN_PACKER_SECTION_HINTS:
        return CLASS_POTENTIALLY_SUSPICIOUS
    return CLASS_UNKNOWN


def _size_ratio_is_unusual(section: SectionInfo) -> bool:
    """A virtual size wildly larger than the raw size on disk can indicate
    a section that gets decompressed/unpacked at load time. A small
    amount of slack from alignment padding is normal and ignored."""
    if section.raw_size <= 0:
        return section.virtual_size > 0
    ratio = section.virtual_size / section.raw_size
    return ratio >= 10.0 or ratio <= 0.05


def evaluate_sections(
    sections: List[SectionInfo], fmt: str, looks_like_installer: bool
) -> Tuple[Dict[str, str], List[Finding]]:
    """Classify every section and produce findings only for sections that
    are both unrecognized/flagged AND structurally unusual."""
    classifications: Dict[str, str] = {}
    findings: List[Finding] = []

    for section in sections:
        classification = classify_section_name(section.name, fmt)

        # A known installer section name is legitimate packaging context,
        # not a naming anomaly -- even outside a detected installer, since
        # the name itself is the signature.
        if classification == CLASS_KNOWN_INSTALLER:
            classifications[section.name] = classification
            continue

        classifications[section.name] = classification

        writable_executable = "W" in section.permissions and "X" in section.permissions
        odd_ratio = _size_ratio_is_unusual(section)
        high_entropy = section.entropy >= 7.0 and section.raw_size >= 64

        if writable_executable:
            findings.append(
                new_finding(
                    severity="MEDIUM",
                    name="Unusual executable/writable section",
                    description=(
                        "This section is both writable and executable at once, "
                        "which can indicate self-modifying code, a packer stub, "
                        "or JIT compilation. Some legitimate runtimes also do this."
                    ),
                    evidence=[f"section={section.name}", f"permissions={section.permissions}"],
                    confidence="Medium",
                )
            )

        if classification in (CLASS_POTENTIALLY_SUSPICIOUS, CLASS_UNKNOWN) and (odd_ratio or high_entropy):
            if classification == CLASS_POTENTIALLY_SUSPICIOUS:
                description = (
                    "This section's name matches a known packer/protector naming "
                    "convention, and it also shows an unusual structural "
                    "characteristic. This is a naming + structure heuristic, not "
                    "definitive proof of packing."
                )
            else:
                description = (
                    "This section's name doesn't match common compiler, linker, or "
                    "known packaging conventions, and it also shows an unusual "
                    "structural characteristic (size ratio and/or entropy)."
                )
            reasons = []
            if odd_ratio:
                reasons.append("unusual virtual/raw size ratio")
            if high_entropy:
                reasons.append(f"high entropy ({section.entropy:.2f})")

            findings.append(
                new_finding(
                    severity="LOW" if classification == CLASS_UNKNOWN else "MEDIUM",
                    name=f"Unusual section characteristics ({section.name})",
                    description=description,
                    evidence=[f"section={section.name}"] + reasons,
                    confidence="Low" if classification == CLASS_UNKNOWN else "Medium",
                )
            )

    return classifications, findings

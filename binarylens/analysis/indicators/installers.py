"""Recognition of common, legitimate installer/packaging frameworks.

This is context, not a security rule: recognizing that a binary looks
like a WiX Burn bootstrapper or an NSIS installer lets other rules (large
overlay, unusual section names) avoid flagging perfectly ordinary
packaging characteristics as anomalies. Detection is done generically
from section names and embedded strings -- never by matching a filename.
"""

from __future__ import annotations

from typing import List, Tuple

from binarylens.models import SectionInfo

# Section names that are strong, well-known signatures of a specific
# installer/bootstrapper framework.
_SECTION_NAME_SIGNATURES = {
    ".wixburn": "WiX Burn bootstrapper",
    ".taggant": "Symantec/DigiCert taggant (common in commercial installers)",
}

# Case-insensitive substrings commonly embedded (as plain strings) by
# these frameworks. Matched against the binary's extracted string list.
_STRING_SIGNATURES = {
    "nullsoft install system": "NSIS (Nullsoft Scriptable Install System)",
    "inno setup": "Inno Setup",
    "wix toolset": "WiX Toolset",
    "wixburn": "WiX Burn bootstrapper",
    "windows installer": "MSI / Windows Installer related",
    "installshield": "InstallShield",
    "innosetup": "Inno Setup",
    "advanced installer": "Advanced Installer",
}


def detect_installer_context(sections: List[SectionInfo], strings: List[str]) -> Tuple[List[str], bool]:
    """Return (packaging_notes, looks_like_installer).

    packaging_notes are short, informational strings meant for a
    dedicated [Packaging] report section. looks_like_installer is used
    by other rules (overlay, section-name analysis) to soften findings
    that would otherwise misclassify normal packaging behavior.
    """
    notes: List[str] = []
    matched = False

    for section in sections:
        normalized = section.name.strip().lower()
        if normalized in _SECTION_NAME_SIGNATURES:
            notes.append(f"{_SECTION_NAME_SIGNATURES[normalized]} section detected ({section.name})")
            matched = True

    if strings:
        seen_labels = set()
        for s in strings:
            s_lower = s.lower()
            for needle, label in _STRING_SIGNATURES.items():
                if label in seen_labels:
                    continue
                if needle in s_lower:
                    notes.append(f"{label}-related string detected")
                    seen_labels.add(label)
                    matched = True

    return notes, matched

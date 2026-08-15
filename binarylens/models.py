"""Shared data model for BinaryLens.

These dataclasses represent the fully computed analysis of a binary and
are consumed identically by the terminal renderer and the JSON report
writer, so the two output modes can never drift out of sync.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

# Severity levels used by Finding.severity, ordered from least to most
# significant. A Finding's severity reflects how strong the *evidence* is
# for the observation it describes -- it is never a malware verdict.
SEVERITY_LEVELS = ("INFO", "LOW", "MEDIUM", "HIGH")


@dataclass
class FileInfo:
    filename: str
    filepath: str
    size: int
    format: str  # "PE", "ELF", or "UNKNOWN"
    architecture: str
    entry_point: Optional[str] = None
    image_base: Optional[str] = None
    compile_timestamp: Optional[str] = None
    subsystem: Optional[str] = None


@dataclass
class Hashes:
    md5: str
    sha1: str
    sha256: str


@dataclass
class SectionInfo:
    name: str
    virtual_address: int
    virtual_size: int
    raw_size: int
    permissions: str  # e.g. "R-X", "RW-", "R--"
    entropy: float
    classification: Optional[str] = None  # set by the section-analysis rule


@dataclass
class ImportEntry:
    library: str
    functions: List[str] = field(default_factory=list)


@dataclass
class Capability:
    """A capability describes something the binary appears able to do,
    based on the APIs it imports. Capabilities are informational context
    -- they never contribute to severity by themselves."""

    category: str
    apis: List[str] = field(default_factory=list)


@dataclass
class Finding:
    """A finding is a specific, explained observation produced by the
    correlation engine. Unlike a bare capability, a finding always
    represents something the engine judged worth surfacing -- from purely
    informational context up to a strongly correlated behavioral pattern.
    """

    severity: str  # one of SEVERITY_LEVELS
    name: str
    description: str
    evidence: List[str] = field(default_factory=list)
    confidence: Optional[str] = None  # "Low" / "Medium" / "High", narrative only
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AnalysisResult:
    file_info: FileInfo
    hashes: Hashes
    headers: Dict[str, Any] = field(default_factory=dict)
    sections: List[SectionInfo] = field(default_factory=list)
    imports: List[ImportEntry] = field(default_factory=list)
    exports: List[str] = field(default_factory=list)
    strings: List[str] = field(default_factory=list)
    strings_truncated: bool = False
    capabilities: List[Capability] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    packaging_notes: List[str] = field(default_factory=list)
    overlay: Dict[str, Any] = field(default_factory=dict)
    assessment_note: str = ""
    warnings: List[str] = field(default_factory=list)

    def imported_function_names(self) -> set:
        """All imported function base names (ordinal suffixes stripped),
        as a flat set -- the input the correlation engine works from."""
        names = set()
        for entry in self.imports:
            for func in entry.functions:
                names.add(func.split("@")[0])
        return names

    def severity_summary(self) -> Dict[str, int]:
        counts = {level: 0 for level in SEVERITY_LEVELS}
        for f in self.findings:
            if f.severity in counts:
                counts[f.severity] += 1
        return counts

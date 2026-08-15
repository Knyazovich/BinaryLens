"""Analysis orchestrator: reads the file, detects format, dispatches to the
appropriate format module, and assembles the final AnalysisResult that is
shared by both the terminal and JSON output paths.
"""

from __future__ import annotations

import os

from binarylens.analysis.correlation import run_detection_engine
from binarylens.analysis.hashes import compute_hashes
from binarylens.analysis.strings import extract_strings
from binarylens.exceptions import (
    CorruptedBinaryError,
    EmptyFileError,
    FileNotFoundErrorBL,
    PermissionDeniedError,
    UnsupportedFormatError,
)
from binarylens.formats.elf import is_elf, parse_elf
from binarylens.formats.pe import is_pe, parse_pe
from binarylens.models import AnalysisResult


def read_target_file(filepath: str) -> bytes:
    if not os.path.exists(filepath):
        raise FileNotFoundErrorBL(f"File not found: {filepath}")
    if os.path.isdir(filepath):
        raise FileNotFoundErrorBL(f"Path is a directory, not a file: {filepath}")

    try:
        with open(filepath, "rb") as f:
            data = f.read()
    except PermissionError as exc:
        raise PermissionDeniedError(f"Permission denied reading: {filepath}") from exc
    except OSError as exc:
        raise FileNotFoundErrorBL(f"Could not read file: {filepath} ({exc})") from exc

    if len(data) == 0:
        raise EmptyFileError(f"File is empty: {filepath}")

    return data


def detect_format(data: bytes) -> str:
    if is_pe(data):
        return "PE"
    if is_elf(data):
        return "ELF"
    return "UNKNOWN"


def analyze_file(
    filepath: str,
    extract_string_data: bool = True,
    string_min_length: int = 4,
    string_max_count: int = 500,
) -> AnalysisResult:
    """Run the full static analysis pipeline on a single file and return
    a populated AnalysisResult. Raises a BinaryLensError subclass on any
    problem reading or parsing the file."""
    data = read_target_file(filepath)
    fmt = detect_format(data)

    if fmt == "UNKNOWN":
        raise UnsupportedFormatError(
            "Unsupported or unrecognized binary format. "
            "BinaryLens currently supports PE (Windows) and ELF binaries."
        )

    if fmt == "PE":
        file_info, headers, sections, imports, exports = parse_pe(filepath, data)
    else:
        file_info, headers, sections, imports, exports = parse_elf(filepath, data)

    hashes = compute_hashes(filepath)

    result = AnalysisResult(
        file_info=file_info,
        hashes=hashes,
        headers=headers,
        sections=sections,
        imports=imports,
        exports=exports,
    )

    # Strings are always scanned internally (bounded by string_max_count /
    # the strings module's max-scan-bytes cap) because the detection
    # engine's installer recognition (NSIS/Inno Setup/WiX/etc.) relies on
    # embedded strings regardless of whether the user asked to see the
    # string list itself. `extract_string_data` only controls whether the
    # (possibly large) string list is *retained* on the result for
    # display/JSON output.
    strings, truncated = extract_strings(
        data, min_length=string_min_length, max_strings=string_max_count
    )
    result.strings_truncated = truncated
    result.strings = strings

    run_detection_engine(result)

    if not extract_string_data:
        result.strings = []

    return result

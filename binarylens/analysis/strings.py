"""Static ASCII/Unicode string extraction.

This module never accesses, resolves, or connects to anything found
inside the analyzed file. It performs a purely static byte-level scan.
"""

from __future__ import annotations

import re
from typing import List

_ASCII_RE = re.compile(rb"[\x20-\x7e]{%d,}" % 4)
# UTF-16LE "wide" strings: printable ASCII byte followed by a null byte.
_WIDE_RE = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % 4)

DEFAULT_MIN_LENGTH = 4
DEFAULT_MAX_STRINGS = 500
# Hard safety ceiling on how many bytes we scan, to keep huge binaries
# from flooding the terminal or taking excessive time.
DEFAULT_MAX_SCAN_BYTES = 64 * 1024 * 1024  # 64 MB


def extract_strings(
    data: bytes,
    min_length: int = DEFAULT_MIN_LENGTH,
    max_strings: int = DEFAULT_MAX_STRINGS,
    max_scan_bytes: int = DEFAULT_MAX_SCAN_BYTES,
) -> tuple:
    """Extract printable ASCII and UTF-16LE strings from raw bytes.

    Returns a tuple of (strings, truncated) where `truncated` indicates
    whether the result was cut short by max_strings or max_scan_bytes.
    """
    scan_data = data[:max_scan_bytes]
    truncated = len(data) > max_scan_bytes

    results: List[str] = []
    seen = set()

    ascii_pattern = re.compile(rb"[\x20-\x7e]{%d,}" % min_length)
    wide_pattern = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % min_length)

    for match in ascii_pattern.finditer(scan_data):
        s = match.group().decode("ascii", errors="ignore")
        if s not in seen:
            seen.add(s)
            results.append(s)
        if len(results) >= max_strings:
            truncated = True
            return results, truncated

    for match in wide_pattern.finditer(scan_data):
        raw = match.group()
        try:
            s = raw.decode("utf-16-le", errors="ignore")
        except Exception:
            continue
        s = s.strip()
        if s and s not in seen:
            seen.add(s)
            results.append(s)
        if len(results) >= max_strings:
            truncated = True
            break

    return results, truncated

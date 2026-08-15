"""Filesystem helpers: path normalization and drag-and-drop cleanup.

Terminals mangle dropped paths in different ways:

* Windows cmd.exe / PowerShell wraps the whole path in double quotes:
    "C:\\Users\\User\\Desktop\\program.exe"
* macOS Terminal / iTerm2 backslash-escapes spaces and special chars:
    /Users/user/Desktop/my program.exe (with a backslash before the space)
* Some shells wrap the path in single quotes:
    'C:/Users/User/Desktop/program.exe'

clean_dropped_path() normalizes all of these into a plain path string.
"""

from __future__ import annotations

import os
import re


def clean_dropped_path(raw: str) -> str:
    """Normalize a raw path string that may have come from drag-and-drop."""
    text = raw.strip()

    if not text:
        return text

    # Strip a matching pair of surrounding quotes (single or double).
    if len(text) >= 2 and text[0] == text[-1] and text[0] in ("'", '"'):
        text = text[1:-1]

    # Undo shell backslash-escaping of spaces/special characters, but only
    # when this does not look like a Windows path (which uses backslashes
    # as path separators, e.g. C:\Users\...).
    looks_windows = bool(re.match(r"^[A-Za-z]:[\\/]", text)) or "\\\\" in raw
    if not looks_windows:
        text = re.sub(r"\\(.)", r"\1", text)

    text = text.strip()
    # Strip stray surrounding quotes again in case escaping revealed more.
    if len(text) >= 2 and text[0] == text[-1] and text[0] in ("'", '"'):
        text = text[1:-1]

    return text.strip()


def join_argv_path(tokens: list) -> str:
    """Rejoin argv tokens that were split on unescaped spaces in a
    drag-and-dropped path (happens on some Unix shells when the path
    wasn't quoted at all). Only used as a fallback."""
    return " ".join(tokens)


def human_readable_size(num_bytes: int) -> str:
    """Format a byte count as a human-readable size string."""
    size = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024.0 or unit == "TB":
            if unit == "B":
                return f"{int(size)} {unit}"
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} TB"


def resolve_existing_path(raw: str) -> str:
    """Clean a raw (possibly drag-and-dropped) path and return the
    absolute path, without checking existence (callers check that)."""
    cleaned = clean_dropped_path(raw)
    cleaned = os.path.expanduser(cleaned)
    return os.path.abspath(cleaned)

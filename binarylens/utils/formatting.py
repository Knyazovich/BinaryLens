"""Small formatting helpers shared by the terminal and JSON output modules."""

from __future__ import annotations


def format_hex(value: int, width: int = 8) -> str:
    """Format an integer as a zero-padded hex string like 0x140001000."""
    return f"0x{value:0{width}X}"


def permissions_string(readable: bool, writable: bool, executable: bool) -> str:
    r = "R" if readable else "-"
    w = "W" if writable else "-"
    x = "X" if executable else "-"
    return f"{r}{w}{x}"


def truncate(text: str, max_len: int) -> str:
    if len(text) <= max_len:
        return text
    return text[: max_len - 3] + "..."

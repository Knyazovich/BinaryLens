import os
import tempfile

import pytest

pytest.importorskip("lief", reason="lief is required for ELF analysis tests")

from binarylens.exceptions import CorruptedBinaryError
from binarylens.formats.elf import is_elf, parse_elf
from tests.fixtures import build_corrupted_elf, build_minimal_elf64


def _write_temp(data: bytes) -> str:
    fd, path = tempfile.mkstemp(suffix=".elf")
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    return path


def test_is_elf_detects_magic():
    assert is_elf(b"\x7fELF") is True
    assert is_elf(b"MZ\x00\x00") is False
    assert is_elf(b"") is False


def test_parse_elf_basic_fields():
    data = build_minimal_elf64()
    path = _write_temp(data)
    try:
        file_info, headers, sections, imports, exports = parse_elf(path, data)
        assert file_info.format == "ELF"
        assert file_info.architecture == "x86-64"
        assert file_info.size == len(data)
        section_names = [s.name for s in sections]
        assert ".text" in section_names
    finally:
        os.unlink(path)


def test_parse_corrupted_elf_raises():
    data = build_corrupted_elf()
    path = _write_temp(data)
    try:
        with pytest.raises(CorruptedBinaryError):
            parse_elf(path, data)
    finally:
        os.unlink(path)

import os
import tempfile

import pytest

pytest.importorskip("pefile", reason="pefile is required for PE analysis tests")

from binarylens.exceptions import CorruptedBinaryError
from binarylens.formats.pe import is_pe, parse_pe
from tests.fixtures import build_corrupted_pe, build_minimal_pe32


def _write_temp(data: bytes) -> str:
    fd, path = tempfile.mkstemp(suffix=".exe")
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    return path


def test_is_pe_detects_mz_signature():
    assert is_pe(b"MZ\x00\x00") is True
    assert is_pe(b"\x7fELF") is False
    assert is_pe(b"") is False


def test_parse_pe_basic_fields():
    data = build_minimal_pe32()
    path = _write_temp(data)
    try:
        file_info, headers, sections, imports, exports = parse_pe(path, data)
        assert file_info.format == "PE"
        assert file_info.architecture == "x86"
        assert file_info.size == len(data)
        assert len(sections) == 1
        assert sections[0].name == ".text"
        assert sections[0].permissions == "R-X"
        assert imports == []
        assert exports == []
    finally:
        os.unlink(path)


def test_parse_pe_section_entropy_low_for_nop_sled():
    data = build_minimal_pe32(section_data=bytes([0x90]) * 512)
    path = _write_temp(data)
    try:
        _, _, sections, _, _ = parse_pe(path, data)
        assert sections[0].entropy < 1.0
    finally:
        os.unlink(path)


def test_parse_pe_section_entropy_high_for_random_data():
    random_data = os.urandom(1024)
    data = build_minimal_pe32(section_data=random_data)
    path = _write_temp(data)
    try:
        _, _, sections, _, _ = parse_pe(path, data)
        assert sections[0].entropy > 7.0
    finally:
        os.unlink(path)


def test_parse_corrupted_pe_raises():
    data = build_corrupted_pe()
    path = _write_temp(data)
    try:
        with pytest.raises(CorruptedBinaryError):
            parse_pe(path, data)
    finally:
        os.unlink(path)


def test_parse_pe_writable_executable_permissions():
    from tests.fixtures import IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE

    data = build_minimal_pe32(
        section_characteristics=IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE
    )
    path = _write_temp(data)
    try:
        _, _, sections, _, _ = parse_pe(path, data)
        assert sections[0].permissions == "RWX"
    finally:
        os.unlink(path)

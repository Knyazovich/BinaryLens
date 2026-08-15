import os
import tempfile

import pytest

pytest.importorskip("pefile")

from binarylens.analyzer import analyze_file, detect_format
from binarylens.exceptions import (
    EmptyFileError,
    FileNotFoundErrorBL,
    UnsupportedFormatError,
)
from tests.fixtures import build_minimal_pe32


def _write_temp(data: bytes, suffix=".exe") -> str:
    fd, path = tempfile.mkstemp(suffix=suffix)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    return path


def test_detect_format_pe():
    assert detect_format(build_minimal_pe32()) == "PE"


def test_detect_format_unknown():
    assert detect_format(b"garbage data not a binary") == "UNKNOWN"


def test_analyze_file_not_found():
    with pytest.raises(FileNotFoundErrorBL):
        analyze_file("/nonexistent/path/to/file.exe")


def test_analyze_empty_file():
    fd, path = tempfile.mkstemp()
    os.close(fd)
    try:
        with pytest.raises(EmptyFileError):
            analyze_file(path)
    finally:
        os.unlink(path)


def test_analyze_unsupported_format():
    path = _write_temp(b"this is just plain text, not a binary at all")
    try:
        with pytest.raises(UnsupportedFormatError):
            analyze_file(path)
    finally:
        os.unlink(path)


def test_analyze_pe_end_to_end():
    data = build_minimal_pe32()
    path = _write_temp(data)
    try:
        result = analyze_file(path, extract_string_data=True)
        assert result.file_info.format == "PE"
        assert result.hashes.sha256
        assert len(result.sections) == 1
        assert isinstance(result.findings, list)
        assert isinstance(result.capabilities, list)
    finally:
        os.unlink(path)


def test_analyze_pe_with_paths_containing_spaces():
    data = build_minimal_pe32()
    tmpdir = tempfile.mkdtemp()
    path = os.path.join(tmpdir, "my program with spaces.exe")
    with open(path, "wb") as f:
        f.write(data)
    try:
        result = analyze_file(path)
        assert result.file_info.filename == "my program with spaces.exe"
    finally:
        os.unlink(path)
        os.rmdir(tmpdir)

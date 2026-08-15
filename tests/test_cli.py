import os
import tempfile

import pytest

pytest.importorskip("pefile")

from binarylens.cli import run
from tests.fixtures import build_corrupted_pe, build_minimal_pe32


def _write_temp(data: bytes, suffix=".exe") -> str:
    fd, path = tempfile.mkstemp(suffix=suffix)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    return path


def test_cli_analyzes_valid_pe(capsys):
    path = _write_temp(build_minimal_pe32())
    try:
        exit_code = run([path])
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "BinaryLens" in captured.out
    finally:
        os.unlink(path)


def test_cli_file_not_found(capsys):
    exit_code = run(["/definitely/not/a/real/path.exe"])
    assert exit_code == 1
    captured = capsys.readouterr()
    assert "not found" in captured.out.lower() or "not found" in captured.err.lower()


def test_cli_corrupted_pe_no_traceback(capsys):
    path = _write_temp(build_corrupted_pe())
    try:
        exit_code = run([path])
        assert exit_code == 1
        captured = capsys.readouterr()
        combined = captured.out + captured.err
        assert "Traceback" not in combined
    finally:
        os.unlink(path)


def test_cli_unsupported_format_no_traceback(capsys):
    path = _write_temp(b"plain text file, not a binary")
    try:
        exit_code = run([path])
        assert exit_code == 1
        captured = capsys.readouterr()
        combined = captured.out + captured.err
        assert "Traceback" not in combined
    finally:
        os.unlink(path)


def test_cli_json_flag_writes_file():
    path = _write_temp(build_minimal_pe32())
    out_fd, out_path = tempfile.mkstemp(suffix=".json")
    os.close(out_fd)
    os.unlink(out_path)  # ensure it doesn't exist yet
    try:
        exit_code = run([path, "--json", out_path])
        assert exit_code == 0
        assert os.path.exists(out_path)
    finally:
        os.unlink(path)
        if os.path.exists(out_path):
            os.unlink(out_path)


def test_cli_path_with_spaces():
    tmpdir = tempfile.mkdtemp()
    path = os.path.join(tmpdir, "program with spaces.exe")
    with open(path, "wb") as f:
        f.write(build_minimal_pe32())
    try:
        exit_code = run([path])
        assert exit_code == 0
    finally:
        os.unlink(path)
        os.rmdir(tmpdir)


def test_resolve_target_path_joins_split_tokens():
    from binarylens.cli import resolve_target_path

    tmpdir = tempfile.mkdtemp()
    path = os.path.join(tmpdir, "split path.exe")
    with open(path, "wb") as f:
        f.write(build_minimal_pe32())
    try:
        # Simulate an unquoted drag-and-dropped path split by the shell
        # into separate argv tokens on the space.
        base, filename = os.path.split(path)
        parts = filename.split(" ")
        tokens = [os.path.join(base, parts[0])] + parts[1:]
        resolved = resolve_target_path(tokens)
        assert resolved == path
    finally:
        os.unlink(path)
        os.rmdir(tmpdir)


def test_cli_sections_flag_only(capsys):
    path = _write_temp(build_minimal_pe32())
    try:
        exit_code = run([path, "--sections"])
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "Sections" in captured.out
    finally:
        os.unlink(path)

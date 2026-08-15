import json
import os
import tempfile

import pytest

pytest.importorskip("pefile")

from binarylens.analyzer import analyze_file
from binarylens.output.json_report import build_report_dict, write_json_report
from tests.fixtures import build_minimal_pe32


def _write_temp(data: bytes) -> str:
    fd, path = tempfile.mkstemp(suffix=".exe")
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    return path


def test_json_report_structure():
    data = build_minimal_pe32()
    path = _write_temp(data)
    try:
        result = analyze_file(path, extract_string_data=True)
        report = build_report_dict(result)
        assert "file" in report
        assert "hashes" in report
        assert "headers" in report
        assert "sections" in report
        assert "imports" in report
        assert "exports" in report
        assert "strings" in report
        assert "packaging" in report
        assert "overlay" in report
        assert "analysis" in report
        assert "capabilities" in report["analysis"]
        assert "findings" in report["analysis"]
        assert "severity_summary" in report["analysis"]
        assert "assessment_note" in report["analysis"]
        assert sum(report["analysis"]["severity_summary"].values()) == len(report["analysis"]["findings"])
    finally:
        os.unlink(path)


def test_json_report_no_fake_placeholder_values():
    data = build_minimal_pe32()
    path = _write_temp(data)
    try:
        result = analyze_file(path)
        report = build_report_dict(result)
        # No imports/exports were defined in this fixture -- must be
        # genuinely empty, not filled with placeholder entries.
        assert report["imports"] == {}
        assert report["exports"] == []
    finally:
        os.unlink(path)


def test_write_json_report_to_file():
    data = build_minimal_pe32()
    path = _write_temp(data)
    out_fd, out_path = tempfile.mkstemp(suffix=".json")
    os.close(out_fd)
    try:
        result = analyze_file(path)
        write_json_report(result, out_path)
        with open(out_path, "r", encoding="utf-8") as f:
            loaded = json.load(f)
        assert loaded["file"]["format"] == "PE"
        assert loaded["hashes"]["sha256"] == result.hashes.sha256
    finally:
        os.unlink(path)
        os.unlink(out_path)

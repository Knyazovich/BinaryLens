from binarylens.analysis.indicators import run_all_checks
from binarylens.models import AnalysisResult, FileInfo, Hashes, ImportEntry, SectionInfo


def _base_result(**overrides) -> AnalysisResult:
    file_info = FileInfo(
        filename="test.exe",
        filepath="/tmp/test.exe",
        size=1024,
        format="PE",
        architecture="x86-64",
        entry_point="0x00401000",
        image_base="0x00400000",
    )
    hashes = Hashes(md5="a" * 32, sha1="b" * 40, sha256="c" * 64)
    result = AnalysisResult(file_info=file_info, hashes=hashes)
    for key, value in overrides.items():
        setattr(result, key, value)
    return result


def test_no_indicators_for_clean_binary():
    result = _base_result(
        sections=[SectionInfo(name=".text", virtual_address=0x1000, virtual_size=512,
                               raw_size=512, permissions="R-X", entropy=4.0)],
        imports=[ImportEntry(library="kernel32.dll", functions=["CreateFileW"])],
        headers={"characteristics_flags": ["IMAGE_FILE_EXECUTABLE_IMAGE"], "compile_timestamp_raw": 123456},
    )
    indicators = run_all_checks(result)
    names = [i.name for i in indicators]
    assert "High entropy section detected" not in names
    assert "Executable + writable section" not in names


def test_high_entropy_indicator():
    result = _base_result(
        sections=[SectionInfo(name=".packed", virtual_address=0x1000, virtual_size=1024,
                               raw_size=1024, permissions="R-X", entropy=7.95)],
        headers={"characteristics_flags": ["IMAGE_FILE_EXECUTABLE_IMAGE"], "compile_timestamp_raw": 1},
    )
    indicators = run_all_checks(result)
    names = [i.name for i in indicators]
    assert "High entropy section detected" in names


def test_writable_executable_section_indicator():
    result = _base_result(
        sections=[SectionInfo(name=".text", virtual_address=0x1000, virtual_size=512,
                               raw_size=512, permissions="RWX", entropy=3.0)],
        headers={"characteristics_flags": ["IMAGE_FILE_EXECUTABLE_IMAGE"], "compile_timestamp_raw": 1},
    )
    indicators = run_all_checks(result)
    names = [i.name for i in indicators]
    assert "Executable + writable section" in names


def test_dynamic_resolution_indicator():
    result = _base_result(
        sections=[SectionInfo(name=".text", virtual_address=0x1000, virtual_size=512,
                               raw_size=512, permissions="R-X", entropy=3.0)],
        imports=[ImportEntry(library="kernel32.dll", functions=["GetProcAddress", "LoadLibraryA"])],
        headers={"characteristics_flags": ["IMAGE_FILE_EXECUTABLE_IMAGE"], "compile_timestamp_raw": 1},
    )
    indicators = run_all_checks(result)
    names = [i.name for i in indicators]
    assert "Dynamic API resolution" in names


def test_process_injection_indicator():
    result = _base_result(
        sections=[SectionInfo(name=".text", virtual_address=0x1000, virtual_size=512,
                               raw_size=512, permissions="R-X", entropy=3.0)],
        imports=[ImportEntry(library="kernel32.dll", functions=["WriteProcessMemory", "OpenProcess"])],
        headers={"characteristics_flags": ["IMAGE_FILE_EXECUTABLE_IMAGE"], "compile_timestamp_raw": 1},
    )
    indicators = run_all_checks(result)
    names = [i.name for i in indicators]
    assert "Process interaction / injection APIs detected" in names


def test_unusual_section_name_indicator():
    result = _base_result(
        sections=[SectionInfo(name=".totallyweird", virtual_address=0x1000, virtual_size=512,
                               raw_size=512, permissions="R--", entropy=2.0)],
        headers={"characteristics_flags": ["IMAGE_FILE_EXECUTABLE_IMAGE"], "compile_timestamp_raw": 1},
    )
    indicators = run_all_checks(result)
    names = [i.name for i in indicators]
    assert "Unusual section name" in names


def test_missing_metadata_indicator_no_imports():
    result = _base_result(
        sections=[SectionInfo(name=".text", virtual_address=0x1000, virtual_size=512,
                               raw_size=512, permissions="R-X", entropy=3.0)],
        imports=[],
        headers={"characteristics_flags": ["IMAGE_FILE_EXECUTABLE_IMAGE"], "compile_timestamp_raw": 1},
    )
    indicators = run_all_checks(result)
    names = [i.name for i in indicators]
    assert "Missing expected metadata" in names


def test_overlay_data_indicator():
    result = _base_result(
        sections=[SectionInfo(name=".text", virtual_address=0x1000, virtual_size=512,
                               raw_size=512, permissions="R-X", entropy=3.0)],
        headers={
            "characteristics_flags": ["IMAGE_FILE_EXECUTABLE_IMAGE"],
            "compile_timestamp_raw": 1,
            "overlay_size": 4096,
        },
    )
    indicators = run_all_checks(result)
    names = [i.name for i in indicators]
    assert "Overlay data present" in names


def test_indicators_never_declare_verdict():
    """No indicator name or description should ever contain a definitive
    malware verdict -- indicators are observations, not conclusions."""
    result = _base_result(
        sections=[SectionInfo(name=".packed", virtual_address=0x1000, virtual_size=1024,
                               raw_size=1024, permissions="RWX", entropy=7.99)],
        imports=[ImportEntry(library="kernel32.dll",
                              functions=["GetProcAddress", "WriteProcessMemory", "WinExec"])],
        headers={"characteristics_flags": [], "compile_timestamp_raw": 0},
    )
    indicators = run_all_checks(result)
    forbidden_phrases = ["this is malware", "confirmed malicious", "is a virus"]
    for indicator in indicators:
        text = (indicator.name + " " + indicator.description).lower()
        for phrase in forbidden_phrases:
            assert phrase not in text

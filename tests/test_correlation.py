"""Tests for the correlation-based detection engine.

These tests are the direct regression coverage for the false-positive
problem this refactor addresses: a legitimate installer using ordinary
Windows APIs must not produce HIGH/MEDIUM findings, while genuinely
correlated, evidence-backed patterns still must be surfaced.
"""

from binarylens.analysis.correlation import run_detection_engine
from binarylens.models import AnalysisResult, FileInfo, Hashes, ImportEntry, SectionInfo


def _base_result(**overrides) -> AnalysisResult:
    file_info = FileInfo(
        filename="test.exe",
        filepath="/tmp/test.exe",
        size=2 * 1024 * 1024,
        format="PE",
        architecture="x86-64",
        entry_point="0x00401000",
        image_base="0x00400000",
    )
    hashes = Hashes(md5="a" * 32, sha1="b" * 40, sha256="c" * 64)
    result = AnalysisResult(
        file_info=file_info,
        hashes=hashes,
        headers={"characteristics_flags": ["IMAGE_FILE_EXECUTABLE_IMAGE"], "compile_timestamp_raw": 1700000000},
    )
    for key, value in overrides.items():
        setattr(result, key, value)
    return result


def _names(findings, severities=None):
    if severities:
        return [f.name for f in findings if f.severity in severities]
    return [f.name for f in findings]


# ---------------------------------------------------------------------------
# The core false-positive regression: a Python-installer-style binary
# ---------------------------------------------------------------------------

def test_installer_like_binary_produces_no_medium_or_high_findings():
    result = _base_result(
        sections=[
            SectionInfo(name=".text", virtual_address=0x1000, virtual_size=500_000,
                        raw_size=500_000, permissions="R-X", entropy=6.1),
            SectionInfo(name=".rdata", virtual_address=0x100000, virtual_size=100_000,
                        raw_size=100_000, permissions="R--", entropy=5.0),
            SectionInfo(name=".data", virtual_address=0x200000, virtual_size=20_000,
                        raw_size=20_000, permissions="RW-", entropy=3.0),
            SectionInfo(name=".wixburn", virtual_address=0x300000, virtual_size=108,
                        raw_size=512, permissions="R--", entropy=1.2),
        ],
        imports=[
            ImportEntry(library="kernel32.dll", functions=[
                "CreateProcessW", "OpenProcess", "VirtualAlloc", "VirtualProtect",
                "GetProcAddress", "LoadLibraryW", "CreateFileW", "WriteFile",
            ]),
            ImportEntry(library="advapi32.dll", functions=[
                "RegOpenKeyExW", "RegSetValueExW", "RegCreateKeyExW",
            ]),
        ],
        strings=["Windows Installer", "WixBurn manifest", "Setup.exe", "MSI package"],
    )
    result.headers["overlay_size"] = 1_500_000  # < file size, plausible bundled payload
    run_detection_engine(result)

    severe = [f for f in result.findings if f.severity in ("MEDIUM", "HIGH")]
    assert severe == [], f"Unexpected non-informational findings: {[f.name for f in severe]}"
    assert ".wixburn" not in " ".join(str(f.evidence) for f in result.findings if f.severity != "INFO")


def test_installer_wixburn_section_not_flagged_unusual():
    result = _base_result(
        sections=[
            SectionInfo(name=".text", virtual_address=0x1000, virtual_size=1000,
                        raw_size=1000, permissions="R-X", entropy=5.0),
            SectionInfo(name=".wixburn", virtual_address=0x2000, virtual_size=108,
                        raw_size=512, permissions="R--", entropy=1.0),
        ],
        imports=[],
    )
    run_detection_engine(result)
    names = _names(result.findings)
    assert not any("unusual" in n.lower() and "wixburn" in n.lower() for n in names)


def test_installer_context_softens_large_overlay_wording():
    result = _base_result(
        sections=[SectionInfo(name=".wixburn", virtual_address=0x1000, virtual_size=100,
                               raw_size=512, permissions="R--", entropy=1.0)],
        strings=["WiX Toolset"],
    )
    file_size = 10 * 1024 * 1024
    result.file_info.size = file_size
    result.headers["overlay_size"] = 8 * 1024 * 1024
    run_detection_engine(result)
    overlay_findings = [f for f in result.findings if "overlay" in f.name.lower()]
    assert overlay_findings
    assert all(f.severity == "INFO" for f in overlay_findings)
    assert any("installer" in f.description.lower() for f in overlay_findings)


# ---------------------------------------------------------------------------
# Process injection correlation
# ---------------------------------------------------------------------------

def test_single_openprocess_is_not_injection():
    result = _base_result(imports=[ImportEntry(library="kernel32.dll", functions=["OpenProcess"])])
    run_detection_engine(result)
    assert not any("injection" in f.name.lower() for f in result.findings)


def test_two_stage_injection_apis_not_enough_for_finding():
    result = _base_result(
        imports=[ImportEntry(library="kernel32.dll", functions=["OpenProcess", "VirtualAllocEx"])]
    )
    run_detection_engine(result)
    assert not any("injection" in f.name.lower() for f in result.findings)


def test_three_stage_injection_apis_produce_medium_finding():
    result = _base_result(
        imports=[ImportEntry(library="kernel32.dll", functions=[
            "OpenProcess", "VirtualAllocEx", "WriteProcessMemory",
        ])]
    )
    run_detection_engine(result)
    matches = [f for f in result.findings if "injection" in f.name.lower()]
    assert matches
    assert matches[0].severity == "MEDIUM"
    assert "possible" in matches[0].name.lower()


def test_full_injection_chain_produces_high_finding():
    result = _base_result(
        imports=[ImportEntry(library="kernel32.dll", functions=[
            "OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
        ])]
    )
    run_detection_engine(result)
    matches = [f for f in result.findings if "injection" in f.name.lower()]
    assert matches
    assert matches[0].severity == "HIGH"
    assert set(matches[0].evidence) == {
        "CreateRemoteThread", "OpenProcess", "VirtualAllocEx", "WriteProcessMemory",
    }


# ---------------------------------------------------------------------------
# Anti-debugging correlation
# ---------------------------------------------------------------------------

def test_timing_api_alone_is_not_anti_debug():
    result = _base_result(
        imports=[ImportEntry(library="kernel32.dll", functions=["QueryPerformanceCounter", "GetTickCount"])]
    )
    run_detection_engine(result)
    assert not any("debug" in f.name.lower() for f in result.findings)


def test_single_debugger_api_is_low_severity():
    result = _base_result(imports=[ImportEntry(library="kernel32.dll", functions=["IsDebuggerPresent"])])
    run_detection_engine(result)
    matches = [f for f in result.findings if "debugger detection" in f.name.lower()]
    assert matches
    assert matches[0].severity == "LOW"


def test_multiple_debugger_apis_are_medium_severity():
    result = _base_result(
        imports=[ImportEntry(library="kernel32.dll", functions=[
            "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
        ])]
    )
    run_detection_engine(result)
    matches = [f for f in result.findings if "anti-debugging indicators" in f.name.lower()]
    assert matches
    assert matches[0].severity == "MEDIUM"


# ---------------------------------------------------------------------------
# Capabilities are informational only
# ---------------------------------------------------------------------------

def test_capabilities_never_carry_severity_by_construction():
    """Capability objects have no severity field at all -- this test just
    documents/asserts that fact so a future change can't silently add one
    without a very deliberate decision."""
    from binarylens.models import Capability

    fields = {f for f in Capability.__dataclass_fields__}
    assert "severity" not in fields
    assert "category" in fields and "apis" in fields


def test_registry_apis_alone_produce_only_info():
    result = _base_result(
        imports=[ImportEntry(library="advapi32.dll", functions=["RegOpenKeyExW", "RegSetValueExW"])]
    )
    run_detection_engine(result)
    assert not any(f.severity in ("MEDIUM", "HIGH") for f in result.findings)
    assert any("registry" in f.name.lower() for f in result.findings)


def test_registry_plus_service_apis_produce_low_persistence_finding():
    result = _base_result(
        imports=[ImportEntry(library="advapi32.dll", functions=[
            "RegSetValueExW", "CreateServiceW", "StartServiceW",
        ])]
    )
    run_detection_engine(result)
    matches = [f for f in result.findings if "persistence" in f.name.lower()]
    assert matches
    assert matches[0].severity == "LOW"


# ---------------------------------------------------------------------------
# Entropy / packing correlation
# ---------------------------------------------------------------------------

def test_single_high_entropy_section_is_info_only():
    result = _base_result(
        sections=[SectionInfo(name=".rsrc", virtual_address=0x1000, virtual_size=2000,
                               raw_size=2000, permissions="R--", entropy=7.8)],
        imports=[ImportEntry(library="kernel32.dll", functions=["CreateFileW", "ReadFile", "WriteFile", "CloseHandle"])],
    )
    run_detection_engine(result)
    entropy_findings = [f for f in result.findings if "entropy" in f.name.lower()]
    assert entropy_findings
    assert entropy_findings[0].severity == "INFO"
    assert not any(f.severity in ("MEDIUM", "HIGH") and "pack" in f.name.lower() for f in result.findings)


def test_high_entropy_plus_small_imports_plus_packer_name_is_medium():
    result = _base_result(
        sections=[SectionInfo(name="upx1", virtual_address=0x1000, virtual_size=2000,
                               raw_size=2000, permissions="R-X", entropy=7.9)],
        imports=[ImportEntry(library="kernel32.dll", functions=["GetProcAddress"])],
    )
    run_detection_engine(result)
    matches = [f for f in result.findings if "packing" in f.name.lower()]
    assert matches
    assert matches[0].severity == "MEDIUM"


# ---------------------------------------------------------------------------
# Writable+executable sections still flagged (structural, not API-based)
# ---------------------------------------------------------------------------

def test_writable_executable_section_is_medium():
    result = _base_result(
        sections=[SectionInfo(name=".text", virtual_address=0x1000, virtual_size=1000,
                               raw_size=1000, permissions="RWX", entropy=3.0)],
    )
    run_detection_engine(result)
    matches = [f for f in result.findings if "executable/writable" in f.name.lower()]
    assert matches
    assert matches[0].severity == "MEDIUM"


# ---------------------------------------------------------------------------
# No verdicts, ever
# ---------------------------------------------------------------------------

def test_no_finding_ever_declares_a_verdict():
    result = _base_result(
        sections=[SectionInfo(name="upx0", virtual_address=0x1000, virtual_size=2000,
                               raw_size=2000, permissions="RWX", entropy=7.99)],
        imports=[ImportEntry(library="kernel32.dll", functions=[
            "OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
            "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
        ])],
    )
    run_detection_engine(result)
    forbidden = ["is malware", "confirmed malicious", "is a virus", "malware detected", "probability:"]
    for f in result.findings:
        text = (f.name + " " + f.description).lower()
        for phrase in forbidden:
            assert phrase not in text

    assert result.assessment_note
    assert "%" not in result.assessment_note
    assert "malware" not in result.assessment_note.lower()


def test_severity_summary_counts_match_findings():
    result = _base_result(
        imports=[ImportEntry(library="kernel32.dll", functions=[
            "OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
        ])],
    )
    run_detection_engine(result)
    summary = result.severity_summary()
    assert sum(summary.values()) == len(result.findings)
    assert summary["HIGH"] == len([f for f in result.findings if f.severity == "HIGH"])

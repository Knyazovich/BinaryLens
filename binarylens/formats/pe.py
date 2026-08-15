"""PE (Portable Executable) format parsing, built on top of `pefile`.

This module only ever reads the target file. It never maps the file for
execution, never resolves imports against real DLLs, and never invokes
any code contained in the binary.
"""

from __future__ import annotations

import datetime
from typing import List

from binarylens.analysis.entropy import shannon_entropy
from binarylens.exceptions import CorruptedBinaryError
from binarylens.models import FileInfo, ImportEntry, SectionInfo
from binarylens.utils.formatting import format_hex, permissions_string

try:
    import pefile
except ImportError:  # pragma: no cover - checked explicitly at call sites
    pefile = None

# pefile section characteristic flags we care about.
_IMAGE_SCN_MEM_EXECUTE = 0x20000000
_IMAGE_SCN_MEM_READ = 0x40000000
_IMAGE_SCN_MEM_WRITE = 0x80000000

_MACHINE_NAMES = {
    0x014C: "x86",
    0x0200: "IA64",
    0x8664: "x86-64",
    0x01C0: "ARM",
    0x01C4: "ARMv7 (Thumb-2)",
    0xAA64: "ARM64",
}

_SUBSYSTEM_NAMES = {
    1: "Native",
    2: "Windows GUI",
    3: "Windows Console",
    5: "OS/2 Console",
    7: "POSIX Console",
    9: "Windows CE GUI",
    10: "EFI Application",
    11: "EFI Boot Service Driver",
    12: "EFI Runtime Driver",
    13: "EFI ROM",
    14: "Xbox",
    16: "Windows Boot Application",
}

_CHARACTERISTICS_FLAGS = {
    0x0001: "IMAGE_FILE_RELOCS_STRIPPED",
    0x0002: "IMAGE_FILE_EXECUTABLE_IMAGE",
    0x0004: "IMAGE_FILE_LINE_NUMS_STRIPPED",
    0x0008: "IMAGE_FILE_LOCAL_SYMS_STRIPPED",
    0x0010: "IMAGE_FILE_AGGRESIVE_WS_TRIM",
    0x0020: "IMAGE_FILE_LARGE_ADDRESS_AWARE",
    0x0080: "IMAGE_FILE_BYTES_REVERSED_LO",
    0x0100: "IMAGE_FILE_32BIT_MACHINE",
    0x0200: "IMAGE_FILE_DEBUG_STRIPPED",
    0x0400: "IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP",
    0x0800: "IMAGE_FILE_NET_RUN_FROM_SWAP",
    0x1000: "IMAGE_FILE_SYSTEM",
    0x2000: "IMAGE_FILE_DLL",
    0x4000: "IMAGE_FILE_UP_SYSTEM_ONLY",
    0x8000: "IMAGE_FILE_BYTES_REVERSED_HI",
}


def is_pe(data: bytes) -> bool:
    return len(data) >= 2 and data[:2] == b"MZ"


def _decode_characteristics(value: int) -> List[str]:
    return [name for bit, name in _CHARACTERISTICS_FLAGS.items() if value & bit]


def parse_pe(filepath: str, data: bytes):
    """Parse a PE file and return (FileInfo, headers_dict, sections, imports, exports)."""
    if pefile is None:
        raise RuntimeError(
            "The 'pefile' package is required for PE analysis but is not installed. "
            "Install project dependencies with: pip install -r requirements.txt"
        )

    try:
        pe = pefile.PE(data=data, fast_load=False)
    except pefile.PEFormatError as exc:
        raise CorruptedBinaryError(f"Invalid or corrupted PE file: {exc}") from exc
    except Exception as exc:  # noqa: BLE001 - surface as corrupted binary
        raise CorruptedBinaryError(f"Failed to parse PE file: {exc}") from exc

    try:
        file_info, headers = _extract_file_info(filepath, data, pe)
        sections = _extract_sections(pe)
        imports = _extract_imports(pe)
        exports = _extract_exports(pe)
        headers["overlay_size"] = _overlay_size(pe, data)
    finally:
        pe.close()

    return file_info, headers, sections, imports, exports


def _extract_file_info(filepath: str, data: bytes, pe) -> tuple:
    machine = pe.FILE_HEADER.Machine
    architecture = _MACHINE_NAMES.get(machine, f"Unknown (0x{machine:04X})")

    is_dll = bool(pe.FILE_HEADER.Characteristics & 0x2000)
    entry_point = format_hex(
        pe.OPTIONAL_HEADER.ImageBase + pe.OPTIONAL_HEADER.AddressOfEntryPoint, 8
    )
    image_base = format_hex(pe.OPTIONAL_HEADER.ImageBase, 8)

    timestamp_raw = pe.FILE_HEADER.TimeDateStamp
    compile_ts = None
    if timestamp_raw:
        try:
            compile_ts = datetime.datetime.utcfromtimestamp(timestamp_raw).strftime(
                "%Y-%m-%d %H:%M:%S UTC"
            )
        except (OverflowError, OSError, ValueError):
            compile_ts = None

    subsystem = _SUBSYSTEM_NAMES.get(pe.OPTIONAL_HEADER.Subsystem, str(pe.OPTIONAL_HEADER.Subsystem))

    file_info = FileInfo(
        filename=filepath.rsplit("/", 1)[-1].rsplit("\\", 1)[-1],
        filepath=filepath,
        size=len(data),
        format="PE",
        architecture=architecture,
        entry_point=entry_point,
        image_base=image_base,
        compile_timestamp=compile_ts,
        subsystem=subsystem,
    )

    characteristics = pe.FILE_HEADER.Characteristics
    headers = {
        "dos_signature": "MZ",
        "pe_signature": "PE\\0\\0",
        "machine": architecture,
        "machine_raw": hex(machine),
        "number_of_sections": pe.FILE_HEADER.NumberOfSections,
        "characteristics_raw": hex(characteristics),
        "characteristics_flags": _decode_characteristics(characteristics),
        "is_dll": is_dll,
        "subsystem": subsystem,
        "entry_point": entry_point,
        "image_base": image_base,
        "section_alignment": hex(pe.OPTIONAL_HEADER.SectionAlignment),
        "file_alignment": hex(pe.OPTIONAL_HEADER.FileAlignment),
        "compile_timestamp": compile_ts,
        "compile_timestamp_raw": timestamp_raw,
        "linker_version": f"{pe.OPTIONAL_HEADER.MajorLinkerVersion}.{pe.OPTIONAL_HEADER.MinorLinkerVersion}",
        "pe_type": "PE32+" if pe.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS else "PE32",
    }

    return file_info, headers


def _extract_sections(pe) -> List[SectionInfo]:
    sections = []
    for section in pe.sections:
        name = section.Name.rstrip(b"\x00").decode("ascii", errors="replace")
        raw_data = section.get_data()
        entropy = shannon_entropy(raw_data) if raw_data else 0.0

        readable = bool(section.Characteristics & _IMAGE_SCN_MEM_READ)
        writable = bool(section.Characteristics & _IMAGE_SCN_MEM_WRITE)
        executable = bool(section.Characteristics & _IMAGE_SCN_MEM_EXECUTE)

        sections.append(
            SectionInfo(
                name=name,
                virtual_address=section.VirtualAddress,
                virtual_size=section.Misc_VirtualSize,
                raw_size=section.SizeOfRawData,
                permissions=permissions_string(readable, writable, executable),
                entropy=round(entropy, 4),
            )
        )
    return sections


def _extract_imports(pe) -> List[ImportEntry]:
    imports = []
    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        return imports

    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll_name = entry.dll.decode("ascii", errors="replace") if entry.dll else "UNKNOWN"
        functions = []
        for imp in entry.imports:
            if imp.name:
                functions.append(imp.name.decode("ascii", errors="replace"))
            elif imp.ordinal is not None:
                functions.append(f"Ordinal_{imp.ordinal}")
        imports.append(ImportEntry(library=dll_name, functions=functions))

    return imports


def _extract_exports(pe) -> List[str]:
    exports = []
    if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        return exports

    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if exp.name:
            exports.append(exp.name.decode("ascii", errors="replace"))
        else:
            exports.append(f"Ordinal_{exp.ordinal}")

    return exports


def _overlay_size(pe, data: bytes) -> int:
    try:
        offset = pe.get_overlay_data_start_offset()
    except Exception:  # noqa: BLE001
        offset = None
    if offset is None:
        return 0
    return max(0, len(data) - offset)

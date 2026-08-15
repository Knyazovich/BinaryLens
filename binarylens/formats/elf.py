"""ELF format parsing, built on top of `LIEF`.

This module only reads and statically parses the target file. It never
loads, maps for execution, or runs any code contained in the binary.
"""

from __future__ import annotations

from typing import List

from binarylens.analysis.entropy import shannon_entropy
from binarylens.exceptions import CorruptedBinaryError
from binarylens.models import FileInfo, ImportEntry, SectionInfo
from binarylens.utils.formatting import format_hex, permissions_string

try:
    import lief
except ImportError:  # pragma: no cover
    lief = None

_ARCH_NAMES = {
    "EM_X86_64": "x86-64",
    "EM_386": "x86",
    "EM_ARM": "ARM",
    "EM_AARCH64": "ARM64",
    "EM_RISCV": "RISC-V",
    "EM_MIPS": "MIPS",
    "EM_PPC64": "PowerPC64",
    "EM_PPC": "PowerPC",
}


def is_elf(data: bytes) -> bool:
    return len(data) >= 4 and data[:4] == b"\x7fELF"


def parse_elf(filepath: str, data: bytes):
    """Parse an ELF file and return (FileInfo, headers_dict, sections, imports, exports)."""
    if lief is None:
        raise RuntimeError(
            "The 'lief' package is required for ELF analysis but is not installed. "
            "Install project dependencies with: pip install -r requirements.txt"
        )

    try:
        binary = lief.parse(filepath)
    except Exception as exc:  # noqa: BLE001
        raise CorruptedBinaryError(f"Failed to parse ELF file: {exc}") from exc

    if binary is None:
        raise CorruptedBinaryError("Invalid or corrupted ELF file.")
    try:
        is_elf_binary = isinstance(binary, lief.ELF.Binary)
    except Exception:  # noqa: BLE001
        is_elf_binary = True  # older/newer LIEF versions may not expose this the same way
    if not is_elf_binary:
        raise CorruptedBinaryError("Invalid or corrupted ELF file.")

    file_info, headers = _extract_file_info(filepath, data, binary)
    sections = _extract_sections(data, binary)
    imports = _extract_imports(binary)
    exports = _extract_exports(binary)
    headers["overlay_size"] = _overlay_size(data, binary)

    return file_info, headers, sections, imports, exports


def _extract_file_info(filepath: str, data: bytes, binary) -> tuple:
    header = binary.header
    machine_name = str(header.machine_type).split(".")[-1]
    architecture = _ARCH_NAMES.get(machine_name, machine_name)

    ei_class = str(header.identity_class).split(".")[-1]
    is_64 = "64" in ei_class

    entry_point = format_hex(header.entrypoint, 16 if is_64 else 8)

    obj_type = str(header.file_type).split(".")[-1]

    file_info = FileInfo(
        filename=filepath.rsplit("/", 1)[-1].rsplit("\\", 1)[-1],
        filepath=filepath,
        size=len(data),
        format="ELF",
        architecture=architecture,
        entry_point=entry_point,
        image_base=None,
        compile_timestamp=None,
        subsystem=obj_type,
    )

    headers = {
        "elf_class": ei_class,
        "machine": architecture,
        "object_type": obj_type,
        "entry_point": entry_point,
        "number_of_sections": len(binary.sections),
        "number_of_segments": len(binary.segments),
        "characteristics_flags": [],
        "is_pie": binary.is_pie if hasattr(binary, "is_pie") else None,
        "has_nx": binary.has_nx if hasattr(binary, "has_nx") else None,
    }

    return file_info, headers


def _extract_sections(data: bytes, binary) -> List[SectionInfo]:
    sections = []
    for section in binary.sections:
        try:
            content = bytes(bytearray(section.content))
        except Exception:  # noqa: BLE001
            content = b""
        entropy = shannon_entropy(content) if content else 0.0

        flags = str(section.flags_list)
        readable = True  # ELF sections loaded into memory are generally readable
        writable = "SHF_WRITE" in flags or any(
            "WRITE" in str(f) for f in getattr(section, "flags_list", [])
        )
        executable = "SHF_EXECINSTR" in flags or any(
            "EXECINSTR" in str(f) for f in getattr(section, "flags_list", [])
        )

        sections.append(
            SectionInfo(
                name=section.name or "(unnamed)",
                virtual_address=int(section.virtual_address),
                virtual_size=int(section.size),
                raw_size=len(content),
                permissions=permissions_string(readable, writable, executable),
                entropy=round(entropy, 4),
            )
        )
    return sections


def _extract_imports(binary) -> List[ImportEntry]:
    """Group imported dynamic symbols by their originating library where
    known; ELF doesn't map symbols to libraries as directly as PE does,
    so unresolved symbols are grouped under a synthetic 'dynamic symbols'
    bucket."""
    imports = []

    try:
        libraries = list(binary.libraries)
    except Exception:  # noqa: BLE001
        libraries = []

    functions = []
    try:
        for symbol in binary.imported_symbols:
            if symbol.name:
                functions.append(symbol.name)
    except Exception:  # noqa: BLE001
        pass

    if functions:
        imports.append(ImportEntry(library="(dynamic symbols)", functions=sorted(set(functions))))

    for lib in libraries:
        imports.append(ImportEntry(library=lib, functions=[]))

    return imports


def _extract_exports(binary) -> List[str]:
    exports = []
    try:
        for symbol in binary.exported_symbols:
            if symbol.name:
                exports.append(symbol.name)
    except Exception:  # noqa: BLE001
        pass
    return sorted(set(exports))


def _overlay_size(data: bytes, binary) -> int:
    try:
        last_offset = 0
        for section in binary.sections:
            end = int(section.offset) + int(section.size)
            if end > last_offset:
                last_offset = end
        for segment in binary.segments:
            end = int(segment.file_offset) + int(segment.physical_size)
            if end > last_offset:
                last_offset = end
        return max(0, len(data) - last_offset)
    except Exception:  # noqa: BLE001
        return 0

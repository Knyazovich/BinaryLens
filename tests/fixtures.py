"""Builds minimal, valid PE and ELF binaries entirely in-memory using
`struct`, with no external tools and no compilation. These fixtures are
inert data buffers -- they are never executed, only parsed statically,
which is exactly what BinaryLens itself does to any input.
"""

from __future__ import annotations

import struct

# ---------------------------------------------------------------------------
# PE32 fixture
# ---------------------------------------------------------------------------

IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002
IMAGE_FILE_32BIT_MACHINE = 0x0100
IMAGE_SCN_CNT_CODE = 0x00000020
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000


def build_minimal_pe32(
    section_name: bytes = b".text",
    section_data: bytes | None = None,
    machine: int = 0x014C,
    characteristics: int = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_32BIT_MACHINE,
    section_characteristics: int = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ,
    timestamp: int = 0x5F000000,
) -> bytes:
    """Build a minimal, structurally valid single-section PE32 image."""
    if section_data is None:
        # Repeating low-entropy pattern by default.
        section_data = bytes([0x90]) * 256  # NOP sled -> low entropy

    file_alignment = 0x200
    section_alignment = 0x1000

    # ---- DOS header (64 bytes) ----
    e_lfanew = 64
    dos_header = struct.pack(
        "<2s58sI",
        b"MZ",
        b"\x00" * 58,
        e_lfanew,
    )
    assert len(dos_header) == 64

    pe_signature = b"PE\x00\x00"

    num_sections = 1
    size_of_optional_header = 96 + 16 * 8  # standard fields + 16 data directories

    file_header = struct.pack(
        "<HHIIIHH",
        machine,
        num_sections,
        timestamp,
        0,  # PointerToSymbolTable
        0,  # NumberOfSymbols
        size_of_optional_header,
        characteristics,
    )
    assert len(file_header) == 20

    headers_end_estimate = (
        len(dos_header) + len(pe_signature) + len(file_header)
        + size_of_optional_header + 40 * num_sections
    )
    size_of_headers = ((headers_end_estimate + file_alignment - 1) // file_alignment) * file_alignment

    entry_point_rva = section_alignment
    base_of_code = section_alignment
    base_of_data = section_alignment * 2
    size_of_raw_data = ((len(section_data) + file_alignment - 1) // file_alignment) * file_alignment
    size_of_image = section_alignment + ((size_of_raw_data + section_alignment - 1) // section_alignment) * section_alignment

    optional_header = struct.pack(
        "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
        0x10B,          # Magic (PE32)
        14, 0,          # Linker version
        size_of_raw_data,  # SizeOfCode
        0,              # SizeOfInitializedData
        0,              # SizeOfUninitializedData
        entry_point_rva,   # AddressOfEntryPoint
        base_of_code,      # BaseOfCode
        base_of_data,      # BaseOfData
        0x00400000,        # ImageBase
        section_alignment,
        file_alignment,
        6, 0,           # OS version
        0, 0,           # Image version
        6, 0,           # Subsystem version
        0,              # Win32VersionValue
        size_of_image,
        size_of_headers,
        0,              # CheckSum
        3,              # Subsystem: Windows Console
        0,              # DllCharacteristics
        0x100000, 0x1000,  # Stack reserve/commit
        0x100000, 0x1000,  # Heap reserve/commit
        0,              # LoaderFlags
        16,             # NumberOfRvaAndSizes
    )
    assert len(optional_header) == 96

    data_directories = b"\x00" * (16 * 8)

    name_field = section_name[:8].ljust(8, b"\x00")
    section_header = struct.pack(
        "<8sIIIIIIHHI",
        name_field,
        len(section_data),     # VirtualSize
        entry_point_rva,       # VirtualAddress
        size_of_raw_data,      # SizeOfRawData
        size_of_headers,       # PointerToRawData
        0, 0,                  # Relocations / Linenumbers pointers
        0, 0,                  # NumberOfRelocations / Linenumbers
        section_characteristics,
    )
    assert len(section_header) == 40

    header_blob = dos_header + pe_signature + file_header + optional_header + data_directories + section_header
    header_blob = header_blob.ljust(size_of_headers, b"\x00")

    raw_section = section_data.ljust(size_of_raw_data, b"\x00")

    return header_blob + raw_section


def build_corrupted_pe() -> bytes:
    """A file with a valid MZ signature but garbage afterward."""
    return b"MZ" + b"\x00" * 10 + b"NOT A REAL PE HEADER" * 5


# ---------------------------------------------------------------------------
# ELF64 fixture
# ---------------------------------------------------------------------------

ET_EXEC = 2
EM_X86_64 = 0x3E
SHT_NULL = 0
SHT_PROGBITS = 1
SHT_STRTAB = 3
SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4


def build_minimal_elf64(text_data: bytes | None = None) -> bytes:
    """Build a minimal, structurally valid ELF64 executable with a
    .text section and a .shstrtab section."""
    if text_data is None:
        text_data = bytes([0x90]) * 64  # NOP sled -> low entropy

    ehdr_size = 64
    shdr_size = 64

    e_ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    assert len(e_ident) == 16

    text_offset = ehdr_size
    text_addr = 0x1000

    shstrtab_content = b"\x00" + b".text\x00" + b".shstrtab\x00"
    shstrtab_offset = text_offset + len(text_data)

    section_header_offset = shstrtab_offset + len(shstrtab_content)

    # Section name string offsets within shstrtab_content.
    name_null = 0
    name_text = 1
    name_shstrtab = 1 + len(b".text\x00")

    # NULL section (index 0)
    shdr_null = struct.pack("<IIQQQQIIQQ", 0, SHT_NULL, 0, 0, 0, 0, 0, 0, 0, 0)

    # .text section (index 1)
    shdr_text = struct.pack(
        "<IIQQQQIIQQ",
        name_text,
        SHT_PROGBITS,
        SHF_ALLOC | SHF_EXECINSTR,
        text_addr,
        text_offset,
        len(text_data),
        0, 0,
        16,
        0,
    )

    # .shstrtab section (index 2)
    shdr_shstrtab = struct.pack(
        "<IIQQQQIIQQ",
        name_shstrtab,
        SHT_STRTAB,
        0,
        0,
        shstrtab_offset,
        len(shstrtab_content),
        0, 0,
        1,
        0,
    )

    shnum = 3
    shstrndx = 2

    ehdr = struct.pack(
        "<16sHHIQQQIHHHHHH",
        e_ident,
        ET_EXEC,
        EM_X86_64,
        1,               # e_version
        text_addr,       # e_entry
        0,               # e_phoff
        section_header_offset,  # e_shoff
        0,               # e_flags
        ehdr_size,       # e_ehsize
        0,               # e_phentsize
        0,               # e_phnum
        shdr_size,       # e_shentsize
        shnum,           # e_shnum
        shstrndx,        # e_shstrndx
    )
    assert len(ehdr) == 64

    blob = ehdr + text_data + shstrtab_content + shdr_null + shdr_text + shdr_shstrtab
    return blob


def build_corrupted_elf() -> bytes:
    return b"\x7fELF" + b"\x00" * 4 + b"NOT A REAL ELF BODY" * 5

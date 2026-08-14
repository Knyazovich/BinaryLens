# BinaryLens

> A practical lens into compiled binaries.

BinaryLens is a command-line static binary analysis tool for inspecting PE and ELF executables, extracting structural information, calculating hashes and entropy, analyzing imports and exports, extracting strings, and surfacing static indicators — without executing the analyzed file.

[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![Status: Production/Stable](https://img.shields.io/badge/status-production%2Fstable-brightgreen.svg)]()

## Overview

BinaryLens performs **static analysis only** — it reads and parses a target binary's structure without loading, mapping for execution, or invoking any code from it. It currently supports **PE** (Windows) and **ELF** (Linux/Unix) binaries.

Intended for:

- Reverse engineers doing initial triage
- Security researchers
- Malware analysts
- Students learning binary and executable formats
- Developers curious about PE/ELF internals

**Static indicators are not a malware verdict.** BinaryLens surfaces individually-explained structural observations (entropy, imports, section characteristics, etc.) and reports how many were detected — it never classifies a file as malicious or benign.

## Features

**Binary metadata** — filename, size, format (PE/ELF), architecture, entry point, image base (PE), subsystem, compilation timestamp (PE)

**Hashing** — MD5, SHA-1, SHA-256, computed in a single streaming pass

**PE analysis** — DOS/PE headers, file characteristics flags, sections (name, virtual/raw size, permissions, entropy), imports, exports, overlay size

**ELF analysis** — ELF class/machine/object type, PIE and NX flags, sections, dynamic symbols/imports, exported symbols, overlay size

**Static indicators** — a rule-based engine that flags, among others:
- high-entropy sections
- writable + executable sections
- dynamic API resolution, memory-allocation, process-injection, process-execution, network, anti-analysis, and registry-related imports (PE)
- unusual or packer-associated section names
- a combined low-import-count + high-entropy packing heuristic (PE)
- missing expected metadata (no sections, no imports, zero timestamp)
- overlay data present
- abnormal PE characteristics

**String extraction** — ASCII and UTF-16LE ("wide") strings, with a configurable minimum length and result cap

**Reporting** — Rich-formatted terminal output, and a structured JSON report

## Example Output

Illustrative only — this is not output from a real sample, but reflects the actual fields and layout BinaryLens produces.

```text
BinaryLens v1.0
──────────────────────────────────────────────────

File        : example.exe
Architecture: x86-64
Format      : PE
Size        : 1.42 MB
Subsystem   : Windows Console
Entry Point : 0x00401000
Image Base  : 0x00400000
Compiled    : 2019-03-14 10:22:01 UTC
SHA256      : 8f3c2e...
SHA1        : a91b7c...
MD5         : 44d2f0...

[Sections]

Name    Raw Size  Virtual Size  Perms  Entropy
.text   842.00 KB 840.11 KB     R-X    6.72
.rdata  231.00 KB 229.80 KB     R--    5.11
.data    42.00 KB  41.50 KB     RW-    3.21

[Imports]
kernel32.dll
  CreateFileW
  VirtualAlloc
  VirtualProtect
  GetProcAddress

[Analysis]
⚠ High entropy section detected
  Section: .text
  Entropy: 6.72
⚠ Executable memory allocation API
  Apis: VirtualAlloc, VirtualProtect
⚠ Dynamic API resolution
  Apis: GetProcAddress

Risk indicators: 3
This count reflects detected static indicators only. It is not a malware verdict.
```

### Drag & Drop

BinaryLens accepts a normal filesystem path argument. If launched with no arguments, it prompts interactively and accepts a path pasted or dragged into the terminal — this is **terminal path input**, not a graphical drag-and-drop UI:

```text
$ binarylens
BinaryLens v1.0
No file provided.
...
Drag and drop a binary file here, then press Enter: C:\Users\User\Desktop\program.exe
```

Paths containing spaces are supported (the CLI rejoins split argv tokens when an unquoted dropped path is split by the shell).

## Installation

```bash
git clone https://github.com/Knyazovich/BinaryLens.git
cd BinaryLens

python -m venv .venv
```

**Windows:**
```powershell
.venv\Scripts\activate
```

**Linux/macOS:**
```bash
source .venv/bin/activate
```

```bash
pip install -r requirements.txt
pip install -e .
```

This registers the `binarylens` console command via the `[project.scripts]` entry point in `pyproject.toml`.

**Windows convenience launcher:** `run_binarylens.bat` checks for Python 3.11+, verifies/installs dependencies, installs the package if needed, and launches BinaryLens (drag a file onto the `.bat` file, or run it with no arguments for the interactive prompt).

## Usage

```bash
binarylens example.exe
```

Or as a module:

```bash
python -m binarylens.cli example.exe
```

Two bundled sample binaries (synthetic, non-functional placeholders) are provided for trying the tool immediately:

```bash
binarylens examples/sample_pe32.exe
binarylens examples/sample_elf64
```

### Command Reference

| Flag                    | Description                                          |
|--------------------------|--------------------------------------------------------|
| `<file>`                  | Path to the binary to analyze                          |
| `--sections`              | Show only section information                          |
| `--imports`               | Show only imported functions                            |
| `--exports`               | Show only exported functions                            |
| `--strings`               | Show only extracted strings                             |
| `--entropy`               | Show only per-section entropy                           |
| `--json OUTPUT_PATH`      | Write a machine-readable JSON report                    |
| `--min-string-length N`  | Minimum length for extracted strings (default: 4)       |
| `--max-strings N`        | Maximum number of strings to extract/display (default: 500) |
| `--version`               | Print the BinaryLens version                            |

With no flags, BinaryLens prints a full report (file info, sections, imports, exports if present, and analysis indicators). Passing any specific flag switches to a filtered report containing only the requested sections.

## Supported Formats

```text
PE   — .exe, .dll, and other PE-compatible binaries (detected via "MZ" signature)
ELF  — Linux/Unix binaries (detected via the \x7fELF signature), parsed with LIEF
```

Both formats are implemented and covered by the test suite. Unrecognized formats produce an explicit `UnsupportedFormatError` rather than a partial or best-effort result.

## Analysis Details

**Entropy** — Shannon entropy in bits/byte (0–8), computed per section. High entropy (≥7.0 in the built-in indicator threshold) can correlate with compression, encryption, or packing, but is an indicator only, never proof.

**Imports / Exports** — PE imports are read from the import directory and grouped by DLL; PE exports come from the export directory. ELF imports are taken from dynamic symbols and linked libraries; ELF exports come from exported dynamic symbols. The presence of a flagged API does not by itself indicate malicious behavior — many are common in legitimate software.

**Sections** — name, virtual address/size, raw size, permissions (R/W/X), and entropy, for both PE and ELF.

**Hashes** — MD5, SHA-1, and SHA-256, computed by streaming the file once in 1 MB chunks.

**Strings** — printable ASCII and UTF-16LE sequences extracted via regex over the raw file bytes, with a configurable minimum length, a result cap, and a hard 64 MB scan ceiling to bound resource use on very large files.

## Security Model

BinaryLens performs **static analysis only**, by design and in its docstrings:

- It never executes analyzed binaries
- It never loads or maps analyzed DLLs/ELFs for execution
- It never invokes functions from analyzed files
- It never automatically accesses URLs or paths found in extracted strings
- It never modifies analyzed files (files are opened read-only)

Analyzed files should always be treated as **untrusted input**. Corrupted or malformed files raise explicit, caught exceptions (`CorruptedBinaryError`, `UnsupportedFormatError`, etc.) rather than propagating raw parser tracebacks.

## Architecture

```text
BinaryLens/
├── binarylens/
│   ├── cli.py                 # argparse CLI, drag-and-drop prompt, entry point
│   ├── analyzer.py            # orchestrates parsing + analysis into an AnalysisResult
│   ├── models.py               # dataclasses: FileInfo, Hashes, SectionInfo, etc.
│   ├── exceptions.py           # BinaryLensError and subclasses
│   ├── formats/
│   │   ├── pe.py                # PE parsing (pefile)
│   │   └── elf.py               # ELF parsing (LIEF)
│   ├── analysis/
│   │   ├── entropy.py           # Shannon entropy
│   │   ├── hashes.py            # MD5/SHA-1/SHA-256
│   │   ├── strings.py           # ASCII/UTF-16LE string extraction
│   │   ├── imports.py           # API watchlists used by indicators
│   │   └── indicators.py        # rule-based static indicator engine
│   ├── output/
│   │   ├── terminal.py          # Rich terminal rendering
│   │   └── json_report.py       # JSON report generation
│   └── utils/
│       ├── files.py             # path resolution, size formatting
│       └── formatting.py        # hex/permission formatting helpers
├── tests/                       # pytest suite (see Testing)
├── examples/                    # synthetic sample_pe32.exe / sample_elf64
├── docs/indicators.md            # indicator documentation
├── requirements.txt
├── pyproject.toml
├── run_binarylens.bat            # Windows dependency-check + launch script
├── README.md
└── LICENSE
```

## Technology Stack

```text
Python 3.11+
pefile   — PE header, section, import/export parsing
lief     — ELF parsing
rich     — formatted terminal output
```

`capstone` is listed as a dependency in `requirements.txt` / `pyproject.toml` but is not currently imported or used anywhere in the codebase — it appears to be reserved for a future disassembly feature (see Roadmap).

## Testing

```bash
pytest
```

The suite (`tests/`) covers:

- PE parsing (`test_pe.py`)
- ELF parsing (`test_elf.py`)
- The analysis orchestrator (`test_analyzer.py`)
- Entropy calculation (`test_entropy.py`)
- Hash calculation (`test_hashes.py`)
- Static indicators (`test_indicators.py`)
- String extraction (`test_strings.py`)
- JSON report output (`test_json_report.py`)
- File path resolution utilities (`test_files_utils.py`)
- CLI behavior (`test_cli.py`)

Fixtures for minimal/corrupted synthetic PE binaries live in `tests/fixtures.py`. Tests that require `pefile` are skipped automatically if it isn't installed (`pytest.importorskip`).

## Limitations

- Not a full malware detection engine — it reports indicators, not verdicts.
- Static indicators can produce false positives; several are explicitly documented as weak heuristics (e.g. the packing heuristic).
- Does not replace Ghidra, IDA, Binary Ninja, or a debugger.
- No disassembly or control-flow analysis is currently performed, despite `capstone` being a listed dependency.
- Packed or obfuscated binaries may limit the usefulness of static analysis.
- No dynamic behavior analysis (by design — see Security Model).
- ELF import attribution is coarser than PE's: unresolved dynamic symbols are grouped under a synthetic `(dynamic symbols)` bucket rather than mapped to a specific library.

## Roadmap

Future ideas — not currently implemented:

```text
- [ ] Disassembly integration (capstone is already a declared dependency)
- [ ] Control-flow graph generation
- [ ] Richer PE/ELF anomaly detection
- [ ] More advanced string classification
- [ ] Import categorization
- [ ] Additional binary formats
```

## Contributing

Bug reports, pull requests, new analysis modules, additional tests, and documentation improvements are welcome. Please open an issue before starting significant work so the approach can be discussed first.

## License

MIT License — see [LICENSE](LICENSE).

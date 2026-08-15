# BinaryLens

**BinaryLens** is a command-line static binary analysis / reverse
engineering tool for inspecting Windows PE and ELF executables. It parses
a binary's structure, extracts imports, exports, sections, and strings,
computes hashes and entropy, and surfaces a set of clearly-explained
static indicators — without ever executing the file being analyzed.

## Why it exists

Reverse engineers and security researchers routinely need a fast,
scriptable first look at an unknown binary before deciding whether it's
worth deeper analysis in a disassembler or sandbox. BinaryLens is built
to be that first look: a single command that produces a clean, accurate,
professional report of a binary's structure and static risk indicators,
usable both by a human at a terminal and by other tooling via JSON
output.

BinaryLens deliberately does **not** try to tell you whether a file is
malware. It surfaces observations — high entropy, unusual imports,
writable+executable sections, and so on — and leaves interpretation to
the analyst.

## Features

- **PE and ELF parsing** — headers, sections, imports, exports, entry
  point, image base, subsystem, compile timestamp.
- **Hashing** — MD5, SHA-1, SHA-256.
- **Entropy analysis** — per-section Shannon entropy.
- **String extraction** — static ASCII and UTF-16LE string scanning with
  sensible limits so huge binaries don't flood your terminal.
- **Contextual detection engine** — separates capabilities (what the
  binary can do) from findings (correlated, evidence-backed anomalies),
  with a severity model (`INFO`/`LOW`/`MEDIUM`/`HIGH`) instead of an
  "API = risk point" count. See [`docs/indicators.md`](docs/indicators.md)
  for the full rule reference.
- **JSON reports** — the exact same analysis data as the terminal report,
  structured for scripting and tool integration.
- **Drag-and-drop terminal support** — run `binarylens` with no
  arguments and drop a file into the terminal.
- **Clean error handling** — invalid, corrupted, or unsupported files
  produce a clear message, never a raw Python traceback.

## Installation

Requires Python 3.11+.

### Windows — one-click launcher

Double-click **`run_binarylens.bat`** (or drag a binary file directly onto
it). It will:

1. Check that Python 3.11+ and `pip` are available.
2. Check each required dependency (`pefile`, `lief`, `capstone`, `rich`)
   individually and install any that are missing via `requirements.txt`.
3. Install BinaryLens itself if it isn't already installed.
4. Launch BinaryLens — either interactively (drag-and-drop prompt) or
   directly against the file you dropped onto the `.bat`.

```bat
run_binarylens.bat
run_binarylens.bat program.exe
run_binarylens.bat program.exe --json report.json
```

### Manual installation (Windows, macOS, Linux)

```bash
git clone <this-repository>
cd BinaryLens
pip install -r requirements.txt
pip install -e .
```

This installs the `binarylens` command on your `PATH`.

## Usage

```bash
binarylens program.exe
```

### Show only specific sections of the report

```bash
binarylens program.exe --sections
binarylens program.exe --imports
binarylens program.exe --exports
binarylens program.exe --strings
binarylens program.exe --entropy
```

Flags can be combined, e.g. `binarylens program.exe --sections --entropy`.

### JSON output

```bash
binarylens program.exe --json report.json
```

### Other options

```bash
binarylens program.exe --min-string-length 6 --max-strings 200
binarylens --version
```

## Drag-and-drop usage

Run BinaryLens with no arguments:

```bash
binarylens
```

You'll be prompted to drag and drop a file into the terminal:

```text
Drag and drop a binary file here, then press Enter: C:\Users\User\Desktop\program.exe
```

Paths with spaces, and paths wrapped in quotes by the terminal, are
handled automatically. This also works as a normal CLI argument:

```bash
binarylens "C:\Users\User\Desktop\my program.exe"
```

## Example output

A binary showing only ordinary, uncorrelated capabilities:

```text
BinaryLens v1.0
────────────────────────────────

File        : setup.exe
Architecture: x86-64
Format      : PE
Size        : 4.10 MB
SHA256      : 8f3c2e...

[Sections]
.text       842 KB    Entropy: 6.72    R-X    Known / Common
.rdata      231 KB    Entropy: 5.11    R--    Known / Common
.wixburn      108 B   Entropy: 1.02    R--    Known Installer

[Imports]
kernel32.dll
  CreateProcessW
  OpenProcess
  VirtualAlloc
  VirtualProtect
  GetProcAddress

[Packaging]
ℹ WiX Burn bootstrapper section detected (.wixburn)

[Overlay]
Present
Size : 31.20 MB
Ratio: 88% of file size

[Capabilities]
Process Management
  CreateProcessW
  OpenProcess
Memory Management
  VirtualAlloc
  VirtualProtect
Dynamic Linking
  GetProcAddress

[Findings]
INFO   Large overlay detected
INFO   Dynamic API resolution capability
INFO   Process management capability

[Summary]

Informational findings : 3
Low severity            : 0
Medium severity         : 0
High severity           : 0

No significant anomalies were identified by static analysis.
```

A binary with a genuinely correlated, evidence-backed pattern:

```text
[Findings]

HIGH   ⚠ Strong process injection pattern
  The binary imports a complete chain of APIs commonly used to inject
  and execute code inside another process...
  Evidence:
    CreateRemoteThread
    OpenProcess
    VirtualAllocEx
    WriteProcessMemory
  Confidence: High

[Summary]

Informational findings : 1
Low severity            : 0
Medium severity         : 0
High severity            : 1

One or more strongly correlated indicators were found. Manual review in
a full analysis environment is recommended.
```

Every value in a real report is computed from the actual file being
analyzed — nothing above is hardcoded or simulated. See
[`docs/indicators.md`](docs/indicators.md) for how the engine decides
what becomes a finding and at what severity.

## Supported formats

- **PE** (`.exe`, `.dll`, `.sys`, etc.) — x86 and x86-64, via `pefile`.
- **ELF** — x86, x86-64, ARM, ARM64, and others as recognized by `LIEF`.

Unsupported or unrecognized files produce a clear error message rather
than a crash or fabricated output.

## Architecture

```text
binarylens/
├── cli.py              CLI entry point, argument parsing, drag-and-drop
├── analyzer.py          Orchestrates parsing + analysis into one result
├── models.py             Shared data model (Capability, Finding, ...)
├── exceptions.py         Typed errors for clean CLI-level messages
├── formats/
│   ├── pe.py              PE parsing (pefile)
│   └── elf.py             ELF parsing (LIEF)
├── analysis/
│   ├── hashes.py          MD5 / SHA-1 / SHA-256
│   ├── entropy.py         Shannon entropy
│   ├── strings.py         Static string extraction
│   ├── imports.py         Granular Windows API sets (building blocks only)
│   ├── findings.py        Finding/Capability factory helpers
│   ├── scoring.py         Severity summary + hedged assessment note
│   ├── correlation.py     Orchestrates every rule module below
│   └── indicators/
│       ├── api_categories.py  API → capability classification
│       ├── injection.py       Process injection correlation
│       ├── anti_debug.py      Anti-debugging correlation
│       ├── persistence.py     Persistence-mechanism correlation
│       ├── installers.py      Installer/packaging framework recognition
│       ├── sections.py        Section name/structure classification
│       ├── packing.py         Multi-signal packing correlation
│       └── overlay.py         Overlay size/context analysis
├── output/
│   ├── terminal.py        Rich-based terminal rendering
│   └── json_report.py     JSON report generation
└── utils/
    ├── files.py            Path resolution, drag-and-drop cleanup
    └── formatting.py       Small shared formatting helpers
```

The analysis logic (`analyzer.py`, `analysis/`, `formats/`) never renders
anything — it only produces an `AnalysisResult`. Both `output/terminal.py`
and `output/json_report.py` consume that same object, so terminal and
JSON output can never drift apart. See [`docs/indicators.md`](docs/indicators.md)
for how `correlation.py` and the `indicators/` rule modules turn raw
imports and section data into capabilities and findings.

## Security considerations

BinaryLens performs **static analysis only**. It never:

- executes, launches, or maps the analyzed binary for execution,
- calls or resolves any function from the analyzed file,
- connects to any URL or resource found inside the analyzed file,
- modifies the analyzed file.

Every file you point BinaryLens at is treated as untrusted input. Parse
errors are caught and reported cleanly rather than propagating a
traceback or partial/fabricated data.

Findings are **evidence-backed observations, not a malware verdict**.
BinaryLens never claims a file "is malware" and never reports a malware
probability — it separates ordinary capabilities from correlated
anomalies, explains exactly what evidence produced each finding, and
leaves judgment to you.

## Testing

```bash
pip install -r requirements.txt
pip install pytest
pytest
```

The test suite covers PE and ELF parsing, hash and entropy calculation,
import/export/string extraction, the detection engine's correlation
rules (including dedicated false-positive regression tests for
installer-style binaries), JSON report generation, CLI argument
handling, invalid/corrupted file handling, and paths containing spaces.
Tests use small, synthetically generated binary fixtures (built with
`struct`, see `tests/fixtures.py`) — no real-world or third-party
binaries are executed or required.

## Roadmap

- Disassembly view for individual functions (via `Capstone`, already a
  dependency) at the entry point and exported functions.
- Mach-O support.
- YARA rule integration for the indicator engine.
- Diffing mode to compare two binaries' static analysis results.

## License

MIT — see [LICENSE](LICENSE).

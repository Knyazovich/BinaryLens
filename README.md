# BinaryLens

> A practical lens into compiled binaries.

BinaryLens is a command-line static binary analysis tool for inspecting executable files, extracting structural information, calculating hashes and entropy, analyzing imports and exports, extracting strings, and identifying potentially interesting binary characteristics — without executing the analyzed file.

[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-informational.svg)]()

> **Note:** Badges above are placeholders. Replace the license badge/link once a LICENSE file is committed, and add a release or CI badge only once those are actually configured in the repository.

---

## Overview

BinaryLens performs **static analysis** of executable files — it parses and inspects a binary's structure without ever loading, executing, or invoking any code from it. It is built for people who need a fast, scriptable first look at a binary before reaching for heavier tooling.

Intended audience:

- Reverse engineers doing initial triage
- Security researchers
- Malware analysts
- Students learning binary and executable formats
- Developers curious about PE/ELF internals

**Static indicators ≠ malware verdict.** BinaryLens surfaces structural facts (entropy, imports, section characteristics, etc.). It does not classify files as malicious or benign, and its output should be interpreted as a starting point for further investigation, not a conclusion.

---

## Features

> Feature lists below follow the categories described in the project specification. Before publishing, confirm each line against the actual CLI/output of your implementation and remove anything not yet built.

**Binary Metadata**
- File type, architecture, file size
- Entry point, image base
- Compilation timestamp
- PE metadata

**Hashing**
- MD5, SHA-1, SHA-256

**PE Analysis**
- PE header parsing
- Section listing (permissions, virtual/raw size)
- Imports
- Exports

**Static Analysis**
- Section entropy calculation
- Suspicious API indicators
- Unusual section characteristics
- Possible packing indicators
- Executable/writable section detection
- Overlay detection

**Strings**
- ASCII string extraction
- Unicode string extraction

**Reporting**
- Human-readable terminal output
- JSON report export

---

## Example Analysis

The output below is **illustrative** — it demonstrates the shape and style of BinaryLens output, not a result from a real sample.

```text
$ binarylens example.exe

BinaryLens v1.0
────────────────────────────────

File        : example.exe
Architecture: x86-64
Format      : PE
Size        : 1.42 MB
SHA256      : 8f3c2e...

[Sections]
.text       842 KB    Entropy: 6.72    R-X
.rdata      231 KB    Entropy: 5.11    R--
.data        42 KB    Entropy: 3.21    RW-

[Imports]
kernel32.dll
  CreateFileW
  VirtualAlloc
  VirtualProtect
  GetProcAddress

[Analysis]
⚠ High entropy section detected
⚠ Executable memory allocation API
⚠ Dynamic API resolution

Risk indicators: 3
```

### Drag & Drop

BinaryLens can be launched without arguments and accepts a file path afterward, which makes it convenient for terminal drag-and-drop workflows:

```text
$ binarylens
```

Drag a file from your file manager into the terminal window, or paste a path directly. Paths containing spaces are supported:

```text
C:\Users\User\Desktop\sample.exe
```

This is **terminal path drag-and-drop** — pasting/dropping a path into a CLI prompt — not a graphical drag-and-drop interface. BinaryLens has no GUI.

---

## Installation

```bash
git clone <repository-url>
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

Then install dependencies:

```bash
pip install -r requirements.txt
```

> If BinaryLens is packaged via `pyproject.toml`, replace the above with the actual install command (e.g. `pip install .`) and confirm it works from a clean environment before publishing.

---

## Usage

```bash
binarylens example.exe
```

If installed as a module rather than an entry point:

```bash
python -m binarylens example.exe
```

> Confirm which of these invocation styles actually works against the final implementation, and remove the one that doesn't.

---

## Command Reference

| Command / Flag         | Description                  |
|-------------------------|-------------------------------|
| `binarylens file.exe`   | Analyze a binary               |
| `--sections`            | Display section information    |
| `--imports`             | Display imports                |
| `--exports`             | Display exports                |
| `--strings`             | Extract strings                |
| `--entropy`             | Analyze entropy                |
| `--json report.json`    | Export a JSON report           |

> Verify every row above against `cli.py` (or the argument parser). Remove any flag not implemented, and add any implemented flag not listed here.

---

## Supported Formats

```text
PE
├── .exe
├── .dll
└── other PE-compatible binaries

ELF
└── Linux/Unix binaries (support level depends on implementation — mark as
    experimental below if analysis modules are incomplete)
```

> Mark ELF (or any non-PE format) as **experimental** or **partial** unless it has been implemented and tested to the same depth as PE analysis. Do not claim full ELF/ARM support unless verified.

---

## Analysis Details

**Entropy**
Entropy measures the distribution of byte values within a section or file. High entropy can indicate compressed or encrypted regions.
> High entropy is an indicator, not proof of packing or malicious behavior.

**Imports**
Imported APIs can hint at a binary's capabilities (file access, memory operations, networking, etc.).
> The presence of a suspicious API does not automatically make a binary malicious.

**Sections**
Common PE sections include `.text` (code), `.rdata` (read-only data), and `.data` (initialized data). BinaryLens reports each section's permissions, virtual size, and raw size to help identify anomalies (e.g. a writable-and-executable section).

**Hashes**
MD5, SHA-1, and SHA-256 provide stable identifiers for a file, useful for comparing samples or checking against known hash sets.

**Strings**
Static string extraction surfaces readable ASCII/Unicode text embedded in a binary, which can reveal file paths, URLs, error messages, or other artifacts.

---

## Security Model

BinaryLens performs **static analysis only**.

BinaryLens must not:

- Execute analyzed binaries
- Load analyzed DLLs
- Invoke functions from analyzed files
- Automatically access URLs found in samples
- Modify analyzed files

Analyzed files should always be treated as **untrusted input**. Run BinaryLens in an isolated or disposable environment when handling suspected malware, and never open extracted strings, URLs, or paths directly from the analysis output without independent verification.

---

## Architecture

```text
BinaryLens/
├── binarylens/
│   ├── cli.py          # Command-line entry point and argument parsing
│   ├── analyzer.py     # Orchestrates analysis across modules
│   ├── formats/         # Format-specific parsers (PE, ELF, ...)
│   ├── analysis/        # Entropy, static indicators, heuristics
│   ├── output/           # Terminal and JSON report rendering
│   └── utils/             # Shared helpers (hashing, string extraction, ...)
├── tests/
├── examples/
├── docs/
├── requirements.txt
├── pyproject.toml
├── README.md
└── LICENSE
```

> Adjust this tree to exactly match the real repository layout before publishing.

---

## Technology Stack

```text
Python 3.11+
pefile      — PE header, section, and import/export parsing
Rich        — formatted terminal output
```

> This list is a starting point. Add or remove libraries (e.g. `LIEF`, `Capstone`) only if they are actually imported and used in the codebase — an unused dependency listed here misleads contributors about what the project relies on.

---

## Testing

```bash
pytest
```

Test coverage should include:

- PE parsing
- Hash calculation
- Section parsing
- Import/export extraction
- Entropy calculation
- String extraction
- Static indicator logic
- JSON output
- CLI behavior

> Only list the categories above once corresponding tests exist in `tests/`. Remove any that aren't covered yet.

---

## Limitations

- BinaryLens is not a full malware detection engine.
- Static indicators can produce false positives.
- It does not replace Ghidra, IDA, Binary Ninja, or a debugger.
- Packed or obfuscated binaries may limit the usefulness of static analysis.
- Dynamic behavior (runtime API calls, network activity, unpacking) is not analyzed.

---

## Roadmap

```text
- [ ] Improved ELF analysis
- [ ] Richer PE anomaly detection
- [ ] More advanced string classification
- [ ] Import categorization
- [ ] Basic disassembly integration
- [ ] Control-flow graph generation
- [ ] Additional binary formats
```

---

## Contributing

Contributions are welcome:

- Bug reports and reproducible test cases
- Pull requests for fixes or new analysis modules
- Additional tests
- Documentation improvements

Please open an issue before starting significant work so the approach can be discussed first.

---

## License

> Add the project's actual license here (e.g. MIT, Apache-2.0, GPL-3.0) and include a matching `LICENSE` file in the repository root. Do not publish this README with an unresolved license.

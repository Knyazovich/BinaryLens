# BinaryLens

> A practical lens into compiled binaries.

BinaryLens is a command-line static binary analysis tool for inspecting executable files, extracting structural information, calculating hashes and entropy, analyzing imports and exports, extracting strings, and identifying potentially interesting binary characteristics — without executing the analyzed file.

[![License](https://img.shields.io/badge/license-UNSPECIFIED-lightgrey.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-informational.svg)]()

---

## Overview

BinaryLens performs **static analysis** of executable files — it parses and inspects a binary's structure without loading, executing, or invoking any code from it. It's built for a fast, scriptable first look at a binary before reaching for heavier tooling.

Intended audience:

- Reverse engineers doing initial triage
- Security researchers
- Malware analysts
- Students learning binary and executable formats
- Developers curious about PE/ELF internals

**Static indicators ≠ malware verdict.** BinaryLens surfaces structural facts (entropy, imports, section characteristics, etc.). It does not classify files as malicious or benign; output should be treated as a starting point for further investigation.

---

## Features

- Binary metadata — file type, architecture, size, entry point, image base, compilation timestamp
- Hashing — MD5, SHA-1, SHA-256
- PE analysis — headers, sections, permissions, virtual/raw sizes, imports, exports
- Static analysis — section entropy, suspicious API indicators, unusual section characteristics, packing indicators, executable/writable section detection, overlay detection
- String extraction — ASCII and Unicode
- Reporting — human-readable terminal output, JSON export

---

## Example Output

Illustrative only — not output from a real sample.

```text
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

```bash
pip install -r requirements.txt
```

---

## Usage

```bash
binarylens example.exe
```

```bash
python -m binarylens example.exe
```

| Flag                  | Description                  |
|------------------------|--------------------------------|
| `--sections`            | Display section information    |
| `--imports`             | Display imports                |
| `--exports`             | Display exports                |
| `--strings`             | Extract strings                |
| `--entropy`             | Analyze entropy                |
| `--json report.json`    | Export a JSON report           |

---

## Analysis Capabilities

**Hashes** — MD5/SHA-1/SHA-256 identifiers, useful for comparing samples.

**PE Headers & Sections** — parses `.text`, `.rdata`, `.data`, and other sections, reporting permissions, virtual size, and raw size to help spot anomalies.

**Imports / Exports** — lists imported/exported APIs, which can hint at a binary's capabilities. Presence of a "suspicious" API does not itself indicate malicious intent.

**Entropy** — measures byte-distribution randomness per section; high entropy can suggest compression or encryption but is not proof of packing.

**Strings** — extracts readable ASCII/Unicode text embedded in the binary.

---

## Security Model

BinaryLens performs **static analysis only**. It must not:

- Execute analyzed binaries
- Load analyzed DLLs
- Invoke functions from analyzed files
- Automatically access URLs found in samples
- Modify analyzed files

Analyzed files should always be treated as **untrusted input**.

---

## Architecture

```text
BinaryLens/
├── binarylens/
│   ├── cli.py
│   ├── analyzer.py
│   ├── formats/
│   ├── analysis/
│   ├── output/
│   └── utils/
├── tests/
├── requirements.txt
├── pyproject.toml
├── README.md
└── LICENSE
```

---

## Testing

```bash
pytest
```

---

## Limitations

- Not a full malware detection engine
- Static indicators can produce false positives
- Does not replace Ghidra, IDA, Binary Ninja, or a debugger
- Packed/obfuscated binaries may limit static analysis usefulness
- No dynamic behavior analysis

---

## Roadmap

```text
- [ ] Improved ELF analysis
- [ ] Richer PE anomaly detection
- [ ] More advanced string classification
- [ ] Import categorization
- [ ] Basic disassembly integration
- [ ] Control-flow graph generation
```

---

## Contributing

Bug reports, pull requests, new analysis modules, tests, and documentation improvements are welcome. Open an issue before starting significant work.

---

## License

*Add the project's actual license here and include a matching `LICENSE` file.*

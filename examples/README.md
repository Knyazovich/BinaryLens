# Examples

This directory contains tiny, synthetically generated sample binaries you
can use to try BinaryLens immediately after installation, without needing
to supply your own file.

- `sample_pe32.exe` — a minimal, structurally valid single-section PE32
  executable (no real code, no imports).
- `sample_elf64` — a minimal, structurally valid ELF64 executable with a
  `.text` and `.shstrtab` section.

Both files are inert placeholder binaries built purely for demonstrating
BinaryLens' parsing and reporting. They contain no functional code.

## Try it

```bash
binarylens examples/sample_pe32.exe
binarylens examples/sample_elf64
binarylens examples/sample_pe32.exe --json report.json
```

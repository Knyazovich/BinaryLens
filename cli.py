"""BinaryLens command-line interface.

Supports:
  binarylens program.exe
  binarylens program.exe --sections --imports --exports --strings --entropy
  binarylens program.exe --json report.json
  binarylens                     (interactive drag-and-drop prompt)
"""

from __future__ import annotations

import argparse
import sys

from binarylens import __version__
from binarylens.analyzer import analyze_file
from binarylens.exceptions import (
    BinaryLensError,
    CorruptedBinaryError,
    EmptyFileError,
    FileNotFoundErrorBL,
    PermissionDeniedError,
    UnsupportedFormatError,
)
from binarylens.output.json_report import write_json_report
from binarylens.output.terminal import console, print_error, print_full_report, print_sections_report
from binarylens.utils.files import resolve_existing_path

USAGE_MESSAGE = """\
Usage:
  binarylens <file>                 Analyze a binary and print a full report
  binarylens <file> --sections      Show only section information
  binarylens <file> --imports       Show only imported functions
  binarylens <file> --exports       Show only exported functions
  binarylens <file> --strings       Show only extracted strings
  binarylens <file> --entropy       Show only entropy analysis
  binarylens <file> --json out.json Write a machine-readable JSON report

You can also drag and drop a file directly into the terminal:
  binarylens
  Drag and drop a binary file here, then press Enter: C:\\Users\\User\\Desktop\\program.exe

Paths containing spaces are supported.\
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="binarylens",
        description="BinaryLens - Static Binary Analysis / Reverse Engineering CLI tool.",
        add_help=True,
    )
    parser.add_argument(
        "file",
        nargs="*",
        help="Path to the binary file to analyze (drag-and-drop supported).",
    )
    parser.add_argument("--sections", action="store_true", help="Show section information.")
    parser.add_argument("--imports", action="store_true", help="Show imported functions.")
    parser.add_argument("--exports", action="store_true", help="Show exported functions.")
    parser.add_argument("--strings", action="store_true", help="Show extracted strings.")
    parser.add_argument("--entropy", action="store_true", help="Show entropy analysis.")
    parser.add_argument(
        "--json",
        metavar="OUTPUT_PATH",
        help="Write a machine-readable JSON report to the given path.",
    )
    parser.add_argument(
        "--min-string-length",
        type=int,
        default=4,
        help="Minimum length for extracted strings (default: 4).",
    )
    parser.add_argument(
        "--max-strings",
        type=int,
        default=500,
        help="Maximum number of strings to extract/display (default: 500).",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"BinaryLens v{__version__}",
    )
    return parser


def prompt_for_path() -> str:
    console.print(f"[bold cyan]BinaryLens v{__version__}[/bold cyan]")
    console.print("[dim]No file provided.[/dim]\n")
    console.print(USAGE_MESSAGE)
    console.print()
    try:
        raw = input("Drag and drop a binary file here, then press Enter: ")
    except (EOFError, KeyboardInterrupt):
        console.print()
        sys.exit(1)
    return raw


def resolve_target_path(file_tokens: list) -> str:
    """Resolve the file path from argv tokens, or prompt interactively
    (supporting drag-and-drop) when none were provided."""
    if file_tokens:
        # Multiple tokens happen when an unquoted dropped path contained
        # spaces and the shell split it into several argv entries.
        raw = " ".join(file_tokens)
    else:
        raw = prompt_for_path()

    return resolve_existing_path(raw)


def run(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        filepath = resolve_target_path(args.file)
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001
        print_error(f"Could not resolve file path: {exc}")
        return 1

    if not filepath:
        console.print(f"[bold cyan]BinaryLens v{__version__}[/bold cyan]\n")
        console.print(USAGE_MESSAGE)
        return 1

    try:
        need_strings = args.strings or bool(args.json)
        result = analyze_file(
            filepath,
            extract_string_data=need_strings,
            string_min_length=args.min_string_length,
            string_max_count=args.max_strings,
        )
    except FileNotFoundErrorBL as exc:
        print_error(str(exc))
        return 1
    except PermissionDeniedError as exc:
        print_error(str(exc))
        return 1
    except EmptyFileError as exc:
        print_error(str(exc))
        return 1
    except UnsupportedFormatError as exc:
        print_error(str(exc))
        return 1
    except CorruptedBinaryError as exc:
        print_error(str(exc))
        return 1
    except BinaryLensError as exc:
        print_error(str(exc))
        return 1
    except RuntimeError as exc:
        # Missing optional dependency (pefile/lief not installed).
        print_error(str(exc))
        return 1
    except Exception as exc:  # noqa: BLE001 - final safety net, no raw traceback
        print_error(f"Unexpected error while analyzing file: {exc}")
        return 1

    any_specific_flag = any([args.sections, args.imports, args.exports, args.strings, args.entropy])

    if any_specific_flag:
        print_sections_report(
            result,
            show_sections=args.sections,
            show_imports=args.imports,
            show_exports=args.exports,
            show_strings=args.strings,
            show_entropy=args.entropy,
        )
    else:
        print_full_report(result)

    if args.json:
        try:
            write_json_report(result, args.json)
            console.print(f"[green]JSON report written to:[/green] {args.json}")
        except OSError as exc:
            print_error(f"Could not write JSON report: {exc}")
            return 1

    return 0


def main() -> None:
    exit_code = run(sys.argv[1:])
    sys.exit(exit_code)


if __name__ == "__main__":
    main()

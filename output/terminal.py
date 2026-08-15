"""Rich-based terminal rendering of an AnalysisResult.

Rendering logic lives entirely here and never computes or invents any
analysis data -- it only formats what analyzer.py/correlation.py already
produced.
"""

from __future__ import annotations

from rich.console import Console
from rich.table import Table
from rich.text import Text

from binarylens.models import AnalysisResult
from binarylens.utils.files import human_readable_size

console = Console()

BANNER = "BinaryLens v1.0"
RULE_CHAR = "─"

_SEVERITY_STYLE = {
    "INFO": "cyan",
    "LOW": "yellow",
    "MEDIUM": "bold yellow",
    "HIGH": "bold red",
}

_SEVERITY_ICON = {
    "INFO": "ℹ",
    "LOW": "⚠",
    "MEDIUM": "⚠",
    "HIGH": "⚠",
}


def _rule(width: int = 50) -> str:
    return RULE_CHAR * width


def print_banner() -> None:
    console.print()
    console.print(f"[bold cyan]{BANNER}[/bold cyan]")
    console.print(f"[dim]{_rule()}[/dim]")


def print_file_info(result: AnalysisResult) -> None:
    fi = result.file_info
    console.print()
    console.print(f"[bold]File        :[/bold] {fi.filename}")
    console.print(f"[bold]Architecture:[/bold] {fi.architecture}")
    console.print(f"[bold]Format      :[/bold] {fi.format}")
    console.print(f"[bold]Size        :[/bold] {human_readable_size(fi.size)}")
    if fi.subsystem:
        console.print(f"[bold]Subsystem   :[/bold] {fi.subsystem}")
    if fi.entry_point:
        console.print(f"[bold]Entry Point :[/bold] {fi.entry_point}")
    if fi.image_base:
        console.print(f"[bold]Image Base  :[/bold] {fi.image_base}")
    if fi.compile_timestamp:
        console.print(f"[bold]Compiled    :[/bold] {fi.compile_timestamp}")
    console.print(f"[bold]SHA256      :[/bold] {result.hashes.sha256}")
    console.print(f"[bold]SHA1        :[/bold] {result.hashes.sha1}")
    console.print(f"[bold]MD5         :[/bold] {result.hashes.md5}")


def print_sections(result: AnalysisResult) -> None:
    if not result.sections:
        console.print("\n[bold]\\[Sections][/bold]\n[dim]No sections found.[/dim]")
        return

    console.print("\n[bold]\\[Sections][/bold]\n")
    table = Table(show_header=True, header_style="bold", box=None, padding=(0, 2, 0, 0))
    table.add_column("Name")
    table.add_column("Raw Size", justify="right")
    table.add_column("Virtual Size", justify="right")
    table.add_column("Perms")
    table.add_column("Entropy", justify="right")
    table.add_column("Classification")

    for section in result.sections:
        entropy_style = "yellow" if section.entropy >= 7.0 else "white"
        table.add_row(
            section.name,
            human_readable_size(section.raw_size),
            human_readable_size(section.virtual_size),
            section.permissions,
            Text(f"{section.entropy:.2f}", style=entropy_style),
            section.classification or "",
        )
    console.print(table)


def print_imports(result: AnalysisResult) -> None:
    if not result.imports:
        console.print("\n[bold]\\[Imports][/bold]\n[dim]No imports found.[/dim]")
        return

    console.print("\n[bold]\\[Imports][/bold]\n")
    for entry in result.imports:
        console.print(f"[bold cyan]{entry.library}[/bold cyan]")
        for func in entry.functions:
            console.print(f"  {func}")


def print_exports(result: AnalysisResult) -> None:
    console.print("\n[bold]\\[Exports][/bold]\n")
    if not result.exports:
        console.print("[dim]No exports found.[/dim]")
        return
    for exp in result.exports:
        console.print(f"  {exp}")


def print_strings(result: AnalysisResult) -> None:
    console.print("\n[bold]\\[Strings][/bold]\n")
    if not result.strings:
        console.print("[dim]No strings extracted.[/dim]")
        return
    for s in result.strings:
        escaped = s.replace('"', '\\"')
        console.print(f'  "{escaped}"')
    if result.strings_truncated:
        console.print(
            f"\n[dim]Output truncated at {len(result.strings)} strings. "
            f"Use --json for the full data set.[/dim]"
        )


def print_entropy(result: AnalysisResult) -> None:
    console.print("\n[bold]\\[Entropy][/bold]\n")
    if not result.sections:
        console.print("[dim]No sections to analyze.[/dim]")
        return
    table = Table(show_header=True, header_style="bold", box=None, padding=(0, 2, 0, 0))
    table.add_column("Section")
    table.add_column("Entropy", justify="right")
    for section in result.sections:
        style = "yellow" if section.entropy >= 7.0 else "white"
        table.add_row(section.name, Text(f"{section.entropy:.2f}", style=style))
    console.print(table)


def print_capabilities(result: AnalysisResult) -> None:
    console.print("\n[bold]\\[Capabilities][/bold]\n")
    if not result.capabilities:
        console.print("[dim]No recognized capability-indicating APIs found.[/dim]")
        return
    for cap in result.capabilities:
        console.print(f"[bold cyan]{cap.category}[/bold cyan]")
        for api_name in cap.apis:
            console.print(f"  {api_name}")


def print_packaging(result: AnalysisResult) -> None:
    if not result.packaging_notes:
        return
    console.print("\n[bold]\\[Packaging][/bold]\n")
    for note in result.packaging_notes:
        console.print(f"[cyan]ℹ {note}[/cyan]")


def print_overlay(result: AnalysisResult) -> None:
    overlay = result.overlay
    if not overlay or not overlay.get("present"):
        return
    console.print("\n[bold]\\[Overlay][/bold]\n")
    console.print("Present")
    console.print(f"Size : {human_readable_size(overlay['size_bytes'])}")
    ratio = overlay.get("ratio", 0.0)
    console.print(f"Ratio: {ratio:.0%} of file size")


def print_findings(result: AnalysisResult) -> None:
    console.print("\n[bold]\\[Findings][/bold]\n")

    info = [f for f in result.findings if f.severity == "INFO"]
    non_info = [f for f in result.findings if f.severity != "INFO"]

    if not result.findings:
        console.print("[dim]No findings.[/dim]")
    else:
        for f in non_info:
            style = _SEVERITY_STYLE.get(f.severity, "white")
            icon = _SEVERITY_ICON.get(f.severity, "⚠")
            console.print(f"[{style}]{f.severity:<6} {icon} {f.name}[/{style}]")
            console.print(f"  {f.description}")
            if f.evidence:
                console.print("  Evidence:")
                for item in f.evidence:
                    console.print(f"    {item}")
            if f.confidence:
                console.print(f"  Confidence: {f.confidence}")
            console.print()

        for f in info:
            console.print(f"[cyan]{f.severity:<6} {f.name}[/cyan]")

    summary = result.severity_summary()
    console.print()
    console.print("[bold]\\[Summary][/bold]\n")
    console.print(f"Informational findings : {summary.get('INFO', 0)}")
    console.print(f"Low severity            : {summary.get('LOW', 0)}")
    console.print(f"Medium severity         : {summary.get('MEDIUM', 0)}")
    console.print(f"High severity           : {summary.get('HIGH', 0)}")
    if result.assessment_note:
        console.print()
        console.print(f"[dim]{result.assessment_note}[/dim]")


def print_warnings(result: AnalysisResult) -> None:
    if not result.warnings:
        return
    console.print()
    for warning in result.warnings:
        console.print(f"[dim yellow]! {warning}[/dim yellow]")


def print_error(message: str) -> None:
    console.print(f"[bold red]✗ {message}[/bold red]")


def print_full_report(result: AnalysisResult) -> None:
    print_banner()
    print_file_info(result)
    print_sections(result)
    print_imports(result)
    if result.exports:
        print_exports(result)
    print_packaging(result)
    print_overlay(result)
    print_capabilities(result)
    print_findings(result)
    print_warnings(result)
    console.print()


def print_sections_report(
    result: AnalysisResult,
    show_sections: bool,
    show_imports: bool,
    show_exports: bool,
    show_strings: bool,
    show_entropy: bool,
) -> None:
    """Print a report showing only the explicitly requested sections,
    always preceded by the file info header."""
    print_banner()
    print_file_info(result)

    if show_sections:
        print_sections(result)
    if show_imports:
        print_imports(result)
    if show_exports:
        print_exports(result)
    if show_entropy:
        print_entropy(result)
    if show_strings:
        print_strings(result)

    print_warnings(result)
    console.print()

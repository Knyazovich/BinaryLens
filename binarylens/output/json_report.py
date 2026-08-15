"""JSON report generation.

Produces the same information shown in the terminal, structured for
machine consumption. Never fabricates fields -- omissions are left as
empty lists/objects rather than placeholder data.
"""

from __future__ import annotations

import json
from dataclasses import asdict

from binarylens.models import AnalysisResult


def build_report_dict(result: AnalysisResult) -> dict:
    return {
        "tool": "BinaryLens",
        "version": "1.0.0",
        "file": asdict(result.file_info),
        "hashes": asdict(result.hashes),
        "headers": result.headers,
        "sections": [asdict(s) for s in result.sections],
        "imports": {entry.library: entry.functions for entry in result.imports},
        "exports": result.exports,
        "strings": result.strings,
        "strings_truncated": result.strings_truncated,
        "packaging": {
            "notes": result.packaging_notes,
        },
        "overlay": result.overlay,
        "analysis": {
            "capabilities": [
                {"category": c.category, "apis": c.apis} for c in result.capabilities
            ],
            "findings": [
                {
                    "severity": f.severity,
                    "name": f.name,
                    "description": f.description,
                    "evidence": f.evidence,
                    "confidence": f.confidence,
                    "details": f.details,
                }
                for f in result.findings
            ],
            "severity_summary": result.severity_summary(),
            "assessment_note": result.assessment_note,
        },
        "warnings": result.warnings,
    }


def write_json_report(result: AnalysisResult, output_path: str) -> None:
    report = build_report_dict(result)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)


def report_to_json_string(result: AnalysisResult) -> str:
    return json.dumps(build_report_dict(result), indent=2, ensure_ascii=False)

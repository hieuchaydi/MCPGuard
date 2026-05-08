from __future__ import annotations

import json
from pathlib import Path

from mcpguard.models import Report


def _serialize_report(report: Report) -> dict:
    data = report.model_dump(mode="json")
    data["score"] = report.score
    data["status"] = report.status
    data["findings"] = [f.model_dump(mode="json") for f in report.all_findings]
    return data


def print_json_report(report: Report, output: Path | None = None) -> None:
    payload = _serialize_report(report)
    formatted = json.dumps(payload, indent=2)
    if output:
        output.write_text(formatted + "\n", encoding="utf-8")
        return
    print(formatted)

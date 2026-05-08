from __future__ import annotations

import json
from pathlib import Path

from mcpguard.models import Report
from mcpguard.risk import fail_threshold_reached, summarize_tool


def build_json_report(report: Report, fail_on: str = "high") -> dict:
    tools = [summarize_tool(tool.tool_name, tool.findings) for tool in report.tools]
    summary = report.severity_summary
    return {
        "target": report.server_command,
        "status": "fail" if fail_threshold_reached(report.all_findings, fail_on) else "pass",
        "overall_risk_level": report.overall_risk_level,
        "summary": {
            "tools_tested": len(report.tools),
            "findings": len(report.all_findings),
            "critical": summary["critical"],
            "high": summary["high"],
            "medium": summary["medium"],
            "low": summary["low"],
        },
        "tools": tools,
    }


def print_json_report(report: Report, output: Path | None = None, fail_on: str = "high") -> None:
    payload = build_json_report(report, fail_on=fail_on)
    formatted = json.dumps(payload, indent=2)
    if output:
        output.write_text(formatted + "\n", encoding="utf-8")
        return
    print(formatted)

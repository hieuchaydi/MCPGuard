from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from mcpguard.models import Report
from mcpguard.risk import explain_finding, finding_severity, recommendation_for_rule

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"


def _sarif_level(severity: str) -> str:
    return {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
    }.get(severity, "note")


def _rule_metadata(report: Report) -> list[dict[str, Any]]:
    seen: set[str] = set()
    rules: list[dict[str, Any]] = []
    for finding in report.all_findings:
        if finding.rule in seen:
            continue
        seen.add(finding.rule)
        explanation = explain_finding(finding)
        rules.append(
            {
                "id": finding.rule,
                "name": finding.rule.replace("_", " ").title(),
                "shortDescription": {"text": recommendation_for_rule(finding.rule)},
                "fullDescription": {"text": explanation["why_this_matters"]},
                "help": {
                    "text": (
                        f"{explanation['why_this_matters']}\n\n"
                        f"Attack path: {explanation['attack_path']}\n\n"
                        f"Remediation: {explanation['remediation']}"
                    )
                },
                "properties": {
                    "security-severity": str(
                        {
                            "critical": 9.5,
                            "high": 8.0,
                            "medium": 5.0,
                            "low": 2.0,
                        }[finding_severity(finding)]
                    )
                },
            }
        )
    return rules


def build_sarif_report(report: Report) -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    for finding in report.all_findings:
        severity = finding_severity(finding)
        explanation = explain_finding(finding)
        results.append(
            {
                "ruleId": finding.rule,
                "level": _sarif_level(severity),
                "message": {
                    "text": (
                        f"{finding.message} Remediation: {explanation['remediation']}"
                    )
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": report.server_command},
                            "region": {"startLine": 1},
                        },
                        "logicalLocations": [
                            {
                                "name": finding.tool_name,
                                "kind": "function",
                            }
                        ],
                    }
                ],
                "properties": {
                    "tool_name": finding.tool_name,
                    "severity": severity,
                    "attack_path": explanation["attack_path"],
                    "possible_consequences": explanation["possible_consequences"],
                },
            }
        )

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "MCPGuard",
                        "informationUri": "https://github.com/hieuchaydi/MCPGuard",
                        "rules": _rule_metadata(report),
                    }
                },
                "results": results,
            }
        ],
    }


def print_sarif_report(report: Report, output: Path | None = None) -> None:
    payload = build_sarif_report(report)
    formatted = json.dumps(payload, indent=2)
    if output:
        output.write_text(formatted + "\n", encoding="utf-8")
        return
    print(formatted)

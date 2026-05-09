from __future__ import annotations

from mcpguard.models import Finding, Report, Severity, ToolReport
from mcpguard.report.sarif_report import build_sarif_report


def test_sarif_report_contains_rules_and_results():
    report = Report(
        server_command="python examples/vulnerable_server/server.py",
        tools=[
            ToolReport(
                tool_name="prompt_bait",
                findings=[
                    Finding(
                        tool_name="prompt_bait",
                        rule="prompt_injection_in_output",
                        severity=Severity.HIGH,
                        message="Tool output contains prompt-injection style instructions.",
                    )
                ],
            )
        ],
    )

    payload = build_sarif_report(report)

    assert payload["version"] == "2.1.0"
    run = payload["runs"][0]
    assert run["tool"]["driver"]["name"] == "MCPGuard"
    assert run["tool"]["driver"]["rules"][0]["id"] == "prompt_injection_in_output"
    result = run["results"][0]
    assert result["ruleId"] == "prompt_injection_in_output"
    assert result["level"] == "error"
    assert result["locations"][0]["logicalLocations"][0]["name"] == "prompt_bait"

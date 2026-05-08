from __future__ import annotations

from rich.console import Console

from mcpguard.models import Finding, Report, Severity, ToolReport
from mcpguard.report.terminal import print_terminal_report


def test_terminal_report_includes_severity_labels():
    report = Report(
        server_command="python server.py",
        tools=[
            ToolReport(
                tool_name="demo",
                findings=[
                    Finding(
                        tool_name="demo",
                        rule="path_outside_allowlist",
                        severity=Severity.LOW,
                        message="outside path",
                    )
                ],
            )
        ],
    )
    console = Console(record=True, width=120)
    print_terminal_report(report, console=console)
    output = console.export_text()
    assert "OVERALL RISK" in output.upper()
    assert "[HIGH]" in output
    assert "path_outside_allowlist" in output

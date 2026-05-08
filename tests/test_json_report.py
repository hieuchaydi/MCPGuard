from __future__ import annotations

from mcpguard.models import Finding, Report, Severity, ToolReport
from mcpguard.report.json_report import build_json_report


def test_json_report_structure_is_stable():
    report = Report(
        server_command="python examples/vulnerable_server/server.py",
        tools=[
            ToolReport(
                tool_name="read_file",
                findings=[
                    Finding(
                        tool_name="read_file",
                        rule="path_outside_allowlist",
                        severity=Severity.LOW,
                        message="outside scope",
                    )
                ],
            )
        ],
    )
    payload = build_json_report(report, fail_on="high")

    assert set(payload.keys()) == {"target", "status", "overall_risk_level", "summary", "tools"}
    assert payload["target"] == "python examples/vulnerable_server/server.py"
    assert payload["status"] == "fail"
    assert payload["overall_risk_level"] == "high"

    summary = payload["summary"]
    assert summary["tools_tested"] == 1
    assert summary["findings"] == 1
    assert summary["critical"] == 0
    assert summary["high"] == 1
    assert summary["medium"] == 0
    assert summary["low"] == 0

    tool = payload["tools"][0]
    assert tool["name"] == "read_file"
    assert tool["status"] == "fail"
    assert tool["risk_level"] == "high"
    assert tool["risk_score"] == 7
    assert tool["findings"][0]["rule"] == "path_outside_allowlist"
    assert tool["findings"][0]["severity"] == "high"
    assert "recommendation" in tool["findings"][0]


def test_json_report_status_respects_fail_on_threshold():
    report = Report(
        server_command="python server.py",
        tools=[
            ToolReport(
                tool_name="demo",
                findings=[
                    Finding(
                        tool_name="demo",
                        rule="timeout_exceeded",
                        severity=Severity.HIGH,
                        message="slow",
                    )
                ],
            )
        ],
    )
    assert build_json_report(report, fail_on="high")["status"] == "pass"
    assert build_json_report(report, fail_on="medium")["status"] == "fail"

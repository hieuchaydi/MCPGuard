from __future__ import annotations

from mcpguard.cli import _enforce_fail_gate
from mcpguard.models import Finding, Report, Severity, ToolReport


def _report_with(rule: str, severity: Severity) -> Report:
    return Report(
        server_command="python server.py",
        tools=[
            ToolReport(
                tool_name="tool",
                findings=[Finding(tool_name="tool", rule=rule, severity=severity, message="x")],
            )
        ],
    )


def test_cli_fail_on_low_fails_for_low_or_above():
    report = _report_with("number_missing_minimum", Severity.LOW)
    assert _enforce_fail_gate(report, "low") is True


def test_cli_fail_on_medium_fails_for_medium_or_above():
    report = _report_with("timeout_exceeded", Severity.MEDIUM)
    assert _enforce_fail_gate(report, "medium") is True
    assert _enforce_fail_gate(report, "high") is False


def test_cli_fail_on_high_fails_for_high_or_critical():
    report = _report_with("path_outside_allowlist", Severity.LOW)
    assert _enforce_fail_gate(report, "high") is True
    assert _enforce_fail_gate(report, "critical") is False


def test_cli_fail_on_critical_only_fails_on_critical():
    report = _report_with("secret_leaked", Severity.LOW)
    assert _enforce_fail_gate(report, "critical") is True

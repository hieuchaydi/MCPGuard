from __future__ import annotations

from mcpguard.models import Finding, Report, Severity, ToolReport
from mcpguard.risk import (
    fail_threshold_reached,
    finding_severity,
    finding_risk_score,
    risk_level_from_findings,
    risk_score_from_findings,
    summarize_tool,
    trust_classification,
)


def _finding(rule: str, severity: Severity, message: str = "msg") -> Finding:
    return Finding(tool_name="tool", rule=rule, severity=severity, message=message)


def test_rule_severity_mapping_overrides_finding_severity():
    finding = _finding("prompt_injection_in_description", Severity.HIGH)
    assert finding_severity(finding) == "medium"


def test_rule_severity_mapping_for_required_rules():
    assert finding_severity(_finding("secret_leaked", Severity.LOW)) == "critical"
    assert finding_severity(_finding("path_outside_allowlist", Severity.LOW)) == "high"
    assert finding_severity(_finding("timeout_exceeded", Severity.HIGH)) == "medium"
    assert finding_severity(_finding("missing_schema", Severity.LOW)) == "medium"
    assert finding_severity(_finding("schema_invalid", Severity.LOW)) == "high"


def test_risk_score_calculation_weights():
    findings = [
        _finding("secret_leaked", Severity.CRITICAL),
        _finding("path_matches_denylist", Severity.HIGH),
        _finding("timeout_exceeded", Severity.MEDIUM),
        _finding("number_missing_minimum", Severity.LOW),
    ]
    assert risk_score_from_findings(findings) >= 99
    assert finding_risk_score(findings[0]) >= 90


def test_risk_level_calculation_uses_highest_severity():
    findings = [
        _finding("number_missing_minimum", Severity.LOW),
        _finding("timeout_exceeded", Severity.MEDIUM),
        _finding("path_outside_allowlist", Severity.HIGH),
    ]
    assert risk_level_from_findings(findings) == "high"


def test_fail_on_threshold_behavior():
    findings = [_finding("timeout_exceeded", Severity.MEDIUM)]
    assert fail_threshold_reached(findings, "low") is True
    assert fail_threshold_reached(findings, "medium") is True
    assert fail_threshold_reached(findings, "high") is False
    assert fail_threshold_reached(findings, "critical") is False

    critical_findings = [_finding("secret_leaked", Severity.LOW)]
    assert fail_threshold_reached(critical_findings, "critical") is True


def test_report_overall_risk_and_status():
    report = Report(
        server_command="python server.py",
        tools=[
            ToolReport(tool_name="a", findings=[_finding("secret_leaked", Severity.CRITICAL)]),
            ToolReport(tool_name="b", findings=[]),
        ],
    )
    assert report.overall_risk_level == "critical"
    assert report.status == "fail"
    assert report.trust_classification == "blocked"


def test_summarize_tool_includes_explainable_risk_fields():
    finding = _finding("prompt_injection_in_output", Severity.HIGH, "unsafe output")
    summary = summarize_tool("tool", [finding])

    assert summary["risk_score"] >= 70
    assert summary["trust_classification"] in {"untrusted", "blocked"}
    assert summary["findings"][0]["risk"]["impact"] == "high"
    assert summary["findings"][0]["risk"]["exploitability"] == "high"
    assert "why_this_matters" in summary["findings"][0]["explanation"]
    assert "attack_path" in summary["findings"][0]["explanation"]


def test_trust_classification_thresholds():
    assert trust_classification(0) == "trusted"
    assert trust_classification(20) == "review"
    assert trust_classification(40) == "restricted"
    assert trust_classification(70) == "untrusted"
    assert trust_classification(90) == "blocked"

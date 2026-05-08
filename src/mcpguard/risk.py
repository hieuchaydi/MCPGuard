from __future__ import annotations

from collections import Counter
from typing import Any

NORMALIZED_SEVERITIES = ("low", "medium", "high", "critical")
SEVERITY_ORDER = {name: index for index, name in enumerate(NORMALIZED_SEVERITIES)}
SEVERITY_WEIGHTS = {
    "low": 1,
    "medium": 4,
    "high": 7,
    "critical": 10,
}

RULE_SEVERITY_MAP = {
    "secret_leaked": "critical",
    "path_matches_denylist": "high",
    "path_outside_allowlist": "high",
    "prompt_injection_in_output": "high",
    "prompt_injection_in_description": "medium",
    "timeout_exceeded": "medium",
    "schema_invalid": "high",
    "missing_schema": "medium",
    # Backward-compatible aliases for existing rule names.
    "missing_input_schema": "medium",
}

RULE_RECOMMENDATIONS = {
    "missing_tool_name": "Add explicit tool names for stable selection and auditing.",
    "missing_description": "Write clear tool descriptions to guide agent behavior.",
    "description_too_short": "Expand descriptions with intent, constraints, and safe usage.",
    "missing_input_schema": "Define a complete inputSchema for every tool.",
    "missing_schema": "Define a complete inputSchema for every tool.",
    "schema_invalid": "Fix invalid input schema definitions and bounds.",
    "no_properties_defined": "Declare input properties with strict type constraints.",
    "missing_required_declaration": "Declare required fields in inputSchema.required.",
    "property_missing_type": "Add explicit type annotations for each input property.",
    "number_missing_maximum": "Set maximum bounds for numeric inputs.",
    "number_missing_minimum": "Set minimum bounds for numeric inputs.",
    "string_missing_maxlength": "Set maxLength for string inputs.",
    "bounded_field_missing_maximum": "Add maximum constraints to limit/count/page fields.",
    "allows_additional_properties": "Set additionalProperties to false.",
    "stack_trace_exposed": "Return sanitized errors without stack traces.",
    "fuzz_server_crash": "Handle malformed input defensively to prevent crashes.",
    "poor_error_message": "Return actionable validation errors for malformed input.",
    "secret_leaked": "Mask secrets and remove sensitive fields from outputs.",
    "timeout_exceeded": "Reduce latency or optimize tool execution path.",
    "slow_response": "Profile and optimize tool performance.",
    "fuzz_timeout": "Ensure invalid input fails fast with clear errors.",
    "path_outside_allowlist": "Restrict file access to explicit allow_paths.",
    "path_matches_denylist": "Block denied paths and return sanitized authorization errors.",
    "prompt_injection_in_description": "Remove instruction-like text from tool descriptions.",
    "prompt_injection_in_output": "Sanitize tool outputs to prevent instruction injection.",
    "no_tools_discovered": "Verify MCP server startup and tool registration.",
    "tool_not_found": "Check tool naming or remove incompatible --tool filter.",
    "connection_error": "Ensure the target server can start and accept MCP connections.",
}


def _severity_value(value: Any) -> str:
    if hasattr(value, "value"):
        return str(value.value)
    return str(value)


def normalize_severity(*, rule: str, fallback: Any) -> str:
    mapped = RULE_SEVERITY_MAP.get(rule)
    if mapped:
        return mapped

    fallback_str = _severity_value(fallback)
    value = fallback_str.strip().lower()
    if value == "warning":
        return "low"
    if value in SEVERITY_ORDER:
        return value
    return "low"


def finding_severity(finding: Any) -> str:
    return normalize_severity(rule=finding.rule, fallback=finding.severity)


def highest_severity(severities: list[str]) -> str | None:
    if not severities:
        return None
    return max(severities, key=lambda severity: SEVERITY_ORDER.get(severity, 0))


def risk_level_from_findings(findings: list[Any]) -> str:
    levels = [finding_severity(f) for f in findings]
    return highest_severity(levels) or "low"


def risk_score_from_findings(findings: list[Any]) -> int:
    return sum(SEVERITY_WEIGHTS[finding_severity(f)] for f in findings)


def severity_counts(findings: list[Any]) -> dict[str, int]:
    counts = Counter(finding_severity(f) for f in findings)
    return {
        "critical": counts["critical"],
        "high": counts["high"],
        "medium": counts["medium"],
        "low": counts["low"],
    }


def fail_threshold_reached(findings: list[Any], threshold: str) -> bool:
    normalized_threshold = threshold.strip().lower()
    if normalized_threshold not in SEVERITY_ORDER:
        return False
    current = highest_severity([finding_severity(f) for f in findings])
    if not current:
        return False
    return SEVERITY_ORDER[current] >= SEVERITY_ORDER[normalized_threshold]


def recommendation_for_rule(rule: str) -> str:
    return RULE_RECOMMENDATIONS.get(rule, f"Investigate rule: {rule}")


def summarize_tool(name: str, findings: list[Any]) -> dict[str, Any]:
    risk_level = risk_level_from_findings(findings)
    return {
        "name": name,
        "status": "pass" if not findings else "fail",
        "risk_level": risk_level,
        "risk_score": risk_score_from_findings(findings),
        "findings": [
            {
                "rule": finding.rule,
                "severity": finding_severity(finding),
                "message": finding.message,
                "recommendation": recommendation_for_rule(finding.rule),
            }
            for finding in findings
        ],
    }

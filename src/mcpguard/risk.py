from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from functools import reduce
from operator import mul
from typing import Any

NORMALIZED_SEVERITIES = ("low", "medium", "high", "critical")
SEVERITY_ORDER = {name: index for index, name in enumerate(NORMALIZED_SEVERITIES)}
SEVERITY_WEIGHTS = {
    "low": 1,
    "medium": 4,
    "high": 7,
    "critical": 10,
}

TRUST_THRESHOLDS = (
    (90, "blocked"),
    (70, "untrusted"),
    (40, "restricted"),
    (20, "review"),
    (0, "trusted"),
)


@dataclass(frozen=True)
class RuleProfile:
    severity: str
    impact: str
    impact_score: int
    exploitability: str
    exploitability_score: int
    confidence: float
    why_this_matters: str
    attack_path: str
    consequences: list[str]
    remediation: str
    tags: tuple[str, ...] = ()

    @property
    def risk_score(self) -> int:
        severity_score = SEVERITY_WEIGHTS[self.severity] * 10
        weighted = (
            severity_score * 0.45
            + self.impact_score * 0.35
            + self.exploitability_score * 0.20
        )
        return max(0, min(100, round(weighted * self.confidence)))


DEFAULT_PROFILE = RuleProfile(
    severity="low",
    impact="low",
    impact_score=25,
    exploitability="low",
    exploitability_score=25,
    confidence=0.65,
    why_this_matters="This finding weakens tool reliability or makes agent behavior harder to audit.",
    attack_path="An agent calls the tool with normal or malformed input and receives unsafe or ambiguous behavior.",
    consequences=["Reduced trust in automated agent decisions.", "Harder incident triage and policy enforcement."],
    remediation="Review the finding and add explicit validation, bounds, or safe failure behavior.",
    tags=("reliability",),
)

RULE_PROFILES: dict[str, RuleProfile] = {
    "secret_leaked": RuleProfile(
        severity="critical",
        impact="critical",
        impact_score=100,
        exploitability="high",
        exploitability_score=85,
        confidence=0.95,
        why_this_matters="Tool output exposes credential-like material that an agent may log, summarize, or pass to another tool.",
        attack_path="An attacker triggers the tool with broad or debug-oriented input, then captures returned secrets from the agent transcript or CI artifact.",
        consequences=["Credential theft.", "Lateral movement into connected services.", "Long-lived secret exposure in logs."],
        remediation="Remove secret-bearing fields from responses, mask debug output, and rotate any exposed credentials.",
        tags=("secret", "exfiltration", "data-loss"),
    ),
    "path_matches_denylist": RuleProfile(
        severity="high",
        impact="high",
        impact_score=80,
        exploitability="high",
        exploitability_score=80,
        confidence=0.95,
        why_this_matters="The tool accepted a path explicitly marked as forbidden by policy.",
        attack_path="An agent or attacker supplies a denylisted path such as .env or ~/.ssh and the tool returns or acts on it.",
        consequences=["Sensitive local file disclosure.", "Policy bypass.", "Credential exposure."],
        remediation="Reject denylisted paths before filesystem access and return sanitized authorization errors.",
        tags=("filesystem", "policy-bypass"),
    ),
    "path_outside_allowlist": RuleProfile(
        severity="high",
        impact="high",
        impact_score=80,
        exploitability="medium",
        exploitability_score=70,
        confidence=0.96,
        why_this_matters="The tool crossed its declared filesystem trust boundary.",
        attack_path="A path-like argument points outside allow_paths and the tool reads or exposes the resolved target.",
        consequences=["Unauthorized file disclosure.", "Unsafe agent access to host context.", "CI workspace leakage."],
        remediation="Canonicalize paths and enforce allow_paths before opening files.",
        tags=("filesystem", "trust-boundary"),
    ),
    "prompt_injection_in_output": RuleProfile(
        severity="high",
        impact="high",
        impact_score=78,
        exploitability="high",
        exploitability_score=82,
        confidence=0.95,
        why_this_matters="Tool output can become instructions for the next model step.",
        attack_path="The agent calls the tool, receives hidden or explicit instructions, and may treat the returned text as trusted context.",
        consequences=["Agent instruction hijacking.", "Secret exfiltration through follow-up tools.", "Policy bypass."],
        remediation="Sanitize untrusted output and separate data from instructions in downstream prompts.",
        tags=("prompt-injection", "agent-control"),
    ),
    "prompt_injection_in_description": RuleProfile(
        severity="medium",
        impact="medium",
        impact_score=55,
        exploitability="medium",
        exploitability_score=55,
        confidence=0.80,
        why_this_matters="Tool descriptions influence agent planning and tool choice.",
        attack_path="A malicious server registers a tool whose description asks the agent to ignore higher-priority instructions.",
        consequences=["Unsafe tool selection.", "Instruction confusion.", "Reduced policy adherence."],
        remediation="Remove imperative or instruction-like text from tool metadata.",
        tags=("prompt-injection", "metadata"),
    ),
    "timeout_exceeded": RuleProfile(
        severity="medium",
        impact="medium",
        impact_score=55,
        exploitability="medium",
        exploitability_score=60,
        confidence=0.90,
        why_this_matters="Slow tools can stall agent workflows and exhaust CI or orchestration budgets.",
        attack_path="The agent calls a tool with normal input and waits beyond the configured timeout.",
        consequences=["Agent denial of service.", "Worker starvation.", "Unreliable automation."],
        remediation="Add hard execution deadlines, cancellation support, and bounded input sizes.",
        tags=("availability", "timeout"),
    ),
    "schema_invalid": RuleProfile(
        severity="high",
        impact="medium",
        impact_score=65,
        exploitability="medium",
        exploitability_score=60,
        confidence=0.85,
        why_this_matters="Invalid schemas prevent agents and validators from reasoning about safe inputs.",
        attack_path="The agent sends values that appear valid to the model but are rejected, coerced, or mishandled by the tool.",
        consequences=["Runtime failures.", "Unexpected type coercion.", "Unsafe fallback behavior."],
        remediation="Publish valid JSON Schema with explicit types, required fields, and bounds.",
        tags=("schema", "contract"),
    ),
    "missing_schema": RuleProfile(
        severity="medium",
        impact="medium",
        impact_score=50,
        exploitability="medium",
        exploitability_score=50,
        confidence=0.80,
        why_this_matters="Without an input schema, agents cannot reliably constrain tool arguments.",
        attack_path="The agent guesses parameters and sends overly broad, malformed, or unsafe values.",
        consequences=["Tool crashes.", "Ambiguous behavior.", "Policy gaps in CI."],
        remediation="Define a complete inputSchema for every tool.",
        tags=("schema", "contract"),
    ),
}
RULE_PROFILES["missing_input_schema"] = RULE_PROFILES["missing_schema"]

RULE_SEVERITY_MAP = {rule: profile.severity for rule, profile in RULE_PROFILES.items()}

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


def profile_for_rule(rule: str, fallback: Any = "low") -> RuleProfile:
    profile = RULE_PROFILES.get(rule)
    if profile:
        return profile
    severity = normalize_severity(rule=rule, fallback=fallback)
    return RuleProfile(
        severity=severity,
        impact=severity,
        impact_score=SEVERITY_WEIGHTS[severity] * 10,
        exploitability="low" if severity == "low" else "medium",
        exploitability_score=35 if severity == "low" else 55,
        confidence=DEFAULT_PROFILE.confidence,
        why_this_matters=DEFAULT_PROFILE.why_this_matters,
        attack_path=DEFAULT_PROFILE.attack_path,
        consequences=DEFAULT_PROFILE.consequences,
        remediation=recommendation_for_rule(rule),
        tags=DEFAULT_PROFILE.tags,
    )


def finding_risk_score(finding: Any) -> int:
    return profile_for_rule(finding.rule, getattr(finding, "severity", "low")).risk_score


def _combine_scores(scores: list[int]) -> int:
    if not scores:
        return 0
    safe_factors = [1 - (max(0, min(100, score)) / 100) for score in scores]
    combined = 1 - reduce(mul, safe_factors, 1.0)
    return max(0, min(100, round(combined * 100)))


def trust_classification(score: int) -> str:
    bounded = max(0, min(100, score))
    for threshold, classification in TRUST_THRESHOLDS:
        if bounded >= threshold:
            return classification
    return "trusted"


def highest_severity(severities: list[str]) -> str | None:
    if not severities:
        return None
    return max(severities, key=lambda severity: SEVERITY_ORDER.get(severity, 0))


def risk_level_from_findings(findings: list[Any]) -> str:
    levels = [finding_severity(f) for f in findings]
    return highest_severity(levels) or "low"


def risk_score_from_findings(findings: list[Any]) -> int:
    return _combine_scores([finding_risk_score(f) for f in findings])


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


def explain_finding(finding: Any) -> dict[str, Any]:
    profile = profile_for_rule(finding.rule, getattr(finding, "severity", "low"))
    return {
        "why_this_matters": profile.why_this_matters,
        "attack_path": profile.attack_path,
        "possible_consequences": profile.consequences,
        "remediation": profile.remediation,
    }


def risk_factors_for_finding(finding: Any) -> dict[str, Any]:
    profile = profile_for_rule(finding.rule, getattr(finding, "severity", "low"))
    return {
        "risk_score": profile.risk_score,
        "confidence": profile.confidence,
        "impact": profile.impact,
        "impact_score": profile.impact_score,
        "exploitability": profile.exploitability,
        "exploitability_score": profile.exploitability_score,
        "trust_classification": trust_classification(profile.risk_score),
        "tags": list(profile.tags),
    }


def summarize_tool(name: str, findings: list[Any]) -> dict[str, Any]:
    risk_level = risk_level_from_findings(findings)
    risk_score = risk_score_from_findings(findings)
    return {
        "name": name,
        "status": "pass" if not findings else "fail",
        "risk_level": risk_level,
        "risk_score": risk_score,
        "trust_classification": trust_classification(risk_score),
        "findings": [
            {
                "rule": finding.rule,
                "severity": finding_severity(finding),
                "message": finding.message,
                "recommendation": recommendation_for_rule(finding.rule),
                "risk": risk_factors_for_finding(finding),
                "explanation": explain_finding(finding),
            }
            for finding in findings
        ],
    }

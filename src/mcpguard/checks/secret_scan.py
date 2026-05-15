from __future__ import annotations

import re

from mcpguard.models import Finding, Severity


def _compile_pattern(pattern: str) -> re.Pattern[str]:
    try:
        return re.compile(pattern, re.IGNORECASE)
    except re.error:
        return re.compile(re.escape(pattern), re.IGNORECASE)


def scan_for_secrets(
    tool_name: str, response_text: str, patterns: list[str]
) -> list[Finding]:
    findings: list[Finding] = []
    seen_patterns: set[str] = set()
    for pattern in patterns:
        if pattern in seen_patterns:
            continue
        seen_patterns.add(pattern)
        if _compile_pattern(pattern).search(response_text):
            findings.append(
                Finding(
                    tool_name=tool_name,
                    severity=Severity.CRITICAL,
                    rule="secret_leaked",
                    message="Response matches a configured sensitive pattern.",
                )
            )
    return findings

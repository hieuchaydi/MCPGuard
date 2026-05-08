from __future__ import annotations

import re

from mcpguard.models import Finding, Severity


def scan_for_secrets(
    tool_name: str, response_text: str, patterns: list[str]
) -> list[Finding]:
    findings: list[Finding] = []
    for pattern in patterns:
        if re.search(pattern, response_text, re.IGNORECASE):
            findings.append(
                Finding(
                    tool_name=tool_name,
                    severity=Severity.CRITICAL,
                    rule="secret_leaked",
                    message=f"Response matches sensitive pattern: {pattern}",
                )
            )
    return findings

from __future__ import annotations

import asyncio
import json
import re
from collections.abc import Mapping
from typing import Any

from mcpguard.checks.timeout_check import build_minimal_valid_input
from mcpguard.config import MCPGuardConfig
from mcpguard.models import Finding, Severity

PROMPT_INJECTION_PATTERNS = [
    r"\bignore\s+(all\s+)?previous\s+instructions?\b",
    r"\boverride\s+(the\s+)?system\s+prompt\b",
    r"\breveal\s+(the\s+)?system\s+prompt\b",
    r"\b(send|return|print|exfiltrate|leak|dump)\b.{0,60}\b(secret|secrets|token|tokens|api[\s_-]?key|api[\s_-]?keys|env[\s_-]?var|environment\s+variable|credential|credentials)\b",
    r"\b(do\s+not|don't)\s+(tell|show|reveal)\s+the\s+user\b",
    r"\bbypass\s+(safety|policy|guardrails?)\b",
    r"\bhidden\s+instructions?\b",
    r"\b(system|developer)\s+message\b.{0,80}\b(ignore|override|follow|execute)\b",
]


def _get_attr(tool: Any, key: str, default: Any = None) -> Any:
    if isinstance(tool, Mapping):
        return tool.get(key, default)
    return getattr(tool, key, default)


def _response_to_text(response: Any) -> str:
    if response is None:
        return ""
    if isinstance(response, str):
        return response
    if isinstance(response, (int, float, bool)):
        return str(response)
    if isinstance(response, Mapping):
        return json.dumps(response, default=str)
    if isinstance(response, list):
        return json.dumps(response, default=str)

    chunks: list[str] = []
    data = getattr(response, "data", None)
    if data is not None:
        try:
            chunks.append(json.dumps(data, default=str))
        except TypeError:
            chunks.append(str(data))

    structured = getattr(response, "structured_content", None)
    if structured is None:
        structured = getattr(response, "structuredContent", None)
    if structured is not None:
        try:
            chunks.append(json.dumps(structured, default=str))
        except TypeError:
            chunks.append(str(structured))

    content = getattr(response, "content", None)
    if isinstance(content, list):
        for item in content:
            text = getattr(item, "text", None)
            if text:
                chunks.append(str(text))
            elif item is not None:
                chunks.append(str(item))

    if not chunks:
        chunks.append(str(response))
    return "\n".join(chunks)


def detect_prompt_injection_phrases(text: str) -> list[str]:
    matches: list[str] = []
    for pattern in PROMPT_INJECTION_PATTERNS:
        if re.search(pattern, text, flags=re.IGNORECASE | re.DOTALL):
            matches.append(pattern)
    return matches


def check_prompt_injection_description(tool: Any, config: MCPGuardConfig) -> list[Finding]:
    policy = config.checks.prompt_injection
    if not policy.enabled or not policy.scan_description:
        return []

    tool_name = str(_get_attr(tool, "name", "") or "<unknown>")
    description = str(_get_attr(tool, "description", "") or "")
    matches = detect_prompt_injection_phrases(description)
    if not matches:
        return []

    return [
        Finding(
            tool_name=tool_name,
            severity=Severity.HIGH,
            rule="prompt_injection_in_description",
            message="Tool description contains prompt-injection style instructions.",
        )
    ]


async def check_prompt_injection_output(tool: Any, client: Any, config: MCPGuardConfig) -> list[Finding]:
    policy = config.checks.prompt_injection
    if not policy.enabled or not policy.scan_output:
        return []

    tool_name = str(_get_attr(tool, "name", "") or "<unknown>")
    payload = build_minimal_valid_input(tool)
    timeout_seconds = config.timeout.timeout_ms / 1000

    try:
        try:
            call = client.call_tool(tool_name, payload, raise_on_error=False)
        except TypeError:
            call = client.call_tool(tool_name, payload)
        response = await asyncio.wait_for(call, timeout=timeout_seconds)
    except Exception:  # noqa: BLE001
        return []

    response_text = _response_to_text(response)
    matches = detect_prompt_injection_phrases(response_text)
    if not matches:
        return []

    return [
        Finding(
            tool_name=tool_name,
            severity=Severity.HIGH,
            rule="prompt_injection_in_output",
            message="Tool output contains prompt-injection style instructions.",
        )
    ]

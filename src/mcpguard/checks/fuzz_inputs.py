from __future__ import annotations

import asyncio
import json
import re
from collections.abc import Mapping
from typing import Any

from mcpguard.config import MCPGuardConfig
from mcpguard.checks.secret_scan import scan_for_secrets
from mcpguard.checks.timeout_check import build_minimal_valid_input
from mcpguard.models import Finding, Severity

STACK_TRACE_PATTERNS = [
    r"Traceback \(most recent call last\)",
    r"\bat Object\.",
    r"File \"[^\"]+\", line \d+",
]

CRASH_PATTERNS = [
    "broken pipe",
    "connection reset",
    "connection closed",
    "eof",
    "process terminated",
    "transport closed",
]


def _get_attr(tool: Any, key: str, default: Any = None) -> Any:
    if isinstance(tool, Mapping):
        return tool.get(key, default)
    return getattr(tool, key, default)


def _input_schema(tool: Any) -> dict[str, Any] | None:
    schema = _get_attr(tool, "inputSchema")
    if schema is None:
        schema = _get_attr(tool, "input_schema")
    if isinstance(schema, Mapping):
        return dict(schema)
    return None


def _append_unique_payload(payloads: list[dict], payload: dict) -> None:
    key = json.dumps(payload, sort_keys=True, default=str)
    existing = {json.dumps(item, sort_keys=True, default=str) for item in payloads}
    if key not in existing:
        payloads.append(payload)


def _type_names(value: Any) -> set[str]:
    if isinstance(value, str):
        return {value}
    if isinstance(value, list):
        return {item for item in value if isinstance(item, str)}
    return set()


def generate_fuzz_inputs(tool: Any) -> list[dict]:
    """Generate harmless malformed inputs for resilience testing."""
    inputs: list[dict] = [{}]
    schema = _input_schema(tool)
    if not schema or not isinstance(schema.get("properties"), Mapping):
        return inputs

    props = schema["properties"]
    base_payload = build_minimal_valid_input(tool)
    extra_payload = dict(base_payload)
    extra_payload["__mcpguard_unexpected"] = "unexpected"
    _append_unique_payload(inputs, extra_payload)

    for name, prop_schema_raw in props.items():
        if not isinstance(prop_schema_raw, Mapping):
            continue
        field_types = _type_names(prop_schema_raw.get("type"))

        def mutated(value: Any, field_name: str = str(name)) -> dict:
            payload = dict(base_payload)
            payload[field_name] = value
            return payload

        if "string" in field_types:
            _append_unique_payload(inputs, mutated(12345))
            _append_unique_payload(inputs, mutated(""))
            _append_unique_payload(inputs, mutated(None))
        elif field_types & {"number", "integer"}:
            _append_unique_payload(inputs, mutated(-1))
            _append_unique_payload(inputs, mutated(0))
            _append_unique_payload(inputs, mutated(999999))
            _append_unique_payload(inputs, mutated("not_a_number"))
        elif "boolean" in field_types:
            _append_unique_payload(inputs, mutated("true"))
            _append_unique_payload(inputs, mutated(1))
        elif "array" in field_types:
            _append_unique_payload(inputs, mutated([]))
            _append_unique_payload(inputs, mutated("not_array"))

    return inputs


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


def _contains_stack_trace(text: str) -> bool:
    if any(re.search(pattern, text) for pattern in STACK_TRACE_PATTERNS):
        return True
    if "Error:" in text and ("/" in text or "\\" in text):
        return True
    return False


def _is_poor_error_message(text: str) -> bool:
    normalized = text.strip().lower()
    if not normalized:
        return True
    generic = {
        "error",
        "failed",
        "invalid input",
        "invalid",
        "bad request",
        "exception",
    }
    if normalized in generic:
        return True
    return len(normalized) < 15


def _is_likely_server_crash(error_text: str) -> bool:
    lower = error_text.lower()
    return any(p in lower for p in CRASH_PATTERNS)


def _add_unique(findings: list[Finding], finding: Finding) -> None:
    key = (finding.rule, finding.message, finding.tool_name)
    existing = {(f.rule, f.message, f.tool_name) for f in findings}
    if key not in existing:
        findings.append(finding)


async def _call_tool_safely(client: Any, tool_name: str, payload: dict) -> Any:
    try:
        return await client.call_tool(tool_name, payload, raise_on_error=False)
    except TypeError:
        return await client.call_tool(tool_name, payload)


async def check_fuzz_inputs(tool: Any, client: Any, config: MCPGuardConfig) -> list[Finding]:
    findings: list[Finding] = []
    tool_name = str(_get_attr(tool, "name", "") or "<unknown>")
    timeout_seconds = config.timeout.timeout_ms / 1000

    for payload in generate_fuzz_inputs(tool):
        try:
            response = await asyncio.wait_for(
                _call_tool_safely(client, tool_name, payload), timeout=timeout_seconds
            )
            response_text = _response_to_text(response)

            is_error = bool(getattr(response, "is_error", False))
            if not is_error:
                is_error = bool(getattr(response, "isError", False))

            if is_error and _is_poor_error_message(response_text):
                _add_unique(
                    findings,
                    Finding(
                        tool_name=tool_name,
                        severity=Severity.MEDIUM,
                        rule="poor_error_message",
                        message="Error response is too generic or empty.",
                    ),
                )

            if _contains_stack_trace(response_text):
                _add_unique(
                    findings,
                    Finding(
                        tool_name=tool_name,
                        severity=Severity.HIGH,
                        rule="stack_trace_exposed",
                        message="Tool error output appears to include a stack trace.",
                    ),
                )

            if config.secret.enabled:
                for finding in scan_for_secrets(
                    tool_name=tool_name,
                    response_text=response_text,
                    patterns=config.secret.patterns,
                ):
                    _add_unique(findings, finding)

        except asyncio.TimeoutError:
            _add_unique(
                findings,
                Finding(
                    tool_name=tool_name,
                    severity=Severity.HIGH,
                    rule="fuzz_timeout",
                    message=f"Fuzz call exceeded timeout of {config.timeout.timeout_ms}ms.",
                ),
            )
        except Exception as exc:  # noqa: BLE001
            error_text = str(exc)

            if _is_likely_server_crash(error_text):
                _add_unique(
                    findings,
                    Finding(
                        tool_name=tool_name,
                        severity=Severity.CRITICAL,
                        rule="fuzz_server_crash",
                        message="Server appears to crash or disconnect on fuzz input.",
                    ),
                )
            if _contains_stack_trace(error_text):
                _add_unique(
                    findings,
                    Finding(
                        tool_name=tool_name,
                        severity=Severity.HIGH,
                        rule="stack_trace_exposed",
                        message="Exception output appears to include a stack trace.",
                    ),
                )
            if _is_poor_error_message(error_text):
                _add_unique(
                    findings,
                    Finding(
                        tool_name=tool_name,
                        severity=Severity.MEDIUM,
                        rule="poor_error_message",
                        message="Error response is too generic or empty.",
                    ),
                )

            if config.secret.enabled:
                for finding in scan_for_secrets(
                    tool_name=tool_name,
                    response_text=error_text,
                    patterns=config.secret.patterns,
                ):
                    _add_unique(findings, finding)

    return findings

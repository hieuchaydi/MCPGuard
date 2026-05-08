from __future__ import annotations

import asyncio
import time
from collections.abc import Mapping
from typing import Any

from mcpguard.config import TimeoutPolicy
from mcpguard.models import Finding, Severity


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


def _value_from_schema(schema: dict[str, Any]) -> Any:
    if "default" in schema:
        return schema["default"]
    examples = schema.get("examples")
    if isinstance(examples, list) and examples:
        return examples[0]
    enum = schema.get("enum")
    if isinstance(enum, list) and enum:
        return enum[0]

    field_type = schema.get("type")
    if field_type == "string":
        return "x"
    if field_type == "integer":
        return 1
    if field_type == "number":
        return 1
    if field_type == "boolean":
        return False
    if field_type == "array":
        return []
    if field_type == "object":
        return {}
    return None


def build_minimal_valid_input(tool: Any) -> dict[str, Any]:
    schema = _input_schema(tool)
    if not schema:
        return {}

    properties = schema.get("properties")
    if not isinstance(properties, Mapping):
        return {}

    required = schema.get("required", [])
    if not isinstance(required, list):
        required = []

    payload: dict[str, Any] = {}
    for name in required:
        prop = properties.get(name)
        if isinstance(prop, Mapping):
            payload[name] = _value_from_schema(dict(prop))

    if not payload:
        for name, prop in properties.items():
            if isinstance(prop, Mapping):
                value = _value_from_schema(dict(prop))
                if value is not None:
                    payload[name] = value
                    break

    return payload


async def check_timeout(tool: Any, client: Any, policy: TimeoutPolicy) -> list[Finding]:
    findings: list[Finding] = []
    tool_name = str(_get_attr(tool, "name", "") or "<unknown>")
    valid_input = build_minimal_valid_input(tool)

    start = time.monotonic()
    try:
        try:
            call = client.call_tool(tool_name, valid_input, raise_on_error=False)
        except TypeError:
            call = client.call_tool(tool_name, valid_input)
        await asyncio.wait_for(
            call, timeout=policy.timeout_ms / 1000
        )
        elapsed_ms = (time.monotonic() - start) * 1000
        if elapsed_ms > policy.warn_after_ms:
            findings.append(
                Finding(
                    tool_name=tool_name,
                    severity=Severity.WARNING,
                    rule="slow_response",
                    message=(
                        f"Tool took {elapsed_ms:.0f}ms "
                        f"(warn threshold: {policy.warn_after_ms}ms)"
                    ),
                )
            )
    except asyncio.TimeoutError:
        findings.append(
            Finding(
                tool_name=tool_name,
                severity=Severity.HIGH,
                rule="timeout_exceeded",
                message=f"Tool exceeded timeout of {policy.timeout_ms}ms",
            )
        )
    except Exception:
        # Timeout checker should not fail the entire run if a single probe errors.
        return findings

    return findings

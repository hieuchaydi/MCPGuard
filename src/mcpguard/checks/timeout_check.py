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


def _type_names(value: Any) -> set[str]:
    if isinstance(value, str):
        return {value}
    if isinstance(value, list):
        return {item for item in value if isinstance(item, str)}
    return set()


def _bounded_number(schema: dict[str, Any], *, integer: bool) -> int | float:
    candidate: int | float = 1

    minimum = schema.get("minimum")
    if isinstance(minimum, (int, float)):
        candidate = max(candidate, minimum)

    exclusive_minimum = schema.get("exclusiveMinimum")
    if isinstance(exclusive_minimum, (int, float)):
        candidate = max(candidate, exclusive_minimum + 1)

    maximum = schema.get("maximum")
    if isinstance(maximum, (int, float)) and candidate > maximum:
        candidate = maximum

    exclusive_maximum = schema.get("exclusiveMaximum")
    if isinstance(exclusive_maximum, (int, float)) and candidate >= exclusive_maximum:
        candidate = exclusive_maximum - 1

    if integer:
        return int(candidate)
    return candidate


def _value_from_schema(schema: dict[str, Any], *, depth: int = 0) -> Any:
    if "default" in schema:
        return schema["default"]
    if "const" in schema:
        return schema["const"]
    examples = schema.get("examples")
    if isinstance(examples, list) and examples:
        return examples[0]
    enum = schema.get("enum")
    if isinstance(enum, list) and enum:
        return enum[0]

    field_types = _type_names(schema.get("type"))
    if "string" in field_types:
        min_length = schema.get("minLength", 1)
        max_length = schema.get("maxLength")
        if not isinstance(min_length, int) or min_length < 0:
            min_length = 1
        length = max(1, min_length)
        if isinstance(max_length, int):
            length = min(length, max_length)
        return "x" * max(0, length)
    if "integer" in field_types:
        return _bounded_number(schema, integer=True)
    if "number" in field_types:
        return _bounded_number(schema, integer=False)
    if "boolean" in field_types:
        return False
    if "array" in field_types:
        min_items = schema.get("minItems", 0)
        if not isinstance(min_items, int) or min_items < 0:
            min_items = 0
        item_schema = schema.get("items")
        if depth >= 3 or not isinstance(item_schema, Mapping):
            return []
        item_value = _value_from_schema(dict(item_schema), depth=depth + 1)
        return [item_value for _ in range(min_items)]
    if "object" in field_types:
        if depth >= 3:
            return {}
        properties = schema.get("properties")
        required = schema.get("required", [])
        if not isinstance(properties, Mapping) or not isinstance(required, list):
            return {}
        payload: dict[str, Any] = {}
        for name in required:
            prop = properties.get(name)
            if isinstance(name, str) and isinstance(prop, Mapping):
                payload[name] = _value_from_schema(dict(prop), depth=depth + 1)
        return payload
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
        if isinstance(name, str) and isinstance(prop, Mapping):
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

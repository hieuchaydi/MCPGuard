from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from mcpguard.config import SchemaPolicy
from mcpguard.models import Finding, Severity


def _get_attr(tool: Any, key: str, default: Any = None) -> Any:
    if isinstance(tool, Mapping):
        return tool.get(key, default)
    if hasattr(tool, key):
        return getattr(tool, key)
    return default


def _get_input_schema(tool: Any) -> dict[str, Any] | None:
    schema = _get_attr(tool, "inputSchema")
    if schema is None:
        schema = _get_attr(tool, "input_schema")
    if isinstance(schema, Mapping):
        return dict(schema)
    return None


def check_schema_quality(tool: Any, policy: SchemaPolicy) -> list[Finding]:
    findings: list[Finding] = []
    tool_name = str(_get_attr(tool, "name", "") or "<unknown>")

    if not (_get_attr(tool, "name", "") or "").strip():
        findings.append(
            Finding(
                tool_name=tool_name,
                severity=Severity.MEDIUM,
                rule="missing_tool_name",
                message="Tool has no name.",
            )
        )

    description = (_get_attr(tool, "description", "") or "").strip()
    if policy.require_descriptions:
        if not description:
            findings.append(
                Finding(
                    tool_name=tool_name,
                    severity=Severity.HIGH,
                    rule="missing_description",
                    message="Tool description is missing.",
                )
            )
        elif len(description) < policy.min_description_length:
            findings.append(
                Finding(
                    tool_name=tool_name,
                    severity=Severity.MEDIUM,
                    rule="description_too_short",
                    message=(
                        f"Description is too short ({len(description)} chars), "
                        f"minimum is {policy.min_description_length}."
                    ),
                )
            )

    input_schema = _get_input_schema(tool)
    if policy.require_input_schema and not input_schema:
        findings.append(
            Finding(
                tool_name=tool_name,
                severity=Severity.MEDIUM,
                rule="missing_input_schema",
                message="Tool does not define inputSchema.",
            )
        )
        findings.append(
            Finding(
                tool_name=tool_name,
                severity=Severity.MEDIUM,
                rule="missing_schema",
                message="Tool does not define inputSchema.",
            )
        )
        return findings

    if not input_schema:
        return findings

    properties = input_schema.get("properties")
    if not isinstance(properties, Mapping):
        findings.append(
            Finding(
                tool_name=tool_name,
                severity=Severity.MEDIUM,
                rule="no_properties_defined",
                message="inputSchema.properties is missing or invalid.",
            )
        )
        findings.append(
            Finding(
                tool_name=tool_name,
                severity=Severity.HIGH,
                rule="schema_invalid",
                message="inputSchema is invalid or too permissive.",
            )
        )
        return findings

    required = input_schema.get("required")
    if policy.require_required_fields and not isinstance(required, list):
        findings.append(
            Finding(
                tool_name=tool_name,
                severity=Severity.HIGH,
                rule="missing_required_declaration",
                message="inputSchema.required is missing.",
            )
        )

    for prop_name, prop_schema_raw in properties.items():
        if not isinstance(prop_schema_raw, Mapping):
            findings.append(
                Finding(
                    tool_name=tool_name,
                    severity=Severity.MEDIUM,
                    rule="property_missing_type",
                    message=f"Property '{prop_name}' has invalid schema.",
                )
            )
            continue

        prop_schema = dict(prop_schema_raw)
        prop_type = prop_schema.get("type")
        if not prop_type:
            findings.append(
                Finding(
                    tool_name=tool_name,
                    severity=Severity.MEDIUM,
                    rule="property_missing_type",
                    message=f"Property '{prop_name}' is missing 'type'.",
                )
            )
            continue

        if prop_type in {"number", "integer"}:
            if policy.require_max_for_numbers and "maximum" not in prop_schema:
                findings.append(
                    Finding(
                        tool_name=tool_name,
                        severity=Severity.HIGH,
                        rule="number_missing_maximum",
                        message=f"Numeric property '{prop_name}' is missing 'maximum'.",
                    )
                )
            if "minimum" not in prop_schema:
                findings.append(
                    Finding(
                        tool_name=tool_name,
                        severity=Severity.LOW,
                        rule="number_missing_minimum",
                        message=f"Numeric property '{prop_name}' is missing 'minimum'.",
                    )
                )

        if prop_type == "string" and "maxLength" not in prop_schema:
            findings.append(
                Finding(
                    tool_name=tool_name,
                    severity=Severity.LOW,
                    rule="string_missing_maxlength",
                    message=f"String property '{prop_name}' is missing 'maxLength'.",
                )
            )

        if prop_name in {"limit", "count", "page_size", "max"} and "maximum" not in prop_schema:
            findings.append(
                Finding(
                    tool_name=tool_name,
                    severity=Severity.HIGH,
                    rule="bounded_field_missing_maximum",
                    message=f"Property '{prop_name}' should define a bounded maximum.",
                )
            )

    if input_schema.get("additionalProperties") is not False:
        findings.append(
            Finding(
                tool_name=tool_name,
                severity=Severity.WARNING,
                rule="allows_additional_properties",
                message="inputSchema allows additionalProperties.",
            )
        )

    return findings

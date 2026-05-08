from __future__ import annotations

import asyncio
import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from mcpguard.checks.timeout_check import build_minimal_valid_input
from mcpguard.config import MCPGuardConfig, ToolPolicy
from mcpguard.models import Finding, Severity

PATH_FIELD_KEYWORDS = ("path", "file", "filename", "filepath", "directory", "dir")
PATH_TOKEN_PATTERN = re.compile(
    r'([A-Za-z]:\\[^\s"\'<>|]+|(?:~|/|\.\.?[/\\])[^\s"\'<>|]+)'
)


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


def _normalize_path(path: str) -> str:
    normalized = path.strip().strip("\"'").replace("\\", "/")
    while "//" in normalized:
        normalized = normalized.replace("//", "/")
    if normalized.endswith("/") and len(normalized) > 1:
        normalized = normalized.rstrip("/")
    return normalized.lower()


def _extract_path_fields(tool: Any) -> list[str]:
    schema = _input_schema(tool)
    if not schema:
        return []
    properties = schema.get("properties")
    if not isinstance(properties, Mapping):
        return []

    fields: list[str] = []
    for field_name in properties:
        lowered = str(field_name).lower()
        if any(keyword in lowered for keyword in PATH_FIELD_KEYWORDS):
            fields.append(str(field_name))
    return fields


def _extract_paths_from_text(response_text: str) -> list[str]:
    matches = PATH_TOKEN_PATTERN.findall(response_text)
    unique: list[str] = []
    seen: set[str] = set()
    for match in matches:
        normalized = _normalize_path(match)
        if normalized and normalized not in seen:
            seen.add(normalized)
            unique.append(normalized)
    return unique


def _is_under_prefix(path_value: str, prefix: str) -> bool:
    path_value = _normalize_path(path_value)
    prefix = _normalize_path(prefix)
    return path_value == prefix or path_value.startswith(prefix + "/")


def _is_error_response(response: Any, response_text: str) -> bool:
    if bool(getattr(response, "is_error", False)) or bool(getattr(response, "isError", False)):
        return True

    try:
        parsed = json.loads(response_text)
    except Exception:  # noqa: BLE001
        parsed = None

    if isinstance(parsed, Mapping):
        if parsed.get("ok") is False:
            return True
        if parsed.get("success") is False:
            return True
        if "error" in parsed and parsed.get("ok") is not True:
            return True

    lowered = response_text.lower()
    return any(token in lowered for token in ("permission denied", "not allowed", '"ok": false'))


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


def _outside_probe_path(policy: ToolPolicy) -> str | None:
    candidates = [
        str(Path.cwd() / "README.md"),
        str(Path.cwd() / "pyproject.toml"),
        "../README.md",
    ]
    for candidate in candidates:
        if not policy.allow_paths:
            return candidate
        if not any(_is_under_prefix(candidate, allowed) for allowed in policy.allow_paths):
            return candidate
    return None


def _add_unique(findings: list[Finding], finding: Finding) -> None:
    key = (finding.rule, finding.message, finding.tool_name)
    existing = {(f.rule, f.message, f.tool_name) for f in findings}
    if key not in existing:
        findings.append(finding)


async def _call_tool_safely(client: Any, tool_name: str, payload: dict[str, Any]) -> Any:
    try:
        return await client.call_tool(tool_name, payload, raise_on_error=False)
    except TypeError:
        return await client.call_tool(tool_name, payload)


async def _probe(
    *,
    client: Any,
    tool_name: str,
    payload: dict[str, Any],
    timeout_seconds: float,
) -> tuple[Any | None, str]:
    try:
        response = await asyncio.wait_for(
            _call_tool_safely(client, tool_name, payload), timeout=timeout_seconds
        )
    except Exception:  # noqa: BLE001
        return None, ""
    return response, _response_to_text(response)


async def check_permission_boundary(tool: Any, client: Any, config: MCPGuardConfig) -> list[Finding]:
    tool_name = str(_get_attr(tool, "name", "") or "<unknown>")
    policy = config.tool_policy(tool_name)
    if not policy:
        return []
    if not policy.allow_paths and not policy.deny_paths:
        return []

    path_fields = _extract_path_fields(tool)
    if not path_fields:
        return []

    findings: list[Finding] = []
    timeout_seconds = config.timeout.timeout_ms / 1000
    base_payload = build_minimal_valid_input(tool)

    if policy.deny_paths:
        deny_probe = policy.deny_paths[0]
        for field in path_fields:
            payload = dict(base_payload)
            payload[field] = deny_probe
            response, response_text = await _probe(
                client=client,
                tool_name=tool_name,
                payload=payload,
                timeout_seconds=timeout_seconds,
            )
            if response is None or _is_error_response(response, response_text):
                continue

            returned_paths = _extract_paths_from_text(response_text)
            if deny_probe and (
                any(_is_under_prefix(p, deny_probe) for p in returned_paths)
                or _normalize_path(deny_probe) in _normalize_path(response_text)
            ):
                _add_unique(
                    findings,
                    Finding(
                        tool_name=tool_name,
                        severity=Severity.HIGH,
                        rule="path_matches_denylist",
                        message=(
                            f"Tool accepted denylisted path '{deny_probe}' for field '{field}'."
                        ),
                    ),
                )

    if policy.allow_paths:
        outside_path = _outside_probe_path(policy)
        if outside_path:
            for field in path_fields:
                payload = dict(base_payload)
                payload[field] = outside_path
                response, response_text = await _probe(
                    client=client,
                    tool_name=tool_name,
                    payload=payload,
                    timeout_seconds=timeout_seconds,
                )
                if response is None or _is_error_response(response, response_text):
                    continue

                returned_paths = _extract_paths_from_text(response_text)
                normalized_outside = _normalize_path(outside_path)
                confirmed_outside = normalized_outside in returned_paths or (
                    normalized_outside in _normalize_path(response_text)
                )
                if not confirmed_outside:
                    continue

                if not any(_is_under_prefix(outside_path, allowed) for allowed in policy.allow_paths):
                    _add_unique(
                        findings,
                        Finding(
                            tool_name=tool_name,
                            severity=Severity.HIGH,
                            rule="path_outside_allowlist",
                            message=(
                                f"Tool accessed path outside allowlist: '{outside_path}'"
                                f" via field '{field}'."
                            ),
                        ),
                    )

    return findings

from __future__ import annotations

import json
from dataclasses import dataclass
from types import SimpleNamespace

import pytest

from mcpguard.checks.permission_boundary import check_permission_boundary
from mcpguard.config import MCPGuardConfig


@dataclass
class FakeContent:
    text: str


@dataclass
class FakeResult:
    is_error: bool
    content: list[FakeContent]


class FakeClient:
    def __init__(self, mode: str):
        self.mode = mode

    async def call_tool(self, name: str, payload: dict, raise_on_error: bool = False):  # noqa: ARG002
        path = payload.get("path", "")
        if self.mode == "reject":
            body = {"ok": False, "error": "permission denied", "path": path}
            return FakeResult(is_error=False, content=[FakeContent(json.dumps(body))])

        body = {"ok": True, "path": path, "content": "demo file content"}
        return FakeResult(is_error=False, content=[FakeContent(json.dumps(body))])


def _make_tool() -> SimpleNamespace:
    return SimpleNamespace(
        name="read_file",
        description="Reads files by path.",
        inputSchema={
            "type": "object",
            "properties": {
                "path": {"type": "string", "maxLength": 300},
            },
            "required": ["path"],
            "additionalProperties": False,
        },
    )


def _config() -> MCPGuardConfig:
    return MCPGuardConfig.model_validate(
        {
            "tools": {
                "read_file": {
                    "allow_paths": ["./docs", "./src"],
                    "deny_paths": [".env", "~/.ssh"],
                    "network": False,
                }
            },
            "timeout": {"timeout_ms": 2000},
        }
    )


@pytest.mark.asyncio
async def test_permission_boundary_detects_outside_allowlist_and_denylist():
    findings = await check_permission_boundary(_make_tool(), FakeClient("allow"), _config())
    rules = {f.rule for f in findings}
    assert "path_outside_allowlist" in rules
    assert "path_matches_denylist" in rules


@pytest.mark.asyncio
async def test_permission_boundary_skips_when_tool_rejects_paths():
    findings = await check_permission_boundary(_make_tool(), FakeClient("reject"), _config())
    assert findings == []

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any

import pytest

from mcpguard.checks.fuzz_inputs import check_fuzz_inputs, generate_fuzz_inputs
from mcpguard.config import MCPGuardConfig


@dataclass
class FakeContent:
    text: str


@dataclass
class FakeResult:
    is_error: bool
    content: list[FakeContent]


class FakeClient:
    def __init__(self, behavior: str):
        self.behavior = behavior

    async def call_tool(self, name: str, payload: dict, raise_on_error: bool = False):  # noqa: ARG002
        if self.behavior == "stack_trace":
            return FakeResult(
                is_error=True,
                content=[
                    FakeContent(
                        "Traceback (most recent call last):\n"
                        '  File "/tmp/x.py", line 10, in run\n'
                        "ValueError: boom"
                    )
                ],
            )
        if self.behavior == "poor_error":
            return FakeResult(is_error=True, content=[FakeContent("error")])
        if self.behavior == "crash":
            raise RuntimeError("connection closed by peer")
        if self.behavior == "timeout":
            await asyncio.sleep(0.2)
            return FakeResult(is_error=False, content=[FakeContent("ok")])
        return FakeResult(is_error=False, content=[FakeContent("ok")])


def _make_tool() -> SimpleNamespace:
    return SimpleNamespace(
        name="demo",
        description="demo tool for fuzz testing",
        inputSchema={
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "limit": {"type": "integer"},
                "enabled": {"type": "boolean"},
                "items": {"type": "array"},
            },
            "required": ["query"],
        },
    )


def test_generate_fuzz_inputs_contains_expected_cases():
    payloads = generate_fuzz_inputs(_make_tool())
    assert payloads[0] == {}
    assert {"query": 12345} in payloads
    assert {"query": ""} in payloads
    assert {"limit": 999999} in payloads
    assert {"limit": "not_a_number"} in payloads
    assert {"enabled": "true"} in payloads
    assert {"items": "not_array"} in payloads


@pytest.mark.asyncio
async def test_fuzz_detects_stack_trace_exposure():
    findings = await check_fuzz_inputs(_make_tool(), FakeClient("stack_trace"), MCPGuardConfig())
    assert any(f.rule == "stack_trace_exposed" for f in findings)


@pytest.mark.asyncio
async def test_fuzz_detects_poor_error_message():
    findings = await check_fuzz_inputs(_make_tool(), FakeClient("poor_error"), MCPGuardConfig())
    assert any(f.rule == "poor_error_message" for f in findings)


@pytest.mark.asyncio
async def test_fuzz_detects_crash():
    findings = await check_fuzz_inputs(_make_tool(), FakeClient("crash"), MCPGuardConfig())
    assert any(f.rule == "fuzz_server_crash" for f in findings)


@pytest.mark.asyncio
async def test_fuzz_detects_timeout():
    config = MCPGuardConfig()
    config.timeout.timeout_ms = 20
    findings = await check_fuzz_inputs(_make_tool(), FakeClient("timeout"), config)
    assert any(f.rule == "fuzz_timeout" for f in findings)

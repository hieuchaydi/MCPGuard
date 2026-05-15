from __future__ import annotations

from types import SimpleNamespace

from mcpguard.checks.timeout_check import build_minimal_valid_input


def test_build_minimal_valid_input_respects_basic_schema_bounds():
    tool = SimpleNamespace(
        name="bounded",
        inputSchema={
            "type": "object",
            "properties": {
                "query": {"type": "string", "minLength": 3, "maxLength": 10},
                "limit": {"type": "integer", "minimum": 5, "maximum": 10},
                "items": {
                    "type": "array",
                    "minItems": 2,
                    "items": {"type": "string", "minLength": 2},
                },
            },
            "required": ["query", "limit", "items"],
            "additionalProperties": False,
        },
    )

    assert build_minimal_valid_input(tool) == {
        "query": "xxx",
        "limit": 5,
        "items": ["xx", "xx"],
    }

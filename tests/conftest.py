from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest


@pytest.fixture
def make_tool():
    def _make_tool(
        name: str = "tool",
        description: str = "A valid tool description.",
        input_schema: dict[str, Any] | None = None,
    ) -> SimpleNamespace:
        if input_schema is None:
            input_schema = {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "maxLength": 200},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 100},
                },
                "required": ["query"],
                "additionalProperties": False,
            }
        return SimpleNamespace(name=name, description=description, inputSchema=input_schema)

    return _make_tool

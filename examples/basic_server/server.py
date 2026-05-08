from __future__ import annotations

from typing import Annotated

from fastmcp import FastMCP
from pydantic import Field

mcp = FastMCP("basic-demo-server")


@mcp.tool()
def echo(
    text: Annotated[str, Field(min_length=1, max_length=120, description="Text to echo back")],
    repeat: Annotated[int, Field(ge=1, le=3, description="Repeat count")] = 1,
) -> dict:
    """Echo validated text for MCPGuard smoke testing."""
    return {"ok": True, "result": " ".join([text] * repeat)}


if __name__ == "__main__":
    mcp.run()

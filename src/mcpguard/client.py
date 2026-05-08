from __future__ import annotations

import asyncio
import os
import shlex
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastmcp import Client
from fastmcp.client.transports import NodeStdioTransport, PythonStdioTransport


class MCPConnectionError(Exception):
    pass


def _candidate_targets(command: str) -> list[Any]:
    known_prefixes = ("stdio:", "http://", "https://", "ws://", "wss://")
    if command.startswith(known_prefixes):
        return [command]

    transport = _extract_stdio_transport(command)
    if transport is not None:
        return [transport, command]

    # fastmcp>=3 expects script path/URL/config instead of shell command strings.
    script_path = _extract_script_path(command)
    if script_path is not None:
        return [str(script_path), command]

    return [f"stdio:{command}", command]


def _extract_stdio_transport(command: str) -> Any | None:
    try:
        parts = shlex.split(command, posix=False)
    except ValueError:
        return None
    if not parts:
        return None

    exe = parts[0].strip("\"'")
    exe_name = Path(exe).stem.lower()
    if exe_name in {"python", "python3", "py"} and len(parts) >= 2:
        script = Path(parts[1].strip("\"'"))
        if script.exists() and script.suffix == ".py":
            env = dict(os.environ)
            env.setdefault("FASTMCP_SHOW_SERVER_BANNER", "false")
            env.setdefault("FASTMCP_LOG_LEVEL", "CRITICAL")
            args = [arg.strip("\"'") for arg in parts[2:]]
            return PythonStdioTransport(script_path=script, args=args, env=env)

    if exe_name in {"node", "nodejs"} and len(parts) >= 2:
        script = Path(parts[1].strip("\"'"))
        if script.exists() and script.suffix == ".js":
            env = dict(os.environ)
            env.setdefault("FASTMCP_SHOW_SERVER_BANNER", "false")
            env.setdefault("FASTMCP_LOG_LEVEL", "CRITICAL")
            args = [arg.strip("\"'") for arg in parts[2:]]
            return NodeStdioTransport(script_path=script, args=args, env=env)

    return None


def _extract_script_path(command: str) -> Path | None:
    command = command.strip()
    if not command:
        return None

    direct_path = Path(command.strip("\"'"))
    if direct_path.exists() and direct_path.suffix in {".py", ".js"}:
        return direct_path

    try:
        parts = shlex.split(command, posix=False)
    except ValueError:
        return None
    if len(parts) < 2:
        return None

    exe = parts[0].lower().strip("\"'")
    candidate = Path(parts[1].strip("\"'"))
    if exe in {"python", "python3", "py", "node", "nodejs"} and candidate.exists():
        return candidate
    return None


@asynccontextmanager
async def connect(command: str):
    """
    Connect to an MCP server using fastmcp.Client.

    Raises:
        MCPConnectionError: If server startup or handshake fails.
    """
    last_error: Exception | None = None
    for target in _candidate_targets(command):
        yielded = False
        try:
            async with Client(target) as client:
                yielded = True
                yield client
                return
        except ProcessLookupError as exc:
            raise MCPConnectionError(
                f"Server process terminated during startup: {command}"
            ) from exc
        except Exception as exc:  # noqa: BLE001
            if yielded:
                raise
            last_error = exc
            continue

    raise MCPConnectionError(f"Cannot connect to server: {command}\n{last_error}")


async def discover_tools(client: Any, timeout_seconds: float = 5.0) -> list[Any]:
    """
    Fetch tool list with a dedicated discovery timeout.
    """
    try:
        tools = await asyncio.wait_for(client.list_tools(), timeout=timeout_seconds)
    except asyncio.TimeoutError as exc:
        raise MCPConnectionError(
            f"Timed out after {timeout_seconds:.0f}s while listing tools"
        ) from exc
    return list(tools or [])

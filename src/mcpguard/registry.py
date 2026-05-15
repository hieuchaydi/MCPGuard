from __future__ import annotations

# Used only for command string quoting, not process execution.
import subprocess  # nosec B404
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

DEFAULT_REGISTRY_PATH = Path("mcpguard.servers.yaml")
VALID_FAIL_ON = {"low", "medium", "high", "critical"}


class ManagedServer(BaseModel):
    command: str
    fail_on: str = "high"
    tags: list[str] = Field(default_factory=list)
    notes: str | None = None


class ManagedRegistry(BaseModel):
    servers: dict[str, ManagedServer] = Field(default_factory=dict)


def normalize_fail_on(value: str) -> str:
    normalized = value.strip().lower()
    if normalized not in VALID_FAIL_ON:
        allowed = ", ".join(sorted(VALID_FAIL_ON))
        raise ValueError(f"Invalid fail_on '{value}'. Allowed values: {allowed}")
    return normalized


def load_registry(path: Path | None = None) -> ManagedRegistry:
    path = path or DEFAULT_REGISTRY_PATH
    if not path.exists():
        return ManagedRegistry()

    with path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    if not isinstance(data, dict):
        raise ValueError(f"Registry file must be a mapping: {path}")

    return ManagedRegistry.model_validate(data)


def save_registry(registry: ManagedRegistry, path: Path | None = None) -> Path:
    path = path or DEFAULT_REGISTRY_PATH
    payload = registry.model_dump(mode="python")
    with path.open("w", encoding="utf-8") as f:
        yaml.safe_dump(payload, f, sort_keys=True, allow_unicode=False)
    return path


def upsert_server(
    *,
    name: str,
    command: str,
    fail_on: str = "high",
    tags: list[str] | None = None,
    notes: str | None = None,
    path: Path | None = None,
) -> ManagedServer:
    clean_name = name.strip()
    clean_command = command.strip()
    if not clean_name:
        raise ValueError("Server name cannot be empty.")
    if not clean_command:
        raise ValueError("Server command cannot be empty.")

    registry = load_registry(path)
    server = ManagedServer(
        command=clean_command,
        fail_on=normalize_fail_on(fail_on),
        tags=[t.strip() for t in (tags or []) if t.strip()],
        notes=notes.strip() if notes else None,
    )
    registry.servers[clean_name] = server
    save_registry(registry, path)
    return server


def remove_server(name: str, path: Path | None = None) -> bool:
    registry = load_registry(path)
    clean_name = name.strip()
    if clean_name in registry.servers:
        del registry.servers[clean_name]
        save_registry(registry, path)
        return True
    return False


def get_server(name: str, path: Path | None = None) -> ManagedServer | None:
    registry = load_registry(path)
    return registry.servers.get(name.strip())


def list_servers(path: Path | None = None) -> dict[str, ManagedServer]:
    registry = load_registry(path)
    return dict(sorted(registry.servers.items(), key=lambda item: item[0].lower()))


def import_codex_servers(
    *,
    codex_config_path: Path,
    registry_path: Path | None = None,
    overwrite: bool = False,
) -> dict[str, ManagedServer]:
    import tomllib

    if not codex_config_path.exists():
        raise FileNotFoundError(f"Codex config not found: {codex_config_path}")

    with codex_config_path.open("rb") as f:
        data = tomllib.load(f)

    raw_servers = data.get("mcp_servers", {})
    if not isinstance(raw_servers, dict):
        raise ValueError("Codex config has invalid mcp_servers format.")

    registry = load_registry(registry_path)
    imported: dict[str, ManagedServer] = {}

    for name, raw in raw_servers.items():
        if not isinstance(raw, dict):
            continue
        if name in registry.servers and not overwrite:
            continue

        command = _command_from_codex_server(raw)
        if not command:
            continue

        fail_on = normalize_fail_on(str(raw.get("fail_on", "high")))
        tags = _to_str_list(raw.get("tags"))
        notes = raw.get("notes")
        if notes is not None:
            notes = str(notes)

        server = ManagedServer(command=command, fail_on=fail_on, tags=tags, notes=notes)
        registry.servers[name] = server
        imported[name] = server

    if imported:
        save_registry(registry, registry_path)
    return imported


def _command_from_codex_server(raw: dict[str, Any]) -> str | None:
    command = raw.get("command")
    args = raw.get("args")

    if isinstance(command, str) and command.strip():
        return _join_command(command, args)

    transport = raw.get("transport")
    if isinstance(transport, dict):
        t_command = transport.get("command")
        t_args = transport.get("args")
        if isinstance(t_command, str) and t_command.strip():
            return _join_command(t_command, t_args)

    return None


def _join_command(command: str, args: Any) -> str:
    cmd = command.strip()
    if isinstance(args, list):
        safe_args = [str(arg) for arg in args]
        return subprocess.list2cmdline([cmd, *safe_args]).strip()
    return cmd


def _to_str_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item).strip() for item in value if str(item).strip()]

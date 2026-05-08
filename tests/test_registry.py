from __future__ import annotations

from pathlib import Path

import pytest

from mcpguard.registry import (
    import_codex_servers,
    list_servers,
    load_registry,
    normalize_fail_on,
    remove_server,
    upsert_server,
)


def test_registry_roundtrip(tmp_path: Path):
    registry_file = tmp_path / "servers.yaml"
    assert load_registry(registry_file).servers == {}

    upsert_server(
        name="basic-demo",
        command="python examples/basic_server/server.py",
        fail_on="high",
        tags=["demo", "basic"],
        notes="minimal demo server",
        path=registry_file,
    )

    servers = list_servers(registry_file)
    assert "basic-demo" in servers
    assert servers["basic-demo"].fail_on == "high"
    assert servers["basic-demo"].tags == ["demo", "basic"]
    assert servers["basic-demo"].notes == "minimal demo server"

    assert remove_server("basic-demo", registry_file) is True
    assert remove_server("basic-demo", registry_file) is False


def test_registry_normalize_fail_on():
    assert normalize_fail_on("HIGH") == "high"
    assert normalize_fail_on(" critical ") == "critical"
    with pytest.raises(ValueError):
        normalize_fail_on("urgent")


def test_import_codex_servers(tmp_path: Path):
    codex_config = tmp_path / "codex.toml"
    registry_file = tmp_path / "servers.yaml"
    codex_config.write_text(
        """
[mcp_servers.alpha]
command = "python"
args = ["examples/basic_server/server.py"]
fail_on = "medium"
tags = ["demo"]
notes = "alpha source"

[mcp_servers.beta.transport]
command = "npx"
args = ["-y", "@acme/mcp-server"]
""".strip(),
        encoding="utf-8",
    )

    imported = import_codex_servers(
        codex_config_path=codex_config,
        registry_path=registry_file,
        overwrite=False,
    )
    assert sorted(imported.keys()) == ["alpha", "beta"]

    servers = list_servers(registry_file)
    assert servers["alpha"].command == "python examples/basic_server/server.py"
    assert servers["alpha"].fail_on == "medium"
    assert servers["beta"].command == "npx -y @acme/mcp-server"
    assert servers["beta"].fail_on == "high"

    codex_config.write_text(
        """
[mcp_servers.alpha]
command = "python"
args = ["changed.py"]
fail_on = "critical"
""".strip(),
        encoding="utf-8",
    )
    imported_again = import_codex_servers(
        codex_config_path=codex_config,
        registry_path=registry_file,
        overwrite=False,
    )
    assert imported_again == {}

    imported_overwrite = import_codex_servers(
        codex_config_path=codex_config,
        registry_path=registry_file,
        overwrite=True,
    )
    assert "alpha" in imported_overwrite
    servers = list_servers(registry_file)
    assert servers["alpha"].command == "python changed.py"
    assert servers["alpha"].fail_on == "critical"

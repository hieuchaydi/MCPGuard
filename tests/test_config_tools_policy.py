from __future__ import annotations

from pathlib import Path

from mcpguard.config import load_config


def test_load_config_parses_tools_policy(tmp_path: Path):
    config_file = tmp_path / "mcpguard.yaml"
    config_file.write_text(
        "\n".join(
            [
                "server:",
                "  command: \"python server.py\"",
                "tools:",
                "  read_file:",
                "    allow_paths:",
                "      - \"./docs\"",
                "    deny_paths:",
                "      - \".env\"",
                "    network: false",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    config = load_config(config_file=config_file)
    tool_policy = config.tool_policy("read_file")

    assert tool_policy is not None
    assert tool_policy.allow_paths == ["./docs"]
    assert tool_policy.deny_paths == [".env"]
    assert tool_policy.network is False

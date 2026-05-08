from __future__ import annotations

import asyncio
import json
from textwrap import dedent
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from mcpguard.client import MCPConnectionError
from mcpguard.config import MCPGuardConfig, load_config
from mcpguard.models import Finding, Report, Severity, ToolReport
from mcpguard.registry import (
    DEFAULT_REGISTRY_PATH,
    get_server,
    import_codex_servers,
    list_servers,
    normalize_fail_on,
    remove_server,
    upsert_server,
)
from mcpguard.report.json_report import build_json_report, print_json_report
from mcpguard.report.terminal import print_terminal_report
from mcpguard.risk import fail_threshold_reached
from mcpguard.runner import run

app = typer.Typer(name="mcpguard", help="Test MCP tools before agents trust them.")
mcp_app = typer.Typer(help="Manage and test multiple MCP server targets.")
app.add_typer(mcp_app, name="mcp")

SEVERITY_ORDER = ["low", "medium", "high", "critical"]

DEFAULT_CONFIG_TEMPLATE = dedent(
    """\
    server:
      command: "python examples/basic_server/server.py"

    policy:
      fail_on: "high"

    schema:
      require_input_schema: true
      require_descriptions: true
      require_required_fields: true
      require_max_for_numbers: true
      min_description_length: 10

    timeout:
      timeout_ms: 10000
      warn_after_ms: 3000

    secret:
      enabled: true
      patterns:
        - "OPENAI_API_KEY"
        - "token="

    tools:
      read_file:
        allow_paths:
          - "./docs"
          - "./src"
        deny_paths:
          - ".env"
          - "~/.ssh"
        network: false

    checks:
      prompt_injection:
        enabled: true
        scan_description: true
        scan_output: true
    """
)


def _validate_format(value: str) -> str:
    normalized = value.lower().strip()
    if normalized not in {"terminal", "json"}:
        raise typer.BadParameter("format must be one of: terminal, json")
    return normalized


def _enforce_fail_gate(report: Report, threshold: str) -> bool:
    return fail_threshold_reached(report.all_findings, threshold)


def _connection_error_report(command: str, exc: Exception) -> Report:
    return Report(
        server_command=command,
        tools=[
            ToolReport(
                tool_name="__server__",
                findings=[
                    Finding(
                        tool_name="__server__",
                        severity=Severity.CRITICAL,
                        rule="connection_error",
                        message=str(exc),
                    )
                ],
            )
        ],
    )


def _render_report(
    report: Report,
    format: str,
    output: Path | None = None,
    fail_on: str = "high",
) -> None:
    if format == "json":
        print_json_report(report, output, fail_on=fail_on)
    else:
        print_terminal_report(report)


def _run_scan(config: MCPGuardConfig, tool: str | None = None) -> Report:
    try:
        return asyncio.run(run(config, only_tool=tool))
    except MCPConnectionError as exc:
        raise typer.Exit(code=2) from exc


@app.callback()
def main() -> None:
    """MCPGuard command group."""


@app.command("init")
def init_config(
    output: Path = typer.Option(Path("mcpguard.yaml"), "--output", help="Output config path"),
    force: bool = typer.Option(False, "--force", help="Overwrite if file already exists"),
) -> None:
    """Create a starter MCPGuard policy file."""
    if output.exists() and not force:
        raise typer.BadParameter(f"Config already exists: {output}. Use --force to overwrite.")
    output.write_text(DEFAULT_CONFIG_TEMPLATE, encoding="utf-8")
    typer.echo(f"Wrote starter config to {output}")


@app.command()
def test(
    command: str | None = typer.Option(None, "--command", "-c", help="MCP server command"),
    config_file: Path | None = typer.Option(None, "--config", help="Path to mcpguard.yaml"),
    tool: str | None = typer.Option(None, "--tool", help="Test only this tool"),
    format: str = typer.Option("terminal", "--format", help="terminal | json"),
    output: Path | None = typer.Option(None, "--output", help="Write report to file"),
    fail_on: str | None = typer.Option(None, "--fail-on", help="Exit code 1 if severity >= this"),
) -> None:
    """Run contract tests against an MCP server."""
    format = _validate_format(format)
    config = load_config(config_file, command, fail_on)
    if not config.server_command:
        raise typer.BadParameter("Missing server command. Use --command or set server.command in config.")

    try:
        report = _run_scan(config, tool=tool)
    except typer.Exit:
        typer.echo(f"Connection error: cannot connect to server: {config.server_command}", err=True)
        raise

    _render_report(report, format, output, fail_on=config.fail_on)
    if _enforce_fail_gate(report, config.fail_on):
        raise typer.Exit(code=1)


@mcp_app.command("add")
def mcp_add(
    name: str = typer.Argument(..., help="Saved MCP target name"),
    command: str = typer.Option(..., "--command", "-c", help="MCP server command"),
    fail_on: str = typer.Option("high", "--fail-on", help="Default severity gate for this target"),
    tag: list[str] = typer.Option(None, "--tag", help="Tag to categorize target (repeatable)"),
    notes: str | None = typer.Option(None, "--notes", help="Optional notes"),
    registry_file: Path = typer.Option(DEFAULT_REGISTRY_PATH, "--registry", help="Registry YAML path"),
) -> None:
    """Add or update a saved MCP target."""
    fail_on = normalize_fail_on(fail_on)
    server = upsert_server(
        name=name,
        command=command,
        fail_on=fail_on,
        tags=tag or [],
        notes=notes,
        path=registry_file,
    )
    typer.echo(
        f"Saved target '{name}' -> command='{server.command}', fail_on='{server.fail_on}' "
        f"({registry_file})"
    )


@mcp_app.command("list")
def mcp_list(
    registry_file: Path = typer.Option(DEFAULT_REGISTRY_PATH, "--registry", help="Registry YAML path"),
    format: str = typer.Option("table", "--format", help="table | json"),
) -> None:
    """List saved MCP targets."""
    servers = list_servers(registry_file)
    if not servers:
        typer.echo(f"No saved targets in {registry_file}")
        return

    if format.lower() == "json":
        payload = {
            name: server.model_dump(mode="json")
            for name, server in servers.items()
        }
        typer.echo(json.dumps(payload, indent=2))
        return
    if format.lower() != "table":
        raise typer.BadParameter("format must be one of: table, json")

    table = Table(title=f"MCP Targets ({registry_file})")
    table.add_column("Name", style="bold cyan")
    table.add_column("Fail On")
    table.add_column("Command")
    table.add_column("Tags")
    table.add_column("Notes")
    for name, server in servers.items():
        table.add_row(
            name,
            server.fail_on,
            server.command,
            ", ".join(server.tags),
            server.notes or "",
        )
    Console().print(table)


@mcp_app.command("get")
def mcp_get(
    name: str = typer.Argument(..., help="Saved MCP target name"),
    registry_file: Path = typer.Option(DEFAULT_REGISTRY_PATH, "--registry", help="Registry YAML path"),
) -> None:
    """Show a single saved MCP target."""
    server = get_server(name, registry_file)
    if not server:
        raise typer.BadParameter(f"Target '{name}' not found in {registry_file}")

    payload = server.model_dump(mode="json")
    payload["name"] = name
    typer.echo(json.dumps(payload, indent=2))


@mcp_app.command("remove")
def mcp_remove(
    name: str = typer.Argument(..., help="Saved MCP target name"),
    registry_file: Path = typer.Option(DEFAULT_REGISTRY_PATH, "--registry", help="Registry YAML path"),
) -> None:
    """Remove a saved MCP target."""
    deleted = remove_server(name, registry_file)
    if not deleted:
        raise typer.BadParameter(f"Target '{name}' not found in {registry_file}")
    typer.echo(f"Removed target '{name}' from {registry_file}")


@mcp_app.command("test")
def mcp_test(
    name: str = typer.Argument(..., help="Saved MCP target name"),
    config_file: Path | None = typer.Option(None, "--config", help="Optional policy config"),
    tool: str | None = typer.Option(None, "--tool", help="Test only this tool"),
    format: str = typer.Option("terminal", "--format", help="terminal | json"),
    output: Path | None = typer.Option(None, "--output", help="Write report to file"),
    fail_on: str | None = typer.Option(None, "--fail-on", help="Override target fail-on"),
    registry_file: Path = typer.Option(DEFAULT_REGISTRY_PATH, "--registry", help="Registry YAML path"),
) -> None:
    """Run MCPGuard test against a saved MCP target."""
    format = _validate_format(format)
    target = get_server(name, registry_file)
    if not target:
        raise typer.BadParameter(f"Target '{name}' not found in {registry_file}")

    fail_threshold = fail_on or target.fail_on
    config = load_config(config_file, target.command, fail_threshold)
    report = _run_scan(config, tool=tool)
    _render_report(report, format, output, fail_on=config.fail_on)
    if _enforce_fail_gate(report, config.fail_on):
        raise typer.Exit(code=1)


@mcp_app.command("test-all")
def mcp_test_all(
    config_file: Path | None = typer.Option(None, "--config", help="Optional policy config"),
    tool: str | None = typer.Option(None, "--tool", help="Test only this tool"),
    format: str = typer.Option("terminal", "--format", help="terminal | json"),
    output: Path | None = typer.Option(None, "--output", help="Write combined JSON report to file"),
    fail_on: str | None = typer.Option(None, "--fail-on", help="Override fail-on for all targets"),
    registry_file: Path = typer.Option(DEFAULT_REGISTRY_PATH, "--registry", help="Registry YAML path"),
) -> None:
    """Run MCPGuard tests for all saved MCP targets."""
    format = _validate_format(format)
    targets = list_servers(registry_file)
    if not targets:
        typer.echo(f"No saved targets in {registry_file}")
        return

    combined: list[dict] = []
    any_failed_gate = False

    for name, target in targets.items():
        threshold = fail_on or target.fail_on
        config = load_config(config_file, target.command, threshold)

        try:
            report = _run_scan(config, tool=tool)
        except typer.Exit:
            report = _connection_error_report(
                target.command,
                MCPConnectionError(f"Cannot connect to server: {target.command}"),
            )

        if _enforce_fail_gate(report, config.fail_on):
            any_failed_gate = True

        if format == "terminal":
            typer.echo(f"\n=== {name} ===")
            print_terminal_report(report)

        combined.append(
            {
                "name": name,
                "command": target.command,
                "fail_on": config.fail_on,
                "report": build_json_report(report, fail_on=config.fail_on),
            }
        )

    if format == "json":
        payload = {"targets": combined}
        text = json.dumps(payload, indent=2)
        if output:
            output.write_text(text + "\n", encoding="utf-8")
        else:
            typer.echo(text)

    if any_failed_gate:
        raise typer.Exit(code=1)


@mcp_app.command("import-codex")
def mcp_import_codex(
    codex_config: Path = typer.Option(
        Path.home() / ".codex" / "config.toml",
        "--codex-config",
        help="Path to Codex config.toml",
    ),
    registry_file: Path = typer.Option(DEFAULT_REGISTRY_PATH, "--registry", help="Registry YAML path"),
    overwrite: bool = typer.Option(False, "--overwrite", help="Overwrite existing targets"),
) -> None:
    """Import MCP targets from Codex mcp_servers config."""
    imported = import_codex_servers(
        codex_config_path=codex_config,
        registry_path=registry_file,
        overwrite=overwrite,
    )
    if not imported:
        typer.echo("No targets imported.")
        return
    typer.echo(f"Imported {len(imported)} target(s) into {registry_file}:")
    for name in sorted(imported):
        typer.echo(f"- {name}")


if __name__ == "__main__":
    app()

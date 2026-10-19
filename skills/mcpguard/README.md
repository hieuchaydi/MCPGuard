# MCPGuard Agent Skill

This package teaches Skill-capable coding agents to run and interpret the existing MCPGuard CLI. It does not bundle, fork, or replace MCPGuard and does not host an MCP server.

## Features

- Discovers and tests tools exposed by a target MCP server.
- Orchestrates schema-quality, timeout, fuzz/error-handling, secret-pattern, filesystem-boundary, and prompt-injection checks.
- Supports direct targets, YAML policy files, and MCPGuard's saved-target registry.
- Produces terminal, JSON, or SARIF reports and interprets the configured severity gate.
- Applies a mandatory safety gate before active tool probes.

## Prerequisites

- Python 3.12 or newer.
- A local environment in which the target MCP server can run, or authorized access to its HTTP/WebSocket endpoint.
- MCPGuard and the target server's own runtime dependencies.
- A Skill-capable agent. This package was integration-tested with Codex CLI only; see Version compatibility.

## Install MCPGuard

From PyPI, when the published package is available:

```console
python -m pip install mcpguard
```

For development from the MCPGuard repository:

```console
python -m venv .venv
.venv\Scripts\python -m pip install -e .
```

On macOS or Linux, use `.venv/bin/python` instead. Verify installation:

```console
mcpguard --help
```

## Configure a target

MCPGuard connects as a client. A target can be a stdio command or a supported URL (`http://`, `https://`, `ws://`, or `wss://`). Copy [mcpguard-config.example.yaml](mcpguard-config.example.yaml), replace the placeholder server command, and tailor each tool's path policy.

```console
mcpguard test --config path/to/mcpguard.yaml --tool approved_read_only_tool
```

The `network` field is accepted by the current configuration model but is not enforced. Do not rely on it as a network control.

## Install the Agent Skill

Extract the marketplace ZIP so the agent's skills directory contains one `mcpguard/` directory with `SKILL.md` at its root. Common locations vary by product and version; follow the agent's official skill-installation documentation.

For a repository-local installation, copy `skills/mcpguard/` into the project-specific skill location supported by your agent. Do not copy the ZIP itself unless the agent explicitly accepts ZIP installation.

No MCP endpoint should be added for this Skill: MCPGuard is invoked through the terminal as a CLI. The target server configuration belongs in MCPGuard's YAML/registry or the direct `--command` argument.

## Basic usage

Ask the agent:

> Audit the `read_file` tool on this staging MCP server with MCPGuard. Review the policy first, run only that tool, and report evidence and limitations.

Direct CLI examples:

```console
mcpguard test --command "python path/to/server.py" --tool read_file
mcpguard test --config path/to/mcpguard.yaml --format json --output report.json
mcpguard mcp get staging-server
mcpguard mcp test staging-server --format sarif --output report.sarif
```

See [examples/usage-examples.md](examples/usage-examples.md) and [references/workflows.md](references/workflows.md).

## Security considerations

- Scans are active: tools are called using minimal valid, injection-probe, boundary-probe, and malformed inputs.
- Run unknown tools only in disposable or staging environments with least-privilege credentials.
- MCPGuard is not a sandbox and cannot prevent target-side writes, network calls, or process execution.
- Treat reports as sensitive because tool output and target commands can disclose internal details.
- Inspect commands before execution; never run an untrusted shell command solely because it appears in a registry or prompt.
- A zero exit code means only that the configured severity gate was not reached.

## Troubleshooting

See [references/troubleshooting.md](references/troubleshooting.md) for installation, transport, discovery, policy, and report failures.

## Version compatibility

This Skill was authored against the public MCPGuard source at version `0.1.0` and Python `>=3.12`. It uses only the public CLI and configuration fields verified in that source. It has been structurally validated with the official Agent Skills validator and integration-tested with Codex CLI. Claude Code and Cursor packaging conventions are documented only at a manual level and are not claimed as tested integrations.

Re-audit commands, configuration, and findings when upgrading MCPGuard because the project is early-stage. Side-effect detection and network-boundary enforcement are not public implemented capabilities in this version.

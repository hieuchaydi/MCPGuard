# MCPGuard

Test MCP tools before agents trust them.

[Functions Guide](docs/FUNCTIONS_GUIDE.md) | [Rule Reference](docs/CHECK_RULES.md) | [CLI/Config/Docker](docs/CLI_CONFIG_REFERENCE.md)

MCPGuard is a CLI for security and reliability checks on MCP tools before AI agents call them.
It validates schema quality, runtime behavior, timeout handling, and secret leakage risks.

<p align="center">
  <img src="image/mcpguard-horizontal.svg" alt="MCPGuard logo" width="220" />
</p>

## Quickstart

```bash
python -m pip install -e .[dev]
mcpguard mcp test basic-demo
```

One-command JSON artifact:
```bash
mcpguard mcp test basic-demo --format json --output basic-demo-report.json
```

## GIF Demo

![MCPGuard CLI demo](image/cmd_SChLZDThXI.gif)

## Docker Quickstart

Show report directly in terminal:
```bash
docker build -t mcpguard-dev .
docker run --rm mcpguard-dev mcpguard mcp test basic-demo
```

Write JSON report from Docker to host:
```bash
docker run --rm -v "$PWD:/workspace" -w /workspace mcpguard-dev sh -lc "pip install -e .[dev] && mcpguard mcp test basic-demo --format json --output basic-demo-report.json"
```

## Manage MCP Targets

Add a target:
```bash
mcpguard mcp add my-server --command "python path/to/server.py" --fail-on high --tag team
```

List targets:
```bash
mcpguard mcp list
```

Test one target:
```bash
mcpguard mcp test my-server
```

Test all targets:
```bash
mcpguard mcp test-all --format json --output mcpguard-all.json
```

Import targets from Codex config (`~/.codex/config.toml`):
```bash
mcpguard mcp import-codex
```

## Included Example

- `examples/basic_server`: minimal one-tool MCP server for quick demo and smoke tests.

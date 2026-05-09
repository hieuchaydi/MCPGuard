# MCPGuard CLI, Config, CI, and Docker Reference

This guide explains how to run MCPGuard in day-to-day workflows, manage multiple targets, and integrate in CI.

## 1. CLI Commands

Main scan command:
```bash
mcpguard test [options]
```

Initialize a starter config:
```bash
mcpguard init
```

Target management command group:
```bash
mcpguard mcp <subcommand> [options]
```

Options (`mcpguard test`):
- `--command`, `-c`: MCP server command (for example, `python server.py`)
- `--config`: path to `mcpguard.yaml`
- `--tool`: test only one tool by name
- `--format`: `terminal` or `json`
- `--output`: write output file when `--format json`
- `--fail-on`: fail gate threshold (`low|medium|high|critical`)

MCP target subcommands:
- `mcpguard mcp add <name> --command "..."`
- `mcpguard mcp list`
- `mcpguard mcp get <name>`
- `mcpguard mcp remove <name>`
- `mcpguard mcp test <name>`
- `mcpguard mcp test-all`
- `mcpguard mcp import-codex`

Default registry: `mcpguard.servers.yaml` (override with `--registry`).

## 2. Option Priority

Precedence order:
1. CLI overrides (`--command`, `--fail-on`)
2. Values in YAML config
3. Code defaults

## 3. Config Schema

Example `mcpguard.yaml`:

```yaml
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
    - "GROQ_API_KEY"
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
```

Field summary:
- `server.command`: command used to start the MCP server
- `policy.fail_on`: severity gate threshold for process exit code
- `schema.*`: schema quality policy options
- `timeout.timeout_ms`: hard timeout per tool call
- `timeout.warn_after_ms`: warning threshold for slow calls
- `secret.enabled`: enable/disable secret scanning
- `secret.patterns`: regex/literal patterns to scan in responses
- `tools.<tool>.allow_paths`: path allowlist policy for that tool
- `tools.<tool>.deny_paths`: path denylist policy for that tool
- `tools.<tool>.network`: placeholder for network-boundary policy
- `checks.prompt_injection.enabled`: enable/disable prompt injection checks
- `checks.prompt_injection.scan_description`: scan tool description/metadata
- `checks.prompt_injection.scan_output`: scan runtime tool output

## 4. Exit Codes

- `0`: fail gate not reached
- `1`: at least one finding reached/exceeded `fail_on`
- `2`: MCP server connection/discovery failure

Fail gate behavior:
- `--fail-on low`: fail on `low|medium|high|critical`
- `--fail-on medium`: fail on `medium|high|critical`
- `--fail-on high`: fail on `high|critical`
- `--fail-on critical`: fail only on `critical`

## 5. Common Usage Recipes

Quick smoke test:
```bash
mcpguard mcp test basic-demo
```

Run with a direct command:
```bash
mcpguard test --command "python examples/basic_server/server.py"
```

Run with config file:
```bash
mcpguard test --config mcpguard.yaml
```

Test one specific tool:
```bash
mcpguard test --command "python examples/basic_server/server.py" --tool echo
```

JSON to stdout:
```bash
mcpguard mcp test basic-demo --format json
```

JSON to file:
```bash
mcpguard mcp test basic-demo --format json --output basic-demo-report.json
```

Vulnerable demo in JSON:
```bash
mcpguard mcp test vulnerable-demo --config mcpguard.yaml --format json
```

Fail gate example:
```bash
mcpguard mcp test basic-demo --fail-on high
```

## 6. Manage and Test Multiple MCP Targets

Add a target:
```bash
mcpguard mcp add my-server --command "python path/to/server.py" --fail-on high --tag team --notes "team-owned server"
```

List targets:
```bash
mcpguard mcp list
```

Show one target:
```bash
mcpguard mcp get my-server
```

Remove a target:
```bash
mcpguard mcp remove my-server
```

Test one saved target:
```bash
mcpguard mcp test my-server --format terminal
```

Test all saved targets:
```bash
mcpguard mcp test-all --format json --output mcpguard-all.json
```

Quick security demo:
```bash
mcpguard mcp test vulnerable-demo --config mcpguard.yaml --fail-on high
```

Import from Codex config:
```bash
mcpguard mcp import-codex
```

Import from custom config and overwrite existing:
```bash
mcpguard mcp import-codex --codex-config C:/path/to/config.toml --overwrite
```

## 7. Registry File Format

Example `mcpguard.servers.yaml`:

```yaml
servers:
  basic-demo:
    command: python examples/basic_server/server.py
    fail_on: medium
    tags: [demo, quickstart]
    notes: Minimal one-tool server for short demos
  my-server:
    command: python path/to/server.py
    fail_on: high
```

## 8. CI Examples

Basic gate:
```bash
mcpguard test --command "python server.py" --fail-on high
```

Write JSON artifact:
```bash
mcpguard test --command "python server.py" --format json --output mcpguard-report.json --fail-on high
```

A ready workflow is included:
- `.github/workflows/mcpguard.yml`

## 9. JSON Output Contract

`--format json` returns a stable object:

```json
{
  "target": "python examples/basic_server/server.py",
  "status": "pass",
  "overall_risk_level": "low",
  "summary": {
    "tools_tested": 1,
    "findings": 0,
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 0
  },
  "tools": [
    {
      "name": "echo",
      "status": "pass",
      "risk_level": "low",
      "risk_score": 0,
      "findings": []
    }
  ]
}
```

## 10. Docker Reference

Build image:
```bash
docker build -t mcpguard-dev .
```

Run tests:
```bash
docker run --rm mcpguard-dev python -m pytest
```

Run quick terminal demo:
```bash
docker run --rm mcpguard-dev mcpguard mcp test basic-demo
```

Write JSON output file from container to host:
```bash
docker run --rm -v "$PWD:/workspace" -w /workspace mcpguard-dev sh -lc "pip install -e .[dev] && mcpguard mcp test basic-demo --format json --output basic-demo-report.json"
```

Windows `cmd.exe` variant:
```bat
docker run --rm -v "%cd%:/workspace" -w /workspace mcpguard-dev sh -lc "pip install -e .[dev] && mcpguard mcp test basic-demo --format json --output basic-demo-report.json"
```

## 11. Troubleshooting

`Connection error: Could not infer a valid transport`
- Use a supported command format, for example:
  - `python server.py`
  - `node server.js`
  - `http://...` (HTTP transport)

`No saved targets in mcpguard.servers.yaml`
- Add targets with `mcpguard mcp add ...` or recreate the registry.

Terminal encoding issues on Windows
- Use `--format json` and inspect the output file.
- Or run your terminal in UTF-8 mode.

`mcpguard mcp import-codex` imports nothing
- Verify `[mcp_servers]` exists in the Codex config.
- Verify each server has `command` (and optional `args`) or `transport.command`.

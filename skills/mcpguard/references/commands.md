# Verified CLI reference

This reference describes MCPGuard `0.1.0` as implemented in `src/mcpguard/cli.py`. MCPGuard exposes CLI commands, not MCP tools.

## `mcpguard init`

Writes a starter policy file.

- `--output PATH`: destination; defaults to `mcpguard.yaml`.
- `--force`: overwrite an existing file.

Mutation: yes. Do not use `--force` without explicit authorization.

## `mcpguard test`

Runs checks against one target.

- `--command`, `-c TEXT`: target command, script, or supported URL.
- `--config PATH`: YAML policy file.
- `--tool TEXT`: restrict the scan to one exact discovered tool name.
- `--format terminal|json|sarif`: defaults to `terminal`.
- `--output PATH`: writes the report instead of printing it.
- `--fail-on low|medium|high|critical`: overrides the policy gate.

Either `--command` or `server.command` in the config is required. A command-line command and threshold override the corresponding config values.

Example:

```console
mcpguard test --config mcpguard.yaml --tool read_file --format json --output report.json
```

## Saved-target registry

The default registry is `mcpguard.servers.yaml`. Every registry command accepts `--registry PATH`.

### `mcpguard mcp add NAME`

Adds or updates a target. Requires `--command`; accepts `--fail-on`, repeatable `--tag`, and `--notes`. This mutates the registry.

### `mcpguard mcp list`

Lists targets. `--format` is `table` or `json`. This is read-only.

### `mcpguard mcp get NAME`

Prints one target as JSON. This is read-only and should precede a scan.

### `mcpguard mcp remove NAME`

Deletes a target from the registry. This is destructive and requires explicit authorization.

### `mcpguard mcp test NAME`

Tests a saved target. It accepts `--config`, `--tool`, `--format`, `--output`, and `--fail-on`.

### `mcpguard mcp test-all`

Tests every saved target. It accepts the same scan/report options. This can execute many tools and must not be used merely for discovery.

### `mcpguard mcp import-codex`

Imports `[mcp_servers]` entries from Codex configuration into the MCPGuard registry.

- `--codex-config PATH`: defaults to the user's `.codex/config.toml`.
- `--overwrite`: replaces name collisions.

This reads agent configuration and writes the registry. Review for secrets and obtain authorization before use.

## Target forms and transports

The client recognizes target strings beginning with `stdio:`, `http://`, `https://`, `ws://`, or `wss://`. It also recognizes existing Python and Node script paths and commands such as `python server.py` or `node server.js`. Other strings are attempted through FastMCP's client target resolution.

Use absolute script paths when the working directory is uncertain. Do not invent endpoint paths or command flags.

## Exit codes

- `0`: configured severity threshold was not reached, or a registry list/test-all operation had nothing to test.
- `1`: at least one finding met or exceeded the failure threshold.
- `2`: direct scan connection/startup/tool-discovery failure.

Treat incomplete output and connection failures as inconclusive. A zero exit code does not certify safety.

## Report shapes

JSON reports use `schema_version: "0.2"` and contain target, pass/fail status, risk level/score, confidence, trust classification, summary counts, and per-tool findings with recommendation, risk factors, and explanation. SARIF output is version 2.1.0. Terminal output is intended for humans and should not be parsed as a stable machine contract.

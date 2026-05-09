# MCPGuard Functions Guide

This document describes MCPGuard internals and the runtime flow used during scans.

## 1. End-to-End Flow

1. Accept CLI input (`--command` or `--config`).
2. Load policy/config (`load_config`).
3. Connect to MCP server (`connect` in `client.py`).
4. Discover tools (`discover_tools`, 5s discovery timeout).
5. Run checks per tool in order:
   - `check_schema_quality`
   - `check_prompt_injection_description`
   - `check_timeout`
   - `check_prompt_injection_output`
   - `check_permission_boundary`
   - `check_fuzz_inputs` (includes secret scan)
6. Aggregate findings into `Report` / `ToolReport`.
7. Build terminal or JSON output with normalized risk summary.
8. Apply fail gate based on `--fail-on` threshold.

## 2. Core Modules

### 2.1 `src/mcpguard/models.py`

Primary data models:
- `Severity`
- `Finding`
- `ToolReport`
- `Report`

Key behavior:
- Tool-level status, risk level, and risk score are derived from findings.
- Report exposes:
  - `risk_score`
  - `overall_risk_level`
  - `severity_summary`
  - `status`

### 2.2 `src/mcpguard/risk.py`

Central risk engine:
- rule -> normalized severity mapping
- severity weights
- fail-threshold evaluation
- recommendation mapping
- helper serializers for tool-level JSON summaries

Normalized severity set:
- `low`
- `medium`
- `high`
- `critical`

### 2.3 `src/mcpguard/config.py`

Policy models:
- `SchemaPolicy`
- `TimeoutPolicy`
- `SecretPolicy`
- `ToolPolicy`
- `PromptInjectionPolicy`
- `ChecksPolicy`
- `MCPGuardConfig`

Config sources:
- `mcpguard.yaml` (if provided)
- CLI overrides (`--command`, `--fail-on`) take precedence

### 2.4 `src/mcpguard/client.py`

Purpose:
- connect to MCP servers through `fastmcp.Client`
- infer transport from command or URL
- reduce startup noise on stdio transport

Supports:
- `python file.py`
- `node file.js`
- URL transports (`http/https/ws/wss`)
- direct script paths

Errors are wrapped as `MCPConnectionError`.

### 2.5 `src/mcpguard/runner.py`

Orchestration layer:
- initializes `Report(server_command=...)`
- handles discovery edge cases:
  - `tool_not_found`
  - `no_tools_discovered`
- executes all checks for each discovered tool

### 2.6 `src/mcpguard/checks/schema_quality.py`

Purpose:
- validate schema contract quality

Coverage:
- tool name/description/schema presence
- properties/required declarations
- field type correctness
- numeric/string bounds
- bounded fields (`limit|count|page_size|max`)
- `additionalProperties` hardening

### 2.7 `src/mcpguard/checks/prompt_injection.py`

Purpose:
- detect prompt-injection style phrasing in:
  - tool descriptions
  - runtime output

Rules:
- `prompt_injection_in_description`
- `prompt_injection_in_output`

Policy toggles:
- `checks.prompt_injection.enabled`
- `checks.prompt_injection.scan_description`
- `checks.prompt_injection.scan_output`

### 2.8 `src/mcpguard/checks/timeout_check.py`

Purpose:
- measure tool responsiveness with minimal valid inputs

Behavior:
- builds probe payload from schema (`default/examples/enum/type fallback`)
- wraps call in `asyncio.wait_for(timeout_ms)`
- emits:
  - `timeout_exceeded`
  - `slow_response`

### 2.9 `src/mcpguard/checks/permission_boundary.py`

Purpose:
- enforce tool-level path access boundaries

Rules:
- `path_outside_allowlist`
- `path_matches_denylist`

Policy keys:
- `tools.<tool>.allow_paths`
- `tools.<tool>.deny_paths`

### 2.10 `src/mcpguard/checks/fuzz_inputs.py`

Purpose:
- run harmless malformed inputs to test robustness

Detects:
- `fuzz_server_crash`
- `stack_trace_exposed`
- `poor_error_message`
- `fuzz_timeout`
- secret leaks in output/error text

### 2.11 `src/mcpguard/checks/secret_scan.py`

Purpose:
- detect sensitive token/credential patterns in text

Rule:
- `secret_leaked`

### 2.12 `src/mcpguard/report/terminal.py`

Purpose:
- render human-readable terminal summary

Shows:
- overall status
- overall risk level
- severity counts
- per-tool risk level and score
- finding severity labels
- rule-based recommendations

### 2.13 `src/mcpguard/report/json_report.py`

Purpose:
- emit stable machine-readable JSON output for CI/CD

Schema includes:
- target/status/overall_risk_level
- summary counts
- per-tool risk summaries
- per-finding recommendation

### 2.14 `src/mcpguard/cli.py`

Command groups:
- `mcpguard test`
- `mcpguard mcp ...`
- `mcpguard init`

Exit codes:
- `0`: fail gate not reached
- `1`: fail gate reached
- `2`: connection/discovery failure

### 2.15 `src/mcpguard/registry.py`

Purpose:
- manage MCP targets in `mcpguard.servers.yaml`
- CRUD targets for multi-server workflows
- import targets from Codex config (`~/.codex/config.toml`)

Main subcommands:
- `mcpguard mcp add/list/get/remove`
- `mcpguard mcp test`
- `mcpguard mcp test-all`
- `mcpguard mcp import-codex`

## 3. Examples Directory

### `examples/basic_server`
- Minimal one-tool server (`echo`) for quick smoke tests.
- Default demo target for `mcpguard mcp test basic-demo`.

### `examples/vulnerable_server`
- Intentionally unsafe server for failure demos.
- Useful for validating risk summaries and CI fail gates.

## 4. Test Coverage

The suite includes tests for:
- schema quality checks
- timeout checks
- fuzz checks
- prompt injection checks
- permission boundary checks
- secret scan patterns
- risk mapping and scoring
- fail gate thresholds
- JSON output contract
- terminal report rendering labels

Current gap:
- full end-to-end CLI integration tests with real subprocess lifecycle are still limited.

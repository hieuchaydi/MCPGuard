# CI/CD Integration

MCPGuard is designed to run as a lightweight trust gate before agent workflows consume MCP tools.

## GitHub Actions

```yaml
name: MCPGuard

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write

jobs:
  mcpguard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
          cache: pip
      - run: python -m pip install -e .[dev]
      - run: python -m pytest -q
      - run: mcpguard mcp test basic-demo --fail-on high
      - run: mcpguard mcp test basic-demo --format sarif --output mcpguard.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: mcpguard.sarif
```

## Pre-Commit Hook

```yaml
repos:
  - repo: local
    hooks:
      - id: mcpguard-basic-demo
        name: MCPGuard basic demo trust gate
        entry: mcpguard mcp test basic-demo --fail-on high
        language: system
        pass_filenames: false
```

## Exit Code Policy

| Exit code | Meaning |
|---:|---|
| 0 | Scan completed and did not reach the configured fail threshold |
| 1 | Scan completed and reached `--fail-on` threshold |
| 2 | MCP server connection or startup failure |

Recommended production defaults:
- PRs: `--fail-on high`
- protected branches: `--fail-on medium`
- nightly exploit corpus: `--fail-on low`
- SARIF upload: always upload, even when the gate fails

## PR Annotations

SARIF output allows GitHub code scanning to annotate findings. For MCP tools, locations point at the server command and logical location points at the MCP tool name.

JSON output is better for dashboards and policy engines because it includes:
- `risk_score`
- `confidence`
- `impact`
- `exploitability`
- `trust_classification`
- explainable remediation fields

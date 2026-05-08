# MCPGuard CLI, Config, CI, Docker Reference

Tai lieu nay tap trung vao cach van hanh MCPGuard theo luong `basic-demo` va cach quan ly nhieu MCP target.

## 1. CLI Commands

Main scan command:
```bash
mcpguard test [options]
```

Init config:
```bash
mcpguard init
```

Target management command group:
```bash
mcpguard mcp <subcommand> [options]
```

Options (`mcpguard test`):
- `--command`, `-c`: command MCP server (vi du `python server.py`)
- `--config`: duong dan den file YAML config
- `--tool`: chi test 1 tool theo ten
- `--format`: `terminal` hoac `json`
- `--output`: file output khi `--format json`
- `--fail-on`: threshold fail gate (`warning|low|medium|high|critical`)

MCP target subcommands:
- `mcpguard mcp add <name> --command "..."`
- `mcpguard mcp list`
- `mcpguard mcp get <name>`
- `mcpguard mcp remove <name>`
- `mcpguard mcp test <name>`
- `mcpguard mcp test-all`
- `mcpguard mcp import-codex`

Registry mac dinh: `mcpguard.servers.yaml` (co the override bang `--registry`).

## 2. Option Priority

Thu tu uu tien:
1. CLI overrides (`--command`, `--fail-on`)
2. Gia tri trong YAML config
3. Default trong code

## 3. Config Schema

Mau `mcpguard.yaml`:
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
- `server.command`: command de khoi tao MCP server
- `policy.fail_on`: nguong fail gate cho exit code
- `schema.*`: rule chinh cho schema-quality checks
- `timeout.timeout_ms`: hard timeout cho moi tool call
- `timeout.warn_after_ms`: warning threshold cho response cham
- `secret.enabled`: bat/tat secret scan
- `secret.patterns`: regex/literal can scan trong response
- `tools.<tool>.allow_paths`: allowlist path cho tool (permission boundary)
- `tools.<tool>.deny_paths`: denylist path cho tool
- `tools.<tool>.network`: placeholder policy cho network boundary (rule se duoc mo rong tiep)
- `checks.prompt_injection.enabled`: bat/tat prompt injection checks
- `checks.prompt_injection.scan_description`: scan description/metadata truoc runtime probe
- `checks.prompt_injection.scan_output`: scan output sau probe call

## 4. Exit Codes

- `0`: khong vuot nguong fail gate
- `1`: co finding vuot nguong `fail_on`
- `2`: khong ket noi/discovery duoc MCP server

## 5. Common Usage Recipes

Shortest smoke demo:
```bash
mcpguard mcp test basic-demo
```

Test bang command truc tiep:
```bash
mcpguard test --command "python examples/basic_server/server.py"
```

Test bang config:
```bash
mcpguard test --config mcpguard.yaml
```

Chi test 1 tool:
```bash
mcpguard test --command "python examples/basic_server/server.py" --tool echo
```

JSON stdout:
```bash
mcpguard mcp test basic-demo --format json
```

JSON file:
```bash
mcpguard mcp test basic-demo --format json --output basic-demo-report.json
```

Fail gate:
```bash
mcpguard mcp test basic-demo --fail-on high
```

## 6. Manage/Test Multiple MCP Targets

Them target:
```bash
mcpguard mcp add my-server --command "python path/to/server.py" --fail-on high --tag team --notes "team-owned server"
```

List target:
```bash
mcpguard mcp list
```

Xem chi tiet 1 target:
```bash
mcpguard mcp get my-server
```

Xoa target:
```bash
mcpguard mcp remove my-server
```

Test 1 target da luu:
```bash
mcpguard mcp test my-server --format terminal
```

Test toan bo target:
```bash
mcpguard mcp test-all --format json --output mcpguard-all.json
```

Demo fail nhanh voi target co chu y de security:
```bash
mcpguard mcp test vulnerable-demo --config mcpguard.yaml --fail-on high
```

Import target tu Codex config:
```bash
mcpguard mcp import-codex
```

Import voi config custom + overwrite:
```bash
mcpguard mcp import-codex --codex-config C:/path/to/config.toml --overwrite
```

## 7. Registry File Format

Vi du `mcpguard.servers.yaml`:
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

Basic CI gate:
```bash
mcpguard test --command "python server.py" --fail-on high
```

Keep JSON artifact:
```bash
mcpguard test --command "python server.py" --format json --output mcpguard-report.json --fail-on high
```

Repo da co workflow mau:
- `.github/workflows/mcpguard.yml`

## 9. Docker Reference

Build image:
```bash
docker build -t mcpguard-dev .
```

Run tests:
```bash
docker run --rm mcpguard-dev python -m pytest
```

Run quick terminal demo (no output file):
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

## 10. Troubleshooting

`Connection error: Could not infer a valid transport`
- Dung command theo format MCPGuard parse duoc, vi du:
  - `python server.py`
  - `node server.js`
  - `http://...` (neu server transport HTTP)

`No saved targets in mcpguard.servers.yaml`
- Them target qua `mcpguard mcp add ...` hoac tao lai registry file.

Terminal output bi loi encoding tren Windows
- Chuyen qua `--format json` de ghi artifact
- Hoac chay terminal UTF-8

`mcpguard mcp import-codex` khong import duoc target nao
- Kiem tra file Codex config co section `[mcp_servers]`
- Kiem tra moi server co `command` (va optional `args`) hoac `transport.command`

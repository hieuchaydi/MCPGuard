# MCPGuard Functions Guide

Tai lieu nay mo ta chi tiet tung chuc nang cua MCPGuard theo luong runtime that te.

## 1. End-to-End Flow

1. Nhan input tu CLI (`--command` hoac `--config`).
2. Load policy/config (`load_config`).
3. Connect MCP server (`connect` trong `client.py`).
4. Discover tools (`discover_tools`, timeout 5s).
5. Chay checks cho tung tool theo thu tu:
   - `check_schema_quality`
   - `check_timeout`
   - `check_fuzz_inputs` (kem secret scan)
6. Gom findings -> score/status (`Report` model).
7. In terminal report hoac xuat JSON report.
8. Tinh exit code theo `fail_on`.

## 2. Core Modules

### 2.1 `src/mcpguard/models.py`

Model du lieu trung tam:
- `Severity`: `critical`, `high`, `medium`, `low`, `warning`
- `Finding`: 1 vi pham/risk tren 1 tool
- `ToolReport`: findings cua 1 tool
- `Report`: report tong cua server

Logic quan trong:
- Score luon clamp ve `>= 0`.
- Status mapping:
  - `PASS` >= 90
  - `WARN` >= 70
  - `FAIL` >= 50
  - `CRITICAL` < 50

### 2.2 `src/mcpguard/config.py`

Policy models:
- `SchemaPolicy`
- `TimeoutPolicy`
- `SecretPolicy`
- `MCPGuardConfig`

Nguon config:
- `mcpguard.yaml` (neu co)
- CLI overrides (`--command`, `--fail-on`) uu tien cao hon file

Secret patterns:
- Co san cac pattern thuong gap: OpenAI/GitHub/Slack/AWS/token/password/private key
- Co the mo rong them pattern rieng theo to chuc

### 2.3 `src/mcpguard/client.py`

Muc tieu:
- Ket noi MCP server qua `fastmcp.Client`
- Tuong thich command string va script path
- Giam noise banner/log khi khoi tao stdio transport

Chi tiet:
- Ho tro infer transport cho:
  - `python file.py`
  - `node file.js`
  - URL (`http/https/ws/wss`)
  - script path truc tiep
- `discover_tools` co timeout discovery rieng 5 giay
- Loi startup/discovery duoc wrap thanh `MCPConnectionError`

### 2.4 `src/mcpguard/runner.py`

Orchestration:
- Tao `Report(server_command=...)`
- Discover tools
- Xu ly edge cases:
  - Tool filter khong tim thay -> `tool_not_found` (warning)
  - Server tra tool list rong -> `no_tools_discovered` (warning)
- Chay checks cho moi tool va append vao `report.tools`

### 2.5 `src/mcpguard/checks/schema_quality.py`

Muc dich:
- Danh gia contract quality cua tool schema

Diem check:
- Ten tool, description, input schema, properties, required
- Kieu du lieu tung field
- Boundaries cho number/string
- Cac field bounded (`limit/count/page_size/max`)
- `additionalProperties: false`

### 2.6 `src/mcpguard/checks/timeout_check.py`

Muc dich:
- Danh gia response time voi input hop le toi thieu

Cach hoat dong:
- Build payload hop le toi thieu tu schema (`default/examples/enum/type fallback`)
- Call tool voi `asyncio.wait_for(timeout_ms)`
- Sinh finding:
  - `timeout_exceeded` (high)
  - `slow_response` (warning)

### 2.7 `src/mcpguard/checks/fuzz_inputs.py`

Muc dich:
- Thu dau vao sai kieu vo hai de test resilience

Fuzz strategy:
- Luon gom `{}` + payload sai type theo tung field type
- Khong dung payload nguy hiem (khong traversal/shell injection)

Detection:
- `fuzz_server_crash`
- `stack_trace_exposed`
- `poor_error_message`
- `fuzz_timeout`
- Secret scan tren moi response/error text neu `secret.enabled=true`

### 2.8 `src/mcpguard/checks/secret_scan.py`

Muc dich:
- Tim pattern nhay cam trong response text

Output:
- Moi pattern match -> `secret_leaked` (critical)

### 2.9 `src/mcpguard/report/terminal.py`

Chuc nang:
- Header, score bar, status, summary counts
- Group finding theo tool
- Sort tool theo highest severity
- Sinh recommendation theo rule id
- Tu dong fallback ASCII neu terminal khong support glyph unicode

### 2.10 `src/mcpguard/report/json_report.py`

Chuc nang:
- Serialize report sang JSON
- Ho tro in stdout hoac ghi file (`--output`)

### 2.11 `src/mcpguard/cli.py`

Command:
- `mcpguard test ...`

Options:
- `--command/-c`
- `--config`
- `--tool`
- `--format`
- `--output`
- `--fail-on`

Exit code:
- `0`: pass gate
- `1`: vuot gate
- `2`: connection/discovery error

### 2.12 `src/mcpguard/registry.py`

Chuc nang:
- Quan ly danh sach MCP targets trong file YAML (`mcpguard.servers.yaml`).
- CRUD targets (`add/list/get/remove`) cho quy trinh test nhieu server.
- Import targets tu Codex config (`~/.codex/config.toml`).

Data model:
- `ManagedServer`:
  - `command`
  - `fail_on`
  - `tags`
  - `notes`
- `ManagedRegistry`:
  - `servers: dict[name -> ManagedServer]`

CLI lien quan:
- `mcpguard mcp add/list/get/remove`
- `mcpguard mcp test`
- `mcpguard mcp test-all`
- `mcpguard mcp import-codex`

## 3. Examples Directory

### `examples/basic_server`
- Minimal one-tool server (`echo`) de smoke test nhanh.
- La demo mac dinh cho command `mcpguard mcp test basic-demo`.
- Muc tieu: quay video demo ngan va validate luong runtime end-to-end.

## 4. Test Coverage

Hien co test cho:
- schema quality checks
- fuzz input generation va phan ung
- secret scan patterns

Chua co integration test full runner/cli trong test suite.

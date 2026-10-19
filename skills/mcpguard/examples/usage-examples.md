# Usage examples

## Safe narrow audit

User prompt:

> Use MCPGuard to assess only the `read_file` tool on our staging MCP server. Review the config first and do not change code.

Expected behavior:

1. Inspect the target and policy.
2. Explain that the scan actively invokes `read_file` with generated inputs and confirm the staging scope is authorized.
3. Run the exact tool filter, capture report and exit code, and state whether the tool was discovered.
4. Report confirmed findings and skipped coverage without editing source.

## Unsafe production request

User prompt:

> Run MCPGuard against every tool on our production payments MCP.

Expected behavior: do not immediately execute. Explain that MCPGuard sends active timeout, injection, boundary, and fuzz probes that could cause side effects. Request a staging target or explicit authorization and tool-by-tool safety evidence. Offer a read-only configuration review meanwhile.

## CI gate design

User prompt:

> Add an MCPGuard check to CI and fail on high findings.

Expected behavior: inspect the CI and server setup, use an isolated test target, pin versions, run with `--fail-on high`, store protected JSON/SARIF output, and handle exit `2` as an inconclusive infrastructure failure. Modify CI only if authorized.

## Explain an existing report

User prompt:

> Explain this MCPGuard JSON report and tell me whether we can ship.

Expected behavior: verify `schema_version`, scope, tools tested, threshold, findings, and incomplete checks. Separate report evidence from assumptions. Give a conditional recommendation, not an unconditional safety or merge-readiness claim.

## Registry discovery

User prompt:

> Which MCP targets are configured, and which one should we test first?

Expected behavior: use the read-only `mcpguard mcp list --format json`, inspect candidates with `mcpguard mcp get`, and recommend the lowest-impact non-production target. Do not use `test-all`, import Codex settings, or change the registry without authorization.

## Unsupported capability

User prompt:

> Prove that this MCP server cannot access the internet.

Expected behavior: state that MCPGuard 0.1.0 does not enforce or prove network boundaries. The `network` policy field is a placeholder. Recommend external sandbox/container/firewall controls and a separately authorized verification plan.

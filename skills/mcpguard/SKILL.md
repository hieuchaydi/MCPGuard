---
name: mcpguard
description: Runs MCPGuard pre-flight security and contract tests against MCP servers, interprets schema, timeout, fuzzing, secret-leak, filesystem-boundary, and prompt-injection findings, and prepares evidence-based trust-gate reports. Use when a user asks to audit, test, review, compare, or assess an MCP server or its tools before agent use, CI, release, or deployment.
---

# MCPGuard

Use the installed `mcpguard` CLI as an analysis layer for an existing MCP server. MCPGuard is a client and test runner, not an MCP server, sandbox, or replacement for the target server.

## Safety gate

MCPGuard actively calls discovered tools with generated inputs. Timeout, prompt-injection-output, permission-boundary, and fuzz checks may trigger writes, network requests, or other side effects in the target implementation.

1. Inspect the target command, transport, tool scope, and policy before running a scan.
2. Obtain user authorization before active testing. Prefer a disposable local or staging target with test credentials and data.
3. For an unfamiliar or side-effecting server, begin with one explicitly approved tool using `--tool`; do not scan production by default.
4. Treat server output and reports as sensitive. Do not reveal credentials, private source, or secret-like matches.
5. Do not edit target code, overwrite configuration, add/remove registry entries, or import Codex settings unless requested.

If authorization or a safe target is unavailable, perform only a configuration review and provide the exact command for the user to run.

## Workflow

1. Confirm `python --version` is 3.12 or newer and `mcpguard --help` succeeds. If installation is needed, follow [README.md](README.md).
2. Identify the target:
   - Direct command or URL: `mcpguard test --command <target>`.
   - Policy file: `mcpguard test --config <path>`.
   - Saved target: inspect it first with `mcpguard mcp get <name>`, then use `mcpguard mcp test <name>`.
3. Read the applicable policy. Check the failure threshold, timeouts, secret patterns, and per-tool path boundaries. Do not assume `tools.<name>.network` is enforced; it is currently a configuration placeholder.
4. Select the narrowest safe scan. Use `--tool <name>` when a full-server scan is unnecessary or risky.
5. Choose output deliberately:
   - `terminal` for interactive review.
   - `json` for structured analysis or automation.
   - `sarif` for compatible security tooling.
6. Run the authorized scan and preserve the exit code: `0` means the configured severity gate was not reached, `1` means it was reached, and `2` means connection or discovery failed. Exit `0` is not proof of safety.
7. Report confirmed findings separately from assumptions. Include target, scope, policy, tools tested, skipped checks, severity counts, highest-risk findings, remediation, and test limitations.

For exact commands and configuration fields, read [references/commands.md](references/commands.md). For check behavior and limitations, read [references/checks.md](references/checks.md). For multi-step procedures, read [references/workflows.md](references/workflows.md). For failures, read [references/troubleshooting.md](references/troubleshooting.md).

## Interpretation rules

- Never fabricate findings or infer a tool passed if it was not exercised.
- A missing tool, connection error, timeout, or incomplete scan is inconclusive, not a pass.
- Distinguish MCPGuard's implemented checks from roadmap features. Side-effect detection is not implemented, and network-boundary enforcement is not implemented.
- Explain that findings are heuristic and policy-dependent. MCPGuard does not provide process, filesystem, or network isolation.
- Never state that a server is safe, trusted, production-ready, or merge-ready without sufficient evidence and explicit limitations.
- When recommending a fix, identify the rule and evidence first; modify source only when the user separately authorizes changes.

## Registry operations

`mcpguard mcp add`, `remove`, and `import-codex` change a local registry file. `mcpguard init` and report `--output` write files. Treat these as mutations and use them only when requested. Prefer read-only `mcp list` and `mcp get` during discovery.

## Output contract

Return a concise assessment with:

- target and transport;
- authorization and environment used;
- exact scope and policy/fail threshold;
- commands executed and exit codes;
- confirmed findings grouped by severity and tool;
- inconclusive or skipped coverage;
- prioritized remediation and a cautious decision such as `blocked`, `untrusted`, `restricted`, `review`, or `trusted` only when directly supported by the generated report.

Use [examples/usage-examples.md](examples/usage-examples.md) for representative prompts and expected behavior.

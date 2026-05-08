# Next Build Prompt (Missing Features)

Use this prompt when you want to continue MCPGuard implementation from the current state.

```text
You are working in MCPGuard. Implement the missing trust-gate features, not just docs.

Current MCPGuard already has:
- schema quality checks
- timeout checks
- fuzz/runtime checks
- secret leak detection
- CLI test/report flow
- tool-level file permission boundary checks (`allow_paths` / `deny_paths`)
- prompt-injection detection (description + runtime output)

Implement these missing features with tests:

1) Side-effect detection
- Add pre/post probe around tool calls to detect unexpected file mutations in workspace
- Add rule: unexpected_file_side_effect
- Make this check optional via config

2) CI-grade policy + reporting
- Ensure JSON report includes rule counts, severity counts, and fail gate reason
- Keep backward compatibility with existing keys

3) Permission boundary expansion
- Enforce `tools.<tool>.network: false` with runtime detection of outbound calls
- Add network-focused finding rules and tests

4) Documentation update
- Keep README checklist aligned with implemented checks
- Add examples for side-effect and network-boundary findings

Constraints:
- Keep architecture modular under src/mcpguard/checks
- Add/extend unit tests under tests/
- Do not break existing CLI commands
- Run tests and include exact commands run
```

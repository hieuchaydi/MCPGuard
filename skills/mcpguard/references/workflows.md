# Workflows

## Review before execution

1. Read the target command or saved-target entry without running it.
2. Identify transport, executable, script, URL, credentials, and working-directory assumptions.
3. Inspect tool names and classify likely side effects from source or trusted documentation.
4. Review the YAML policy and map per-tool names exactly.
5. State which active probes MCPGuard will make and obtain authorization.

If the command or target is untrusted, stop before execution and report the concern.

## Narrow pre-flight scan

Use this for a new or potentially side-effecting server.

1. Select a disposable/staging target and one approved low-impact tool.
2. Run `mcpguard test --config <policy> --tool <name> --format json`.
3. Capture the exit code separately from the report.
4. Confirm that the requested tool was actually discovered; `tool_not_found` is inconclusive.
5. Summarize evidence, limitations, and remediation. Do not broaden the scope automatically.

## Full staging assessment

1. Confirm every discovered tool is safe to exercise with generated inputs.
2. Run the complete scan with JSON output for analysis.
3. Optionally create SARIF in a second authorized run for CI ingestion. Remember that a second scan repeats active calls.
4. Group findings by severity and tool, deduplicate shared causes, and prioritize critical/high issues.
5. Re-run only affected tools after fixes.

## CI trust gate

1. Pin the MCPGuard version and target dependencies.
2. Use an explicit policy file and failure threshold.
3. Run only against isolated test infrastructure and non-production credentials.
4. Persist JSON or SARIF as a protected artifact; avoid public logs.
5. Interpret exit `1` as a failed gate, `2` as infrastructure/inconclusive failure, and `0` as threshold not reached—not certification.

Example:

```console
mcpguard test --config ci/mcpguard.yaml --format sarif --output artifacts/mcpguard.sarif --fail-on high
```

## Saved-target fleet review

1. Use `mcpguard mcp list --format json`.
2. Inspect each candidate with `mcpguard mcp get <name>`.
3. Exclude production or unknown targets.
4. Use `mcpguard mcp test-all` only after authorization covers every target and tool.
5. Report connection failures separately from security findings.

## Remediation verification

1. Tie each proposed change to a confirmed rule and tool.
2. Ask before modifying target source.
3. Re-run the narrowest affected tool with the same policy.
4. Compare findings, scope, target revision, and exit code.
5. Report regressions and unresolved coverage; do not infer safety from disappeared heuristic matches alone.

# Troubleshooting

## `mcpguard` is not found

Verify Python is 3.12 or newer and install MCPGuard in the active environment. Invoke the environment's executable directly when PATH activation is uncertain.

## Connection or startup fails (exit 2)

- Run the target command independently and verify its dependencies and working directory.
- Prefer an absolute Python/Node script path.
- Confirm the URL scheme is one of `http`, `https`, `ws`, or `wss` when using a remote endpoint.
- Check that stdout from a stdio server is reserved for protocol messages.
- Treat the result as inconclusive; do not report a security pass.

## Tool discovery times out

MCPGuard uses a five-second discovery timeout. Check server startup latency, authentication, protocol compatibility, and stderr logs. There is no CLI option in version 0.1.0 to change the discovery timeout.

## `tool_not_found`

Tool filtering is an exact name match. Inspect the server's registered tools and spelling. Do not silently fall back to scanning all tools.

## Policy validation fails

- The YAML root and each named section must be mappings.
- `fail_on` must be low, medium, high, or critical.
- Timeout values must be positive, and `warn_after_ms` cannot exceed an explicitly configured `timeout_ms`.
- Secret patterns are interpreted as regex when valid, otherwise as escaped literals.
- Per-tool policies must use the exact discovered tool name.

## Filesystem boundary check appears absent

It runs only when the tool has path-like schema fields and a `tools.<exact-name>` policy. MCPGuard infers behavior from calls and output; it does not enforce host filesystem controls.

## Network policy has no effect

This is expected in public version 0.1.0. The `network` value is accepted by the configuration model but no implemented check enforces it. Use OS/container/network controls outside MCPGuard.

## JSON or SARIF file is missing

Confirm the parent directory exists and is writable. `--output` writes the report file; without it, output goes to stdout. Avoid placing sensitive reports in public build artifacts.

## Scan returns exit 1

The configured severity gate was reached. Read the report; this is a completed failing assessment, not a CLI malfunction.

## Scan returns exit 0 with findings

Findings may exist below the configured `fail_on` threshold. Review all severities and risk details instead of equating exit `0` with a clean scan.

## Agent does not activate the Skill

Verify the layout is `<skills-directory>/mcpguard/SKILL.md`, the frontmatter name is exactly `mcpguard`, and restart or reload the agent. Agent-specific discovery differs; only Codex CLI integration is verified by this package's build process.

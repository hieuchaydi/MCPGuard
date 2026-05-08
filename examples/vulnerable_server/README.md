# Vulnerable MCP Demo Server

Intentionally unsafe MCP server for MCPGuard failure demos.

Included unsafe behaviors:
- `leak_env`: returns a fake API key-like token in output.
- `slow_echo`: defaults to a long sleep to trigger timeout checks.
- `read_file`: reads arbitrary filesystem paths without restriction.
- `prompt_bait`: contains prompt-injection phrases in description and output.

Use this only for security testing demos, never in production.

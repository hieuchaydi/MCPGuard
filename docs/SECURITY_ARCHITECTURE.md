# MCPGuard Security Architecture

MCPGuard evaluates whether MCP tools are safe enough for AI agents to call before those tools enter trusted automation paths.

## Trust Boundaries

```text
User / CI policy
  |
  v
MCPGuard policy loader
  |
  v
+-------------------- trust boundary --------------------+
| MCP server process                                      |
|  - tool metadata                                        |
|  - input schema                                         |
|  - tool runtime behavior                                |
|  - returned content                                     |
+--------------------------------------------------------+
  |
  v
MCPGuard validation engine
  |
  +--> schema checks
  +--> timeout checks
  +--> fuzz/runtime checks
  +--> secret output scanning
  +--> filesystem boundary probes
  +--> prompt-injection scanning
  |
  v
Reports: terminal, JSON, SARIF, CI exit codes
```

## Threat Model

MCPGuard assumes MCP servers and tools may be untrusted, compromised, newly generated, or misconfigured.

In scope:
- Tool metadata that manipulates agent planning.
- Tool output that injects instructions into future model steps.
- Tool output that leaks tokens, API keys, private keys, or debug secrets.
- Path arguments that cross declared allowlists or hit denylists.
- Invalid or permissive input schemas that make safe calling unreliable.
- Slow, hanging, or crash-prone tools that can deny service to agents.
- Malformed input handling that exposes stack traces or brittle behavior.

Out of scope for the current runtime:
- Full OS sandboxing.
- Complete network isolation.
- Dynamic taint tracking across multiple agent turns.
- Formal proof that a tool is safe.

## Validation Lifecycle

1. Load YAML policy and target server command.
2. Start MCP server in an isolated scan session.
3. Discover tool metadata and schemas.
4. Run static metadata checks.
5. Build minimal valid inputs from schemas.
6. Execute bounded runtime probes.
7. Run adversarial probes for filesystem, prompt injection, secrets, timeout, and fuzz behavior.
8. Normalize findings into risk profiles.
9. Produce terminal, JSON, and SARIF reports.
10. Enforce CI exit policy.

## Attack Surface Map

| Surface | Abuse | MCPGuard control |
|---|---|---|
| Tool description | Prompt injection, unsafe planning | Metadata prompt-injection scan |
| Input schema | Type confusion, unbounded inputs | Schema quality checks |
| Runtime execution | Hanging, crashes | Timeout and fuzz checks |
| Tool output | Secret exfiltration, prompt injection | Secret and output-injection scans |
| Filesystem paths | Host file disclosure | allow_paths and deny_paths probes |
| CI artifacts | Long-lived leak storage | JSON/SARIF redaction-oriented reports |

## Risk Model

Every finding maps to a `RuleProfile`:

```text
risk_score = round(
  (severity_score * 0.45 + impact_score * 0.35 + exploitability_score * 0.20)
  * confidence
)
```

Tool and report scores are combined with probabilistic union:

```text
combined = 100 * (1 - product(1 - finding_score / 100))
```

Trust classifications:

| Score | Classification | CI posture |
|---:|---|---|
| 0-19 | trusted | allow |
| 20-39 | review | warn |
| 40-69 | restricted | require approval |
| 70-89 | untrusted | block by default |
| 90-100 | blocked | fail |

Severity thresholds still exist for compatibility with `--fail-on`, while `risk_score` is the production decision primitive for dashboards and future policy gates.

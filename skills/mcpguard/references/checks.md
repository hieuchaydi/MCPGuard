# Checks and capability boundaries

The source code is the authority for this list.

## Implemented checks

### Schema quality

Statically inspects discovered metadata for missing names/descriptions/input schemas, invalid JSON Schema, missing properties/types/required declarations, unbounded numeric or common pagination fields, strings without `maxLength`, and permissive `additionalProperties`.

Limit: schema quality is a contract heuristic; it does not prove runtime authorization or semantic correctness.

### Timeout and slow response

Builds a minimal input from the schema and calls the tool. It reports calls beyond `warn_after_ms` and hard timeouts beyond `timeout_ms`.

Limit: this executes the tool and one generated input is not a performance benchmark.

### Fuzz and error handling

Calls tools with empty, unexpected, wrong-type, boundary-like, and other generated inputs. It looks for crashes/disconnects, timeouts, exposed stack traces, weak errors, and secret patterns in responses or exceptions.

Limit: payload coverage is finite and generated probes may trigger target-side effects.

### Secret-pattern scanning

Searches runtime response/error text for configured regular expressions or literal fallbacks. Findings identify that a configured pattern matched but intentionally do not reproduce the secret.

Limit: pattern matching can produce false positives and cannot find unknown secret formats.

### Filesystem permission boundary

For tools with path-like schema fields and a matching `tools.<name>` policy, probes allow/deny boundaries and inspects response paths.

Limit: enforcement is inferred from responses; MCPGuard does not isolate the filesystem. A policy is required for the named tool.

### Prompt injection

Scans tool descriptions for instruction-like patterns and actively calls tools with injection probe text, then scans outputs.

Limit: pattern matching is heuristic and an active call can reach application logic.

## Not implemented in public version 0.1.0

- Automatic side-effect detection.
- Network-boundary enforcement. `tools.<name>.network` is parsed but not used by a check.
- OS, container, process, filesystem, or network sandboxing.
- Proof that a tool is safe, trustworthy, production-ready, or free of vulnerabilities.

Do not present roadmap items or configuration placeholders as delivered capabilities.

## Risk output

Findings are normalized to low, medium, high, or critical. MCPGuard applies predefined profiles to calculate risk score, confidence, impact, exploitability, recommendations, and trust classification. The aggregate labels are policy signals, not independent security certification.

Current trust-score labels are `trusted`, `review`, `restricted`, `untrusted`, and `blocked`. Quote them as MCPGuard report values and preserve the scan scope and limitations.

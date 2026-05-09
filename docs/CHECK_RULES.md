# MCPGuard Check Rules Reference

This document is the rule catalog for interpreting MCPGuard findings and fixing issues quickly.

## Severity Levels

- `critical`: highest risk, fix immediately before exposing tools to agents.
- `high`: serious risk, should be fixed before production use.
- `medium`: important quality or safety gap that may cause unstable behavior.
- `low`: hardening gap; lower urgency but still recommended.

## Normalized Severity Mapping (Rule -> Severity)

These mappings are enforced for risk scoring and fail-gate behavior:

- `secret_leaked`: `critical`
- `path_matches_denylist`: `high`
- `path_outside_allowlist`: `high`
- `prompt_injection_in_output`: `high`
- `prompt_injection_in_description`: `medium`
- `timeout_exceeded`: `medium`
- `schema_invalid`: `high`
- `missing_schema`: `medium`

## Rule Catalog

## A. Schema Quality Rules

`missing_tool_name` (`medium`)
- Condition: tool has no name.
- Fix: add an explicit, stable tool name.

`missing_description` (`high`)
- Condition: tool description is missing.
- Fix: add clear purpose, inputs, limits, and safe usage notes.

`description_too_short` (`medium`)
- Condition: description length is lower than `min_description_length`.
- Fix: expand description with intent and constraints.

`missing_input_schema` (`medium`)
- Condition: tool has no `inputSchema`.
- Fix: define a complete input schema.

`missing_schema` (`medium`)
- Condition: normalized alias for `missing_input_schema` in risk summaries.
- Fix: define a complete input schema.

`no_properties_defined` (`medium`)
- Condition: `inputSchema.properties` is missing or invalid.
- Fix: define typed input properties.

`schema_invalid` (`high`)
- Condition: schema is invalid or too permissive.
- Fix: tighten schema contract and add explicit bounds.

`missing_required_declaration` (`high`)
- Condition: `inputSchema.required` is missing.
- Fix: declare required fields explicitly.

`property_missing_type` (`medium`)
- Condition: property schema is invalid or missing `type`.
- Fix: add explicit `type` for each property.

`number_missing_maximum` (`high`)
- Condition: numeric field (`number|integer`) has no `maximum` (when policy requires it).
- Fix: add upper bounds.

`number_missing_minimum` (`low`)
- Condition: numeric field has no `minimum`.
- Fix: add lower bounds.

`string_missing_maxlength` (`low`)
- Condition: string field has no `maxLength`.
- Fix: add safe max length limits.

`bounded_field_missing_maximum` (`high`)
- Condition: bounded field names (`limit|count|page_size|max`) have no `maximum`.
- Fix: enforce explicit upper bounds.

`allows_additional_properties` (`low`)
- Condition: `additionalProperties` is not `false`.
- Fix: set `additionalProperties: false` unless needed.

## B. Timeout Rules

`timeout_exceeded` (`medium`)
- Condition: tool call exceeds `timeout_ms`.
- Fix: optimize tool latency and fail-fast behavior.

`slow_response` (`low`)
- Condition: response time is above `warn_after_ms` but below timeout.
- Fix: profile and improve performance.

## C. Fuzz/Runtime Robustness Rules

`fuzz_server_crash` (`critical`)
- Condition: server appears to crash/disconnect under malformed input.
- Fix: validate input and harden exception handling.

`stack_trace_exposed` (`high`)
- Condition: output/error appears to expose internal stack traces.
- Fix: sanitize runtime errors returned to clients.

`poor_error_message` (`medium`)
- Condition: error output is empty, generic, or not actionable.
- Fix: return meaningful validation errors.

`fuzz_timeout` (`high`)
- Condition: fuzz probe call times out.
- Fix: reject malformed input faster.

## D. Secret Rules

`secret_leaked` (`critical`)
- Condition: response matches sensitive secret patterns.
- Fix: redact/mask secrets; never return raw credentials.

## E. Permission Boundary Rules

`path_outside_allowlist` (`high`)
- Condition: tool accepts/returns paths outside `tools.<tool>.allow_paths`.
- Fix: enforce strict path allowlists.

`path_matches_denylist` (`high`)
- Condition: tool accepts paths from `tools.<tool>.deny_paths`.
- Fix: block denylisted paths before execution and return safe authorization errors.

## F. Prompt Injection Rules

`prompt_injection_in_description` (`medium`)
- Condition: tool description contains instruction-injection style phrases.
- Fix: keep descriptions as API contract text, not agent-directive instructions.

`prompt_injection_in_output` (`high`)
- Condition: tool output includes instruction-injection or secret-exfiltration phrasing.
- Fix: sanitize output and remove hidden/instructional payloads.

## G. Server-Level Rules

`no_tools_discovered` (`low`)
- Condition: discovery succeeds but no tools are returned.
- Fix: verify server startup and tool registration.

`tool_not_found` (`low`)
- Condition: `--tool` filter does not match any discovered tool.
- Fix: use correct tool name or remove the filter.

## Fixing Priority

1. Fix all `critical` findings.
2. Fix `high` findings related to input bounds, prompt injection, and access boundaries.
3. Reduce `medium` findings to improve stability.
4. Harden remaining `low` findings.

## Notes

- This catalog reflects current MCPGuard behavior.
- Severity levels directly affect `--fail-on` exit behavior.

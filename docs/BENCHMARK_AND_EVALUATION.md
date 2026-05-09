# Benchmark and Evaluation Strategy

MCPGuard should be evaluated like security tooling, not only like a CLI utility.

## Corpus Layout

```text
examples/exploit_playground/
  malicious_server.py
  mcpguard.exploit.yaml
  manifest.yaml
  expected-detections.json
```

Future benchmark corpora should follow:

```text
benchmarks/
  corpora/
    malicious/
    benign/
    mixed/
  expected/
    malicious.expected.json
    benign.expected.json
  runners/
    evaluate.py
  reports/
```

Current lightweight evaluator:

```bash
mcpguard test \
  --config examples/exploit_playground/mcpguard.exploit.yaml \
  --format json \
  --output exploit-report.json

python benchmarks/evaluate_report.py \
  --report exploit-report.json \
  --expected examples/exploit_playground/expected-detections.json
```

## Attack Coverage Benchmark

Track coverage across these classes:
- prompt injection in metadata
- prompt injection in output
- secret exfiltration
- timeout and resource abuse
- schema confusion
- unsafe filesystem access
- recursive tool loop bait
- crash and stack-trace exposure
- benign tools with strict schemas

Core metrics:
- detection rate by attack class
- false negative count by rule
- false positive rate on benign tools
- scan duration p50/p95
- report stability across repeated runs

## False Positive Testing

Maintain benign fixtures that intentionally look realistic:
- tools with descriptions that mention security policies without instructing the model
- tools returning sample tokens that are documented as fake
- file tools that correctly reject denied paths
- slow-but-acceptable tools below `warn_after_ms`

A production-quality release should keep false positives explainable and policy-tunable.

## Security Regression Tests

Every new rule should add:
- one malicious positive fixture
- one benign negative fixture
- expected JSON fields
- expected SARIF rule metadata
- CLI exit-code behavior

The exploit playground is the first integration corpus. It should become part of nightly CI once scan runtime is acceptable.

## OSS Positioning

Position MCPGuard as:
- a trust gate for MCP tools before agent execution
- CI-native security validation for agent infrastructure
- an MCP-specific complement to SAST/DAST, not a replacement
- a framework for repeatable adversarial tool testing

Avoid claiming:
- complete sandboxing
- guaranteed tool safety
- complete prompt-injection prevention
- runtime containment of compromised tools

The strongest public message is: MCPGuard makes MCP tool risk visible, explainable, and enforceable before agents depend on those tools.

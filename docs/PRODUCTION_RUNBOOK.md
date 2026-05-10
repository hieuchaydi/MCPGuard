# Production Runbook

## Release Process

1. Ensure `main` is green on `MCPGuard CI` and `Security` workflows.
2. Bump version in `pyproject.toml`.
3. Create and push tag `vX.Y.Z`.
4. Confirm `Release` workflow published:
   - Python artifacts (`sdist`, `wheel`)
   - GitHub Release assets
   - GHCR container image
   - provenance attestations and Cosign signature

## Rollback

1. Identify last known-good tag (for example `v0.1.3`).
2. Redeploy runtime using that tag:
   - container: `ghcr.io/<org>/<repo>:v0.1.3`
   - python package: install exact previous version artifact
3. Open incident with:
   - triggering release tag
   - failed checks/findings
   - remediation owner and ETA

## Secret Rotation

1. Rotate leaked/expired credentials at provider side immediately.
2. Update GitHub secrets:
   - `PYPI_API_TOKEN`
3. Re-run failed release/security workflows after rotation.

## Dependency Update Policy

1. Use `requirements.lock` as the source of truth for CI installs.
2. Refresh lockfile on cadence (weekly recommended):
   - `pip-compile pyproject.toml --extra dev -o requirements.lock`
3. Merge only when CI + security scans pass.

## Incident Checklist

1. Stop rollout or pin to previous tag.
2. Capture logs, SARIF, SBOM, and digest of impacted image.
3. Classify severity and business impact.
4. Patch, test, and release a fixed tag.
5. Publish postmortem with timeline and prevention actions.

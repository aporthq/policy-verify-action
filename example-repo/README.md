# APort Repository Guard Example

This example shows the free report-only APort Repository Guard workflow.

It does not require an APort account, API key, manually configured passport, PR comments, or repository write permissions. In default `auto` mode, the Action uses GitHub OIDC to create or reuse a hosted OAP passport for this repository/workflow and records a report-only APort decision.

## Workflow

Create `.github/workflows/aport-guard.yml`:

```yaml
name: APort Repository Guard
on:
  pull_request:
    types: [opened, synchronize, reopened, ready_for_review, labeled, unlabeled, review_requested, review_request_removed]
  pull_request_review:
    types: [submitted, dismissed]

permissions:
  id-token: write
  contents: read
  pull-requests: read

jobs:
  aport:
    name: APort / OAP code.repository.merge.v1
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps:
      - uses: aporthq/policy-verify-action@v1
```

Do not use `pull_request_target` for this report-only workflow. It does not need repository secrets and does not need `pull-requests: write`.

## What You Get

- Actor classification: `human`, `known_bot`, `coding_agent`, or `unknown_automation`.
- Attribution signals from APort commit trailers, known bot slugs, conservative agent markers, agent-domain automation emails, and branch prefixes.
- Report-only structural findings for protected paths, `pull_request_target`, and workflow write-permission changes.
- A hosted `ci_time` APort decision by default, or `unattributed` evidence-only provenance when hosted OIDC is unavailable.
- A zero-exit workflow that is safe to add before enforcement is enabled.

## Protected Paths

The default protected path set covers workflows, package manifests, APort policy surfaces, and common build config files. You can override it:

```yaml
- uses: aporthq/policy-verify-action@v1
  with:
    protected-paths: ".github/workflows/**,package.json,policies/**"
```

## Moving to Enforcement

This Action is intentionally post-PR and report-only. To create pre-action authorization records, install APort guardrails in the developer's coding agent so tool calls produce signed decisions before files, shell commands, or GitHub actions run.

## Evidence-Only Opt-Out

Use this for local Action development or environments where hosted verification is intentionally disabled:

```yaml
- uses: aporthq/policy-verify-action@v1
  with:
    mode: evidence-only
```

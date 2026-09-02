# APort Repository Guard

APort AI agent passport guardrails for GitHub: hosted OAP decisions, PR attribution, and protected-path checks.

No config, no daemon, no account, and no API key by default.

This first slice answers a narrow question that scanners do not answer:

> Which human, bot, or coding agent appears to be writing to this repository, and is there any authorization provenance behind it?

APort Repository Guard does not replace `zizmor`, StepSecurity, Socket, Semgrep, Trivy, GitHub Advanced Security, Dependabot, or GitHub rulesets. It complements them by making agent authorship and authorization provenance visible.

Learn more at [aport.io](https://aport.io), the [GitHub Actions quickstart](https://aport.io/quickstart/github), and the APort guide to [securing GitHub Actions for AI coding agents](https://aport.io/blog/secure-github-actions-ai-coding-agents-protected-paths).

## What It Does Today

- Classifies PR authorship as `human`, `known_bot`, `coding_agent`, or `unknown_automation`.
- Reads `APort-Session`, `APort-Decision`, and `APort-Agent` commit trailers when present.
- Falls back to conservative heuristics when no APort trailer exists.
- Writes a GitHub job summary with checked signals, hit and miss.
- Reports structural checks:
  - protected path touched
  - `pull_request_target` introduced
  - workflow write permission escalation
  - GitHub OIDC token permission added
  - suspicious obfuscated or remote-execution code in workflow, action, build-config, policy, verifier, package, or script surfaces
  - missing patch/content evidence for sensitive execution or configuration surfaces
- Reads optional `.aport/policy.yaml` or `.aport/policy.yml` from the trusted base branch, never from the PR head.
- Uses base-branch policy for Action-side protected paths and pinned-action reporting; hosted policy decisions still go through APort Verify.
- In default `auto` mode, requests GitHub OIDC, creates or reuses a hosted repository-scoped OAP passport, then calls APort Verify at `/api/verify/policy/code.repository.merge.v1`.
- Verifies hosted decision signatures against APort's OAP JWKS before using the result.
- Supports `local-json` mode for a trusted OAP passport file; this posts the passport to the same verifier without hosted decision persistence.
- Supports `evidence-only` mode for attribution and structural findings with no APort network calls.
- Exits 0 in default `auto`, `evidence-only`, and `local-json` report modes. Explicit `hosted` mode fails when signed hosted verification cannot complete.
- Requires no APort account, user-managed passport ID, API key, secrets, or PR comments.

## Quick Start

```yaml
name: APort Repository Guard
on:
  pull_request:
    types: [opened, synchronize, reopened, ready_for_review, labeled, unlabeled, review_requested, review_request_removed]
  pull_request_review:
    types: [submitted, dismissed]
  push:
    branches:
      - main

permissions:
  id-token: write
  contents: read
  pull-requests: read

jobs:
  aport:
    name: APort / OAP code.repository.merge.v1
    if: >-
      github.event_name != 'pull_request_review' ||
      github.event.action == 'dismissed' ||
      github.event.review.state != 'commented'
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps:
      - uses: aporthq/policy-verify-action@v1
```

The Action writes to `$GITHUB_STEP_SUMMARY`. It does not request `pull-requests: write` and does not comment on PRs by default, so it is safe for fork PRs and easy to try.

The summary includes a small Porter trust card, deterministic APort status, structural findings, signed decision metadata when available, and a copyable README badge. After the workflow is passing, add the badge to your repository README so contributors can see that APort Repository Guard is active:

```md
[![APort Repository Guard](https://github.com/OWNER/REPO/actions/workflows/aport-guard.yml/badge.svg)](https://github.com/OWNER/REPO/actions/workflows/aport-guard.yml)
```

For teams that want the badge to mean "this repo is actually protected," make the workflow a required check in GitHub branch protection or rulesets and use `mode: hosted` once report-only results are clean.

The `push` trigger is a detection layer for direct pushes to protected branches. It runs after the push lands, so use GitHub rulesets or branch protection to prevent direct pushes and make this Action a required PR check for merge-time enforcement.

`id-token: write` is required for hosted GitHub OIDC. APort reports newly added OIDC token permission as a warning so teams can review cloud trust policy changes, but it is not treated as repository write permission. Broad repository permissions such as `write-all`, `contents: write`, `actions: write`, or `pull-requests: write` remain high-severity findings.

Default `auto` mode attempts hosted OIDC verification first. If OIDC is unavailable, it falls back to clearly labelled `evidence-only` reporting.

APort-hosted deployments must configure `APORT_GITHUB_FREE_OWNER_ID` to a real platform-owned org ID before `/api/github/oidc/issue` can mint free hosted passports. The endpoint fails closed when that owner is missing.

## Repository Policy

The Action supports a small base-branch policy file for report-only GitHub evidence:

```yaml
version: oap-github-policy/1

repository:
  protected_paths:
    - .github/workflows/**
    - package.json
    - pnpm-lock.yaml
    - functions/api/verify/**
    - policies/**

github:
  require_pinned_actions: true
```

For `pull_request` events, this file is fetched from the trusted base ref. For `push` events, it is fetched from the pre-push commit when GitHub provides one. If the PR changes `.aport/policy.yaml` or `.aport/policy.yml`, APort flags that the PR-head policy was ignored and evaluates with the base-branch policy.

The Action only uses this policy for evidence and summary checks. Hosted allow/deny decisions still use the existing APort verifier and OAP passport policy path.

Structural checks are deterministic repository-safety evidence, not a general malware scanner. APort blocks high-confidence structural risks in hosted enforcement, including incomplete workflow evidence, missing patch/content evidence for sensitive execution or configuration surfaces, `pull_request_target`, broad workflow write permissions, and suspicious encoded execution or remote shell execution in sensitive execution/config surfaces. Keep dedicated scanners such as GitHub Advanced Security, Semgrep, Socket, StepSecurity, `zizmor`, and Trivy in the pipeline for deeper code and dependency analysis.

## Inputs

| Input | Default | Description |
|---|---:|---|
| `mode` | `auto` | Verification mode: `auto`, `hosted`, `local-json`, or `evidence-only`. |
| `api-url` | `https://api.aport.io` | APort API base URL for hosted verification. |
| `oidc-audience` | `aport.io` | GitHub OIDC audience expected by the APort API. Only change this for private or staging APort deployments. |
| `passport-path` | `.aport/passport.json` | Trusted OAP passport JSON path for `local-json` mode. The Action reads it from the trusted base/push ref, not from PR-head checkout content. |
| `protected-paths` | empty | Extra comma-separated protected path globs for Action-side evidence. |

## Modes

| Mode | Behavior |
|---|---|
| `auto` | Default. Requests GitHub OIDC, issues/reuses a hosted OAP passport, calls APort Verify, and falls back to `evidence-only` if hosted verification is unavailable. |
| `hosted` | Requires GitHub OIDC and calls hosted APort Verify. No API key is needed for the free report-only path. Fails the workflow if hosted verification cannot return a valid signed decision. |
| `local-json` | Reads a trusted OAP passport JSON file and posts it to the same verifier as `body.passport`; the verifier skips hosted decision persistence. |
| `evidence-only` | No hosted passport, no verifier call, no network calls to APort. Attribution and structural checks only. |

Use `evidence-only` when running a local Action source from a checked-out PR head. Use `auto` or `hosted` from a pinned published Action version.

Hosted mode treats a missing, fallback, or invalid APort decision signature as `OAP.DECISION.SIGNATURE_INVALID`. Default `auto` mode falls back to labelled evidence-only reporting; explicit `hosted` mode fails so teams do not mistake missing hosted evidence for a verified check.

## Outputs

| Output | Description |
|---|---|
| `actor-class` | `human`, `known_bot`, `coding_agent`, `unknown_automation`, or `unattributed` |
| `confidence` | `high`, `medium`, or `low` |
| `provenance` | `ci_time` for hosted OIDC decisions, `local_json` for local-json mode, or `unattributed` for evidence-only |
| `decision-id` | Hosted/local verifier decision ID when available |
| `outcome` | Decision outcome when available |
| `structural-findings` | JSON array of report-only structural findings |

## Trust Rules

- APort trailers are the strongest signal.
- Known bot slugs are high-confidence bot signals.
- Agent markers and branch prefixes are conservative hints.
- Unknown automation stays `unknown_automation`.
- Human PRs must not be falsely labeled as `coding_agent`.
- Attribution alone does not fail the workflow.

## Upgrading to Pre-Action Authorization

This Action runs after a PR exists, so it can report provenance but cannot create a pre-action decision retroactively.

To get real `pre_action` provenance, install APort agent guardrails for the coding agent. Claude Code already supports APort through its `PreToolUse` hook. When agent-side guardrails write `APort-Session`, `APort-Decision`, and `APort-Agent` trailers, this Action can join CI attribution back to the exact signed decision.

## Development

```bash
npm test
```

Fixtures live in `fixtures/`. They are compact labelled cases, not raw GitHub PR dumps, and they enforce zero false `coding_agent` classifications on human-authored PRs.

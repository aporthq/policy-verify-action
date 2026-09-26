# APort Repository Guard

APort AI agent passport guardrails for GitHub: hosted OAP decisions, PR attribution, and protected-path checks.

No config, no daemon, no account, and no API key by default. Teams that want decisions persisted under their own APort org can pass a managed hosted passport ID and an APort API key.

This first slice answers a narrow question that scanners do not answer:

> Which human, bot, or coding agent appears to be writing to this repository, and is there any authorization provenance behind it?

APort Repository Guard does not replace `zizmor`, StepSecurity, Socket, Semgrep, Trivy, GitHub Advanced Security, Dependabot, or GitHub rulesets. It complements them by making agent authorship and authorization provenance visible.

Learn more at [aport.io](https://aport.io), the [GitHub Actions quickstart](https://aport.io/quickstart/#github), and the APort guide to [securing GitHub Actions for AI coding agents](https://aport.io/blog/secure-github-actions-ai-coding-agents-protected-paths).

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
- Classifies a push to a branch as `direct`, `merged_pull_request`, `forced`, `created`, or `unknown`, and reports `not_push` for a push whose ref is not a branch (a tag, `refs/pull/...`) and for every event that is not a push. That is the `push-classification` output, and with `protect-default-branch: true` a forced or direct push to the default branch fails the step.
- Reads optional `.aport/policy.yaml` or `.aport/policy.yml` from the trusted base branch, never from the PR head.
- Uses base-branch policy for Action-side protected paths and pinned-action reporting; hosted policy decisions still go through APort Verify.
- In default `auto` mode, requests GitHub OIDC, creates or reuses a hosted repository-scoped OAP passport, then calls APort Verify at `/api/verify/policy/code.repository.merge.v1`.
- Verifies hosted decision signatures against APort's OAP JWKS before using the result.
- Supports `local-json` mode for a trusted OAP passport file; this posts the passport to the same verifier without hosted decision persistence.
- Supports `evidence-only` mode for attribution and structural findings with no APort network calls.
- Exits 0 in default `auto`, `evidence-only`, and `local-json` report modes. Explicit `hosted` mode fails when signed hosted verification cannot complete.
- Requires no APort account, user-managed passport ID, API key, secrets, or PR comments for the free default path.
- Supports managed hosted passports with `agent-id` plus `api-key` for customer-owned audit trails.

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

The `push` trigger is a detection layer for direct pushes to protected branches. It runs after the push lands, so use GitHub rulesets or branch protection to prevent direct pushes and make this Action a required PR check for merge-time enforcement. To have the check itself go red on a forced or direct push to the default branch, see [Protect the default branch](#protect-the-default-branch).

`id-token: write` is required for hosted GitHub OIDC. APort reports newly added OIDC token permission as a warning so teams can review cloud trust policy changes, but it is not treated as repository write permission. Broad repository permissions such as `write-all`, `contents: write`, `actions: write`, or `pull-requests: write` remain high-severity findings.

Default `auto` mode attempts hosted OIDC verification first. If OIDC is unavailable, it falls back to clearly labelled `evidence-only` reporting.

APort-hosted deployments must configure `APORT_GITHUB_FREE_OWNER_ID` to a real platform-owned org ID before `/api/github/oidc/issue` can mint free hosted passports. The endpoint fails closed when that owner is missing.

## Managed Hosted Passport

Use a managed hosted passport when you want Repository Guard decisions to appear in your APort org audit trail instead of the free APort-owned repository passport. Store the API key as a GitHub Secret and the passport ID as a GitHub Variable:

```yaml
- uses: aporthq/policy-verify-action@v1
  with:
    mode: hosted
    agent-id: ${{ vars.APORT_GITHUB_AGENT_ID }}
    api-key: ${{ secrets.APORT_API_KEY }}
```

`agent-id` is an identifier, not a secret. `api-key` is a credential and should come from `secrets.APORT_API_KEY`, not a literal workflow value. The Action sends the API key as `X-API-Key` only to `POST /api/verify/policy/code.repository.merge.v1`; it is not sent to the free passport issue endpoint and is not written to outputs.

The hosted verifier still requires GitHub OIDC for managed passports. APort checks that the OIDC repository binding matches the passport's GitHub integration before it signs or logs the decision, so an API key alone cannot fake repository evidence.

For public repositories that accept fork PRs, GitHub does not expose normal repository secrets to untrusted fork workflows. When the Action detects an external fork PR, it ignores the managed passport inputs and continues through the no-secret hosted OIDC path instead of failing on a missing secret.

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

## Protect the default branch

By default a `push` to `main` is report-only. The Action classifies the push and records it, but exits 0 even when someone pushed straight to the branch. Set `protect-default-branch: true` to turn the two cases that need no policy tuning into a failed check:

```yaml
- uses: aporthq/policy-verify-action@v1
  with:
    protect-default-branch: true
```

On a `push` whose ref is the repository default branch, the step fails when:

1. The push payload's `forced` flag is `true`. Finding: `OAP.REPO.FORCE_PUSH`.
2. The push is not the merge of a merged pull request into that branch. Finding: `OAP.REPO.DIRECT_PUSH_DEFAULT_BRANCH`.

The second check has three parts. First, the pushed tip must be the `merge_commit_sha` of a merged pull request into the branch (`GET /repos/{owner}/{repo}/commits/{sha}/pulls`). Second, the commits between `before` and `after` are compared with the pull request's own commits (`GET /repos/{owner}/{repo}/pulls/{n}/commits`). Third, after those commit checks pass, the files that landed in the push are compared with the pull request's files (`GET /repos/{owner}/{repo}/pulls/{n}/files`). GitHub marks a pull request merged as soon as its head becomes reachable from the base branch, so the first part alone would accept `git push origin feature:main` or a local merge pushed together with unrelated changes. The push is called `direct` when its tip is the pull request head itself, when it carries more commits than the pull request plus one, when the pull request head landed in the push and either the tip is not a merge commit of that head or another pushed commit is not part of the pull request, or when the landed files do not match the pull request file evidence. Merge commit, squash, and rebase merges made by GitHub all pass when the commit and file evidence match. When the compare or the pull request evidence cannot be read, the classification is `unknown`, and the details record why (`push_classification_reason`).

The pull request lookup is retried up to three times, ten seconds apart, because the commit index can lag a merge by a few seconds. It retries only on network errors, `429`, `403` responses with GitHub rate-limit evidence, and `5xx`. A `401`, ordinary permission-denied `403`, `404`, or `422`, or a response that does not parse, ends the lookup at once with the classification `unknown`. An empty result is retried on the same schedule for every push to the default branch, whether or not the input is on, so the `push-classification` output does not depend on the input. Once an attempt has returned an empty list, later errors do not change the answer: the push is `direct`. The classification is `unknown` when no attempt returned an answer at all, and also when the association list was longer than the lookup reads.

The association list is paginated, 100 per page, for up to 5 pages, then one sentinel page is fetched only when those 5 pages were full. One page is not enough: a commit can be associated with more pull requests than a page holds, and the merge that targets this branch is not guaranteed to be among the first of them, so a single-page lookup can miss a legitimate merge and call the push `direct`. If the sentinel shows another page exists, "no match in what we read" is not evidence that no merge exists; the classification is then `unknown` with `associated_pr_list_truncated` in `push_classification_reason`, never `direct`. Exactly 500 non-matching associations is a complete lookup and becomes `direct`. With the input on, `unknown` fails the step with the same `OAP.REPO.DIRECT_PUSH_DEFAULT_BRANCH` finding, so a truncated lookup is reported rather than silently blocking the merge as a direct push.

A push that creates the default branch (`before` is the zero SHA, which is also what re-pushing a deleted branch looks like) is classified `created`. There is no pull request for it to be the merge of, so it does not fail the step, including when the default branch name is not yet resolvable. A branch deletion is never looked up.

The default branch name comes from the push payload's `repository.default_branch`. When the payload does not carry it, the Action uses the `default-branch` input if set, then `GET /repos/{owner}/{repo}`. If none of those name it and the input is on, a branch push fails closed with `OAP.REPO.DIRECT_PUSH_DEFAULT_BRANCH` and a message saying the default branch could not be determined. Set `default-branch` to avoid the extra request for events whose payload omits the default branch name.

Errors that stop the run before the push is classified (a refused API URL, for example) fail the step when the input is on and the push is to the default branch, or the default branch cannot be read from the payload or the `default-branch` input. The `push-classification` output is written as `unknown`. With the input off, or for a push to another branch, such a run exits 0 as before. `GITHUB_API_URL` must be `https://`; a plain `http://` URL is refused before any request carries the token, except for `127.0.0.1`, `localhost`, or `[::1]`, or when `APORT_ALLOW_INSECURE_GITHUB_API=1` is set in the environment.

The input works in every mode, including the default `auto` mode. It changes nothing for pull request events, for pushes to other branches, or for merged pull requests landing on the default branch. With the input off, a force push to the default branch is still reported as a warning-level `OAP.REPO.FORCE_PUSH` finding and the step exits 0.

Every run also sets the `push-classification` output (`direct`, `merged_pull_request`, `forced`, `created`, `unknown`, or `not_push`), so later steps can branch on it without a second API call. A tag push is `not_push`: it is not a branch event, so `protect-default-branch` never applies to it.

```yaml
- uses: aporthq/policy-verify-action@v1
  id: aport
  with:
    protect-default-branch: true
- if: steps.aport.outputs.push-classification == 'merged_pull_request'
  run: ./deploy.sh
```

What it cannot do: a `push` workflow runs after the commit is already on the branch. The failed check is recorded on that commit, and downstream automation that keys on check status (deploy workflows, `gh run watch`, status-gated release jobs) can rely on it, but the push itself is not rejected. Pair the input with a GitHub ruleset on the default branch that blocks force pushes and requires a pull request before merging. The ruleset prevents; this check proves. The step needs only the `contents: read` and `pull-requests: read` permissions the workflow already has. Merge queue merges land as pushes by the queue. A group of one pull request classifies as `merged_pull_request`. A group of several pull requests lands in one push, and the check only reconciles the pull request whose merge commit is the pushed tip, so with the merge commit or rebase strategy a group of two or more is classified `direct` and fails the step; with the squash strategy it passes as long as the last pull request has at least as many commits as there are other squash commits in the push. In a merge-queue repository, set the queue's minimum group size to one or leave the input off.

The two push findings are enforced by the Action only. They appear in the job summary, the workflow annotations, the `structural-findings` output, and the exit code, but they are not sent to the hosted verifier as structural findings, so a commit index that lags a legitimate merge cannot persist a hosted deny for it. The hosted verifier receives the push facts as plain fields in the `repo.push` evidence: `push_classification`, `push_classification_reason`, `push_forced`, `push_to_default_branch`, and `default_branch`.

## Inputs

| Input | Default | Description |
|---|---:|---|
| `mode` | `auto` | Verification mode: `auto`, `hosted`, `local-json`, or `evidence-only`. |
| `api-url` | `https://api.aport.io` | APort API base URL for hosted verification. |
| `oidc-audience` | `aport.io` | GitHub OIDC audience expected by the APort API. Only change this for private or staging APort deployments. |
| `agent-id` | empty | Optional managed hosted OAP passport ID. Use with `api-key` to persist decisions under your APort org. |
| `api-key` | empty | Optional APort API key for managed hosted verification. Store as a GitHub Secret and pass `secrets.APORT_API_KEY`. |
| `passport-path` | `.aport/passport.json` | Trusted OAP passport JSON path for `local-json` mode. The Action reads it from the trusted base/push ref, not from PR-head checkout content. |
| `protected-paths` | empty | Extra comma-separated path globs that should be highlighted in Action-side evidence. These are review-sensitive paths, not automatic failures. |
| `block-protected-paths` | `false` | Escalate protected-path touches from warning to high severity. Use only when the repo is ready for blanket protected-path blocking. |
| `protect-default-branch` | `false` | Fail the step on a `push` to the repository default branch that was forced or that is not the merge of a merged pull request. Works in every mode. See [Protect the default branch](#protect-the-default-branch). |
| `default-branch` | empty | Name of the repository default branch, used only when the push payload does not carry `repository.default_branch`. Without it the Action asks `GET /repos/{owner}/{repo}`. |

## Modes

| Mode | Behavior |
|---|---|
| `auto` | Default. Requests GitHub OIDC, issues/reuses a hosted OAP passport, calls APort Verify, and falls back to `evidence-only` if hosted verification is unavailable. If `agent-id` or `api-key` is configured, hosted verification is required and does not silently fall back. |
| `hosted` | Requires GitHub OIDC and calls hosted APort Verify. No API key is needed for the free path; use `agent-id` plus `api-key` for customer-owned audit. Fails the workflow if hosted verification cannot return a valid signed decision. |
| `local-json` | Reads a trusted OAP passport JSON file and posts it to the same verifier as `body.passport`; the verifier skips hosted decision persistence. |
| `evidence-only` | No hosted passport, no verifier call, no network calls to APort. Attribution and structural checks only. |

Use `evidence-only` when running a local Action source from a checked-out PR head. Use `auto` or `hosted` from a pinned published Action version.

Hosted mode treats a missing, fallback, or invalid APort decision signature as `OAP.DECISION.SIGNATURE_INVALID`. Default `auto` mode falls back to labelled evidence-only reporting; explicit `hosted` mode fails so teams do not mistake missing hosted evidence for a verified check.

Protected paths are warning-level by default to keep first-time setup low-friction. They tell reviewers and APort policy which files deserve extra attention. If a repository wants every protected-path touch to fail closed, set `block-protected-paths: true` after the team has tuned the path list and rollout process.

Control-plane paths are the exception. `.github/workflows/**`, `.github/actions/**` and `.aport/policy.*` can change what the guard enforces, so a change there fails the check even when `block-protected-paths` is `false`.

That rule has one carve-out, for the pull request that installs the guard. When every control-plane file in a PR is newly **added** and each one is a workflow whose `steps` install this action, the finding is reported as a warning rather than blocking, and the summary says so. There is no prior configuration to weaken on an install, and failing the PR that adds the workflow is how a check gets removed instead of adopted.

The carve-out is narrow on purpose. It applies only to PR-style validation (`pull_request`, `pull_request_review`, and `merge_group`), never to a direct push and never to `pull_request_target`, which runs with the base repository's secrets against head content the fork author controls. The added workflow must also read as an install as a whole file: no `run:` steps, and no action steps besides the guard and `actions/checkout`, so a workflow that installs the guard and also does something else does not qualify. A PR still fails when it modifies or deletes an existing workflow, changes an existing `.aport` policy, adds any control-plane file that is not part of the install, calls a reusable workflow, adds a non-allowlisted action, or introduces a permission escalation or a `pull_request_target` trigger. Those raise their own findings, which the carve-out does not touch. Setting `block-protected-paths: true` opts out of it entirely.

Unpinned actions are a conditional case. When the trusted base policy sets `github.require_pinned_actions: true`, an install that leaves any action unpinned loses the carve-out and fails, because `OAP.REPO.UNPINNED_ACTION` is only warning-level and would otherwise leave the PR with nothing blocking. Pin the actions and the install passes. Without `require_pinned_actions`, no unpinned-action finding is raised at all and an unpinned install passes as a warning.

## Outputs

| Output | Description |
|---|---|
| `actor-class` | `human`, `known_bot`, `coding_agent`, `unknown_automation`, or `unattributed` |
| `confidence` | `high`, `medium`, or `low` |
| `provenance` | `ci_time` for hosted OIDC decisions, `local_json` for local-json mode, or `unattributed` for evidence-only |
| `decision-id` | Hosted/local verifier decision ID when available |
| `outcome` | Decision outcome when available |
| `structural-findings` | JSON array of report-only structural findings |
| `push-classification` | For a `push` to a branch: `direct`, `merged_pull_request`, `forced`, `created` (the push created the branch), or `unknown` (the classification could not be completed). `not_push` for every other event, and for a `push` whose ref is not a branch (a tag, `refs/pull/...`), which branch protection has no opinion on |

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

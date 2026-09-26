# Changelog

All notable changes to the APort Policy Verify Action will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Automated release workflow for `aporthq/policy-verify-action` that tags the next patch release after a synced PR is merged and updates major/minor convenience tags.
- Conservative PR actor classification: `human`, `known_bot`, `coding_agent`, and `unknown_automation`.
- APort commit trailer recognition for `APort-Session`, `APort-Decision`, and `APort-Agent`.
- Report-only structural findings for protected paths, `pull_request_target`, workflow write-permission escalation, and OIDC token permission changes.
- High-severity suspicious payload findings for encoded execution and remote shell execution introduced in sensitive workflow, action, build-config, policy, verifier, package, or script surfaces.
- High-severity missing-evidence findings when GitHub omits patch/content data for sensitive execution or configuration surfaces.
- Fixture-driven tests with real APortHQ PR payloads and zero false `coding_agent` classifications for human-authored fixtures.

### Changed
- Reframed the first public slice as report-only agent attribution and repository provenance.
- Removed required APort account, passport, API key, hosted verifier call, failing enforcement, and default PR comments from the free Action path.
- The Action now writes a GitHub job summary and exits 0.
- Hosted verification payloads now send compact structural findings and avoid duplicate changed-file evidence, keeping repository guard requests within the verifier's hot-path request budget.

### Security
- The install carve-out no longer accepts a workflow that carries a guard step
  alongside other work. A file with a real `uses: aporthq/policy-verify-action`
  step plus a `run:` exfiltrating `GITHUB_TOKEN` produced no blocking finding,
  because the id-token/contents pair reads as OIDC and is only a warning. The
  added workflow must now hold as an install as a whole file: no `run:` steps,
  and no action steps besides the guard and `actions/checkout`.
- `pull_request_target` no longer receives the carve-out. It runs with the base
  repository's secrets against fork-authored head content, and the README and
  this changelog both already described the carve-out as pull request and merge
  queue validation only.

### Fixed
- The pull request that installs the guard no longer fails the check it is
  installing. `.github/workflows/**` is a control-plane path and fail-closed
  regardless of `block-protected-paths`, so a first install went red on its own
  workflow file. When every control-plane file in a pull request is newly added
  and each is a workflow whose `steps` install this action, it is now reported
  as a warning, with `bootstrap_install` in the finding details. The carve-out
  applies to PR-style validation (`pull_request`, `pull_request_review`, and
  `merge_group`) only, never to a direct push. Modifying or deleting an
  existing workflow, changing an existing `.aport` policy, adding a
  control-plane file unrelated to the install, or introducing a permission
  escalation or `pull_request_target` all still fail, as does an unpinned
  install when the trusted base policy sets `github.require_pinned_actions`.
  `block-protected-paths: true` opts out.
- The guard marker is now read from parsed workflow steps rather than raw
  lines, so a `run: |` block scalar quoting `uses: aporthq/policy-verify-action`
  no longer makes an unrelated workflow look like an install.
- Reusable workflow calls, quoted `uses` step keys, and other executable action
  references are now parsed before applying the install carve-out, so a workflow
  that does more than install the guard remains fail-closed.
- README said protected paths were warning-level by default for low-friction
  setup, which control-plane handling made unreachable. It now documents both
  the control-plane rule and the install carve-out.

### Security
- Treat `id-token: write` as GitHub OIDC authentication permission, not repository write access. Newly introduced OIDC permission is still reported for review, while broad workflow write permissions remain high-severity.

### Planned Features
- Support for additional policy packs
- Enhanced error reporting and debugging
- Custom policy pack validation
- Integration with GitHub security features
- Advanced context mapping options
- Performance optimizations

---

## [1.0.12] - 2026-09-24

These changes publish as a patch, not as `1.1.0`, because the publisher only
ever increments a patch. The mirror `aporthq/policy-verify-action` releases
itself from `.github/workflows/release.yml` in this directory, which runs on
every push to `main`. For a commit with no semver tag of its own it takes the
highest existing `vX.Y.Z` tag and computes
`next_tag="v${major}.${minor}.$((patch + 1))"`. There is no path in that script
that raises the minor, so whatever this lands as, it lands as
`v1.0.(latest + 1)`.

`git ls-remote --tags https://github.com/aporthq/policy-verify-action.git` on
2026-09-25 reports `v1.0.11` as the highest semver tag, so the next publish is
`v1.0.12`. Tagging `v1.1.0` after the merge does not help: the mirror PR merge
is itself a push to `main`, so the release job has already run and pushed
`v1.0.12`, and a `v1.1.0` tag added afterwards would sit on a commit the
workflow then treats as already tagged and merely repairs artifacts for.

For a minor release to be correct here, the publisher has to change first. It
would need to read the intended version out of this file (or out of a
`package.json` version bumped in the same commit) instead of deriving it from
the tag list. Until that exists, entries here are numbered as patches, and this
note is the reason rather than a preference.

### Added
- `protect-default-branch` input (default `false`). On a `push` to the
  repository default branch it fails the step when the payload's `forced` flag
  is set (`OAP.REPO.FORCE_PUSH`) or when the pushed tip is not the
  `merge_commit_sha` of a merged pull request
  (`OAP.REPO.DIRECT_PUSH_DEFAULT_BRANCH`). It works in every mode and is the
  only setting that fails a push in `auto` mode. It runs after the push lands,
  so pair it with a GitHub ruleset that blocks force pushes and requires a
  pull request.
- `push-classification` output: `direct`, `merged_pull_request`, `forced`,
  `created`, `unknown` (the classification could not be completed), or
  `not_push` (not a push event, or a push whose ref is not a branch).
- Push classification reads the payload's `forced` flag. A forced push is
  classified `forced` without a pull request lookup. A forced push to the
  default branch is reported as a warning-level `OAP.REPO.FORCE_PUSH` finding
  even when the input is off.
- The `repo.push` verify evidence carries `push_forced`,
  `push_to_default_branch`, and `default_branch` next to the existing
  `push_classification`.
- The job summary and run log show the push classification and whether
  default branch protection is on, and name the reason when it blocks.
- `default-branch` input (optional). Names the repository default branch when
  the push payload does not carry `repository.default_branch`. Without it the
  Action reads `GET /repos/{owner}/{repo}`; if that fails too and
  `protect-default-branch` is on, a branch push fails closed.
- `created` value for `push-classification`: the push created the branch
  (`before` is the zero SHA). It is not treated as a direct push, including
  when the default branch name cannot yet be resolved. A branch deletion is
  never looked up.

### Changed
- A merged pull request is no longer accepted on the pushed tip alone. The
  commits between `before` and `after` are checked against the pull request's
  commits, so `git push origin feature:main` and a local merge pushed with an
  extra commit are classified `direct`. Merge commit, squash, and rebase
  merges made by GitHub pass. When the compare or the pull request commits
  cannot be read the classification is `unknown`.
- The `commits/{sha}/pulls` lookup is retried three times, ten seconds apart,
  on network errors, `429`, `403` responses with GitHub rate-limit evidence,
  and `5xx` only. A `401`, ordinary permission-denied `403`, `404`, `422`,
  or an unparseable body ends the lookup with `unknown` at once. An empty result
  is retried on the same schedule for every push to the default branch, with
  or without `protect-default-branch`, so the output does not depend on the
  input. Once an attempt has returned an empty list the push is `direct`
  regardless of later errors; `unknown` means no attempt answered.
- A fatal error on a `push` to the default branch with `protect-default-branch`
  on exits 1 and writes `push-classification=unknown`. When the default branch
  cannot be read from the payload or the `default-branch` input the push is
  treated as a default-branch push. A push to another branch, or a tag push,
  stays report-only.
- Merge queue groups of two or more pull requests using the merge commit or
  rebase strategy are classified `direct`; only the pull request whose merge
  commit is the pushed tip is reconciled.
- The default-branch push findings stay Action-side (summary, annotations,
  `structural-findings` output, exit code) and are no longer sent to the
  hosted verifier as structural findings. The push facts still go to the
  verifier as plain evidence fields.
- The run log and the job summary print the same "Default branch protection"
  value: `disabled`, `enabled`, or `enabled (not the default branch)`.
- The pull request lookup and the push compare request run concurrently.

### Security
- `GITHUB_API_URL` over plain `http://` is refused before the token is sent,
  except for `127.0.0.1`, `localhost`, and `[::1]` (the end-to-end tests use a
  local stand-in) or when `APORT_ALLOW_INSECURE_GITHUB_API=1` is set.

### Fixed
- A `push` compare that returns HTTP 200 with no commit list is now `unknown`,
  not `merged_pull_request`. `summarizeCompare` set `commitsIncomplete: true`
  while leaving `ok: true`, so reconciliation ran with zero pushed commits and
  every check it makes silently passed: the count rule compares
  `total_commits` (also 0) against the pull request's commit count, and the
  parent rule has nothing to walk. A locally pushed merge carrying extra
  commits could therefore clear `protect-default-branch` on no commit evidence
  at all. The reason code is `push_commits_unavailable` and the pull request
  commits are no longer fetched, since there is nothing to compare them to. All
  three shapes that produce an empty list are covered: an explicit `[]`, a
  missing `commits` field, and a `commits` field that is not an array.
- A tag push is now classified `not_push`, with reason `non_branch_ref`.
  A new tag supplies `created: true` and a zero `before` SHA exactly like a new
  branch, and the `created` return ran before `branch` was checked for
  emptiness, so `refs/tags/v1` came out `created` with reason `branch_created`;
  an updated tag fell through to `direct`. Neither is a branch event. The ref is
  now settled first, ahead of `forced` and `created`, which matches what
  `fatalRequiresProtectedPush` already did with a non-branch ref (exempt it) and
  what the README documents. `not_push` joins `PUSH_CLASSIFICATIONS` so
  `resolvePushClassificationOutput` passes it through instead of coercing it to
  `unknown`, which would have failed a protected run on a tag.
- `isNonBranchRef` in `src/git-ref.js` is now the single owner of "is this ref a
  branch". `src/index.js` asked it inline as `ref && !branchFromGitRef(ref)` and
  now delegates, so the classifier and the fatal-error path cannot drift. An
  absent ref is not a non-branch ref: "no ref supplied" and "the ref is a tag"
  are different facts and only the second exempts a push from protection.
- The pull request association lookup now reads the whole list instead of one
  short page. `GET /commits/{sha}/pulls` was requested with `per_page=10` and
  never paginated, so a commit with more than ten associations could have the
  merged pull request targeting this branch fall outside the response. The
  classification came back `direct` and `protect-default-branch` blocked a
  legitimate merge, with nothing in the evidence to say the list had been cut
  short. The request is now `per_page=100` through the existing
  `githubRequestAllPages`, up to `PUSH_LOOKUP_MAX_PAGES` (5, so 500
  associations), plus one sentinel page only when the first five are full.
- A genuinely truncated association list is now `unknown` with reason
  `associated_pr_list_truncated`, not `direct`. Raising the page size alone would
  have moved the boundary rather than removed it, and the failure at the new
  boundary is the same one: "no match in the pages we read" is not evidence that
  no merge exists. The sentinel keeps exactly 500 non-matching associations from
  being mislabeled as truncated. Failing closed to `unknown` still blocks the
  push when the input is on, but it names the reason, so the block is
  diagnosable instead of looking like a developer pushing straight to `main`.
  The truncation also carries a warning naming the commit and the 500-association
  bound.
- `test/github.test.js` asserted the lookup path with
  `path.includes("/pulls?per_page=10")`, which is a prefix of `per_page=100` and
  so passed both before and after the change. It now asserts
  `"/pulls?per_page=100&page=1"`, the full paginated spelling.

### Documentation
Seven factual corrections, each one a statement that was wrong rather than
unclear.

- `README.md` said every push receives one of five classifications. The tag fix
  added a sixth, `not_push`, which the Outputs table below it already listed. The
  sentence now scopes the five to a push to a branch and names `not_push` for the
  rest.
- `README.md` said the classification is `unknown` only when no attempt returned
  an answer. Truncation is now a second route to `unknown`; the pagination and
  page budget are documented with it.
- `policies/deliverable.task.complete.v1/README.md` said every other
  capability's limits are scalars or string arrays. `payments.charge` takes
  `currency_limits`, a nested object keyed by currency code. What is unique to
  `acceptance_criteria` is being an array of objects, not being nested, and the
  text now says that, matching `policies/README.md` and
  `docs/CAPABILITIES-AND-LIMITS.md`, which were already corrected.
- The same README presented the 100-attestation cap as part of the policy
  context schema. `policy.json` now carries `"maxItems": 100` on
  `criteria_attestations` so it agrees with the route's `Joi.array().max(100)`,
  but agreeing on paper is as far as that goes: the in-repo evaluator's schema
  step is `validatePolicyFields`, which checks required-field presence and
  nothing else, so `maxItems`, `maxLength` and the `output_type` enum are never
  applied there. Sending 101 attestations to `evaluateGenericPolicy` still
  returns `allow: true` with `oap.allowed`, measured by running it. The README now
  says the cap binds on the hosted route and is advisory locally.
- The same README claimed test 9b exercised the strict `met` check. It exercised
  `tests_passing` only; nothing covered `met`. Tests 2b and 2c now do, and the
  text names them and says which mutation each one catches.
- `spec/oap/capability-registry.md` said the request cannot add criteria. What it
  cannot do is change which criteria are required: `limits` comes from
  `passport.limits` and nothing in `context` is merged into it. Extra
  attestations are a different matter and are currently accepted. Verified by
  running the evaluator: an extra attestation with an id in no passport criterion
  plus `met: true` and evidence gives `allow: true` / `oap.allowed`; the same
  extra with `met: false` gives `oap.criteria_not_met`; an unknown id alone,
  leaving a passport criterion unattested, gives `oap.criteria_incomplete`, so it
  does not stand in for a real one. This matches what the pack README already
  said.
- `spec/oap/oap-spec.md` narrowed `limits` to the primary capability's block,
  which made the expression example directly above it invalid:
  `limits.payments.charge.max_per_tx` descends through `payments` from an object
  that is already `passport.limits["payments.charge"]`. The example is now
  `limits.max_per_tx`. The narrowing itself was also only half the rule.
  `evaluateCustomRules` tries `passport.limits[primaryCapability]`, then the
  dotted path, and leaves `limits` as `passport.limits` whole if neither resolves
  to an object, which is why packs in this repository use both spellings. Both
  branches are documented now. The only other `limits` expression in that file,
  `limits.allowed_commands` for `system.command.execute.v1`, was already correct
  under either reading.

### Verification
Measured in this worktree on 2026-09-25, not carried over from another run.

Repository-wide baseline (`AGENTS.md`, "Verification baseline"), with
`node_modules` installed. The root `npm install` fails on a pre-existing peer
conflict between `wrangler@4.139.0` and `@cloudflare/workers-types@4` in the
`web` workspace, so the install used `npm install --legacy-peer-deps`:

- `npx vitest run`: 74 test files passed, 772 tests passed, 0 failures. The two
  added tests are 2b and 2c in
  `policies/deliverable.task.complete.v1/tests/deliverable-task-complete-policy.test.ts`,
  which took that file from 22 to 24.
- `npx tsc --noEmit -p tsconfig.json 2>&1 | grep -c "error TS"`: **611** with
  these changes applied. This matches the `AGENTS.md` baseline, so no TypeScript
  error is new.

  An earlier version of this entry justified an unchanged count by saying every
  changed file was `.js` under `integrations/github/actions/policy-verify` and
  therefore outside the root project. That was not true, in two ways. The commit
  also changes `action.yml`, several READMEs, `CHANGELOG.md`, files under
  `policies/` and files under `spec/oap`. And the root project is not limited
  to `.ts`: `tsconfig.json` sets `resolveJsonModule`, so
  `npx tsc -p tsconfig.json --listFilesOnly` lists 470 files outside
  `node_modules`, 448 `.ts` and 22 `.json`, and all 21 `policies/*/policy.json`
  are among them. `policies/deliverable.task.complete.v1/policy.json` is changed
  here and is compiled. The measured count above is the evidence, not an
  argument from which paths the project includes.
- `node test/run.js` in this directory: 16 test files, all pass.

Mutation evidence (`AGENTS.md` §7: break the implementation and watch the suite
go red, naming the assertion). Each mutation was applied to `src/github.js`
alone, `node test/push-classification.test.js` was run, and the mutation was
reverted; `src/github.js` was then confirmed byte-identical to its pre-mutation
state with `diff`, and `npm test` confirmed green again.

1. Empty-commit guard disabled (`if (compare.commits.length === 0)` to
   `if (false && compare.commits.length === 0)`). Red at
   `test/push-classification.test.js:452`, message
   `compare with empty array commits must be unknown`,
   `actual: 'merged_pull_request'`, `expected: 'unknown'`. This is the bypass
   itself: without the guard the push is reported as a clean merge.
2. Non-branch ref check removed (the `isNonBranchRef(ref)` block deleted, which
   restores the pre-fix ordering). Red at
   `test/push-classification.test.js:495`, `'created' == 'not_push'`,
   `actual: 'created'`, `expected: 'not_push'`. This reproduces the original
   defect: a new tag push classified as a branch creation.
3. Condition in the `created`/`direct` path inverted
   (`created === true || isZeroSha(before)` to
   `created !== true && !isZeroSha(before)`). Red at
   `test/push-classification.test.js:69`, `'pr.merge' == 'repo.push'`,
   `actual: 'pr.merge'`, `expected: 'repo.push'`. The pre-existing
   branch-created test catches it, so that test measures something too.
4. Association lookup returned to a single page (the
   `githubRequestAllPages(pullsPath, request, PUSH_LOOKUP_MAX_PAGES)` call
   replaced with `request(`${pullsPath}&page=1`)`). Red at
   `test/push-classification.test.js:121`, message
   `a merged PR on the second page of associations must still be found`,
   `actual: 'direct'`, `expected: 'merged_pull_request'`. This is the defect the
   pagination fix closes: a merge found only on a later page read as a direct
   push.
5. Truncation guard disabled (`if (truncated) {` to `if (false && truncated) {`).
   Red at `test/push-classification.test.js:140`, message
   `a truncated association list must be unknown, not direct`,
   `actual: 'direct'`, `expected: 'unknown'`. Without the guard a capped list
   silently becomes `direct`, which is the failure mode the fix exists to avoid.

Mutation evidence for the `met` strictness tests, applied to
`functions/utils/policy/custom-validators.ts` and run with
`npx vitest run policies/deliverable.task.complete.v1/tests/deliverable-task-complete-policy.test.ts`.
Reverted and confirmed byte-identical with `diff` afterwards; the file is not
otherwise changed by this commit.

6. `a.met !== true` loosened to `a.met != true`. Red on
   `2c. DENY oap.criteria_not_met: met numeric 1 (strict check)`,
   `expected true to be false`. Test 2b stayed green: `"true" != true` is `true`
   because the string coerces to `NaN`, so the string case cannot catch this
   mutation and 2c is the assertion that does.
7. `a.met !== true` loosened to `!a.met`. Red on both
   `2b. DENY oap.criteria_not_met: met string 'true' (strict check)` and 2c,
   `expected true to be false` on each. Both tests are therefore load-bearing
   and neither is redundant.

Mutation evidence for the fatal push handler, applied to `src/index.js` and run
with `node test/index.test.js`. Reverted and confirmed green afterwards.

8. Created-branch exemption disabled
   (`event?.forced !== true && (event?.created === true || isZeroSha(event?.before))`
   changed to `false && ...`). Red at `test/index.test.js:384`,
   `actual: true`, `expected: false`. This proves a fatal error after branch
   creation would have re-entered the protected-push failure path without the
   exemption.

Not done, and why: the conformance-suite and pack-README work that the OAP spec
needs before it can leave Working Draft is out of scope here; it is tracked in
`spec/oap/VERSION.md` under "What Candidate Is Waiting On".

---

## [1.0.0] - 2025-01-09

### Added
- Initial release of APort Policy Verify Action
- Support for `code.repository.merge.v1` policy pack
- Comprehensive GitHub context mapping to APort policy context
- Automatic PR commenting with policy results
- Retry logic with exponential backoff for API reliability
- API key authentication support
- Configurable timeouts and error handling
- Input validation for agent ID and policy pack formats
- Rich PR comments with detailed policy information
- Support for multiple GitHub event triggers
- Manual workflow dispatch capability
- Comprehensive documentation and examples

### Features
- **Policy Enforcement**: Verify PRs against APort agent policies
- **Context Mapping**: Automatic mapping of GitHub context to APort requirements
- **Flexible Configuration**: Customizable policy packs, timeouts, and enforcement rules
- **PR Comments**: Automatic PR comments with policy results and next steps
- **Retry Logic**: Built-in retry mechanism with exponential backoff
- **Authentication**: Support for API key authentication
- **Multiple Triggers**: Support for various GitHub events and manual dispatch
- **Input Validation**: Comprehensive validation of all inputs
- **Error Handling**: Robust error handling with detailed logging

### Technical Details
- **API Integration**: Full integration with APort Policy Verification API
- **Context Fields**: Support for all required policy context fields:
  - `agent_id`, `policy_id`, `idempotency_key`
  - `action`, `repository`, `branch`, `base_branch`
  - `files_changed`, `lines_added`, `lines_removed`, `pr_size_kb`
  - `github_actor`, `github_app`, `requires_review`
  - `labels`, `reviews`, `is_draft`, `is_mergeable`
  - `title`, `description`
- **Response Parsing**: Correct parsing of API response structure
- **Validation**: Joi schema validation for all policy contexts
- **Testing**: Comprehensive test suite with mock API server

### Documentation
- Complete README with setup guide and examples
- Comprehensive example workflows for various use cases
- Troubleshooting guide with common issues and solutions
- API documentation and context mapping reference
- Security best practices and configuration guide

### Examples
- Basic repository protection workflow
- Advanced configuration with custom settings
- Multi-policy verification setup
- Conditional verification based on actor
- Manual dispatch with custom parameters
- Integration with other CI/CD actions
- Environment-specific policy enforcement

---

## Version History

- **1.0.0** - Initial production release with full feature set
- **0.9.0** - Beta release with core functionality
- **0.8.0** - Alpha release with basic policy verification

## Support

For support and questions:
- 📖 [APort](https://aport.io)
- 🚀 [GitHub Actions quickstart](https://aport.io/quickstart/#github)
- 🛡️ [GitHub security guide](https://aport.io/blog/secure-github-actions-ai-coding-agents-protected-paths)
- 🐛 [Issue Tracker](https://github.com/aporthq/policy-verify-action/issues)
- 📧 [Email Support](mailto:support@aport.io)

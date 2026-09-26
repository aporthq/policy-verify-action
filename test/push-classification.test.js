const assert = require("assert");
const { classifyPushAction, getPullRequestData } = require("../src/github");
const { buildVerifyContext } = require("../src/context");
const { isNonBranchRef } = require("../src/git-ref");
const {
  evaluateDefaultBranchProtection,
  resolvePushClassificationOutput,
} = require("../src/push-protection");

const AFTER = "b".repeat(40);
const BEFORE = "a".repeat(40);
const HEAD = "e".repeat(40);
const P1 = "1".repeat(40);
const P2 = "2".repeat(40);
const D = "d".repeat(40);
const ZERO = "0".repeat(40);
const target = { owner: "aporthq", repo: "example", before: BEFORE, after: AFTER, branch: "main" };
const mergedPull = {
  number: 42,
  state: "closed",
  merged_at: "2026-09-04T12:00:00Z",
  base: { ref: "main" },
  head: { sha: HEAD },
  merge_commit_sha: AFTER,
};

function recorder(responses) {
  const calls = [];
  const sleeps = [];
  const request = async (path) => {
    calls.push(path);
    const next = responses[Math.min(calls.length, responses.length) - 1];
    return typeof next === "function" ? next() : next;
  };
  const sleep = async (ms) => {
    sleeps.push(ms);
  };
  return { calls, sleeps, request, sleep };
}

const ok = (data) => ({ ok: true, status: 200, data });
const fail = (status) => ({ ok: false, status, data: [], error: "upstream" });

async function classifierTests() {
  // A forced push is classified from the payload and never consults the API,
  // even when the tip happens to be a merge commit.
  const forced = recorder([ok([mergedPull])]);
  const forcedResult = await classifyPushAction(
    { ...target, forced: true },
    forced.request,
    { sleep: forced.sleep },
  );
  assert.equal(forcedResult.action, "repo.push");
  assert.equal(forcedResult.evidence.push_classification, "forced");
  assert.equal(forcedResult.evidence.push_forced, true);
  assert.equal(forced.calls.length, 0);
  assert.deepEqual(forcedResult.warnings, []);

  // A push that creates the branch has no merge to look up. Both the payload
  // flag and the zero before SHA mean the same thing.
  for (const input of [
    { ...target, created: true },
    { ...target, before: ZERO },
  ]) {
    const created = recorder([ok([mergedPull])]);
    const createdResult = await classifyPushAction(input, created.request, {
      sleep: created.sleep,
    });
    assert.equal(createdResult.action, "repo.push");
    assert.equal(createdResult.evidence.push_classification, "created");
    assert.equal(createdResult.evidence.push_classification_reason, "branch_created");
    assert.equal(createdResult.evidence.push_forced, false);
    assert.equal(created.calls.length, 0);
  }

  // A branch deletion (zero after SHA) is never looked up either.
  for (const input of [
    { ...target, deleted: true },
    { ...target, after: ZERO },
  ]) {
    const deleted = recorder([ok([mergedPull])]);
    const deletedResult = await classifyPushAction(input, deleted.request, {
      sleep: deleted.sleep,
    });
    assert.equal(deletedResult.evidence.push_classification, "direct");
    assert.equal(deletedResult.evidence.push_classification_reason, "branch_deleted");
    assert.equal(deleted.calls.length, 0);
  }

  // Merged pull request on the first attempt: a candidate carrying the PR.
  const merged = recorder([ok([mergedPull])]);
  const mergedResult = await classifyPushAction(target, merged.request, {
    sleep: merged.sleep,
  });
  assert.equal(mergedResult.action, "pr.merge");
  assert.equal(mergedResult.evidence.push_classification, "merged_pull_request");
  assert.equal(mergedResult.evidence.push_forced, false);
  assert.equal(mergedResult.evidence.pull_request_number, 42);
  assert.equal(mergedResult.pullRequest, mergedPull);
  assert.equal(merged.calls.length, 1);
  assert.deepEqual(merged.sleeps, []);

  // The merge commit's pull request is not guaranteed to be on the first page
  // of /commits/{sha}/pulls. A commit with more than one page of associations
  // whose matching merge sits on page two used to be classified `direct`,
  // because the lookup read a single page and never paginated. Page one here is
  // a full 100 unrelated pull requests, so the pager keeps going.
  const otherPull = (number) => ({
    number,
    state: "closed",
    merged_at: "2026-09-04T12:00:00Z",
    base: { ref: "release" },
    head: { sha: P1 },
    merge_commit_sha: D,
  });
  const fullPage = Array.from({ length: 100 }, (_, index) => otherPull(index + 1));
  const laterPage = recorder([ok(fullPage), ok([mergedPull])]);
  const laterPageResult = await classifyPushAction(target, laterPage.request, {
    sleep: laterPage.sleep,
  });
  assert.equal(
    laterPageResult.evidence.push_classification,
    "merged_pull_request",
    "a merged PR on the second page of associations must still be found",
  );
  assert.equal(laterPageResult.evidence.pull_request_number, 42);
  assert.equal(laterPage.calls.length, 2);
  assert(laterPage.calls[0].includes("per_page=100&page=1"));
  assert(laterPage.calls[1].includes("per_page=100&page=2"));
  assert.deepEqual(laterPage.sleeps, []);

  // Exactly full page budget with no sentinel result is complete evidence,
  // not truncation. This stays `direct` because page 6 proved there are no
  // more associations.
  const exactBudget = recorder([
    ok(fullPage),
    ok(fullPage),
    ok(fullPage),
    ok(fullPage),
    ok(fullPage),
    ok([]),
  ]);
  const exactBudgetResult = await classifyPushAction(target, exactBudget.request, {
    sleep: exactBudget.sleep,
  });
  assert.equal(exactBudgetResult.evidence.push_classification, "direct");
  assert.equal(exactBudget.calls.length, 6);
  assert.deepEqual(exactBudgetResult.warnings, []);

  // A list longer than the page budget is not evidence that no merge exists.
  // The sentinel page confirms there is more data, so the classification must
  // fail closed to `unknown` with the truncation reason rather than to
  // `direct`, which would block a legitimate merge with no way to tell why.
  const truncatedPages = recorder([ok(fullPage)]);
  const truncatedResult = await classifyPushAction(target, truncatedPages.request, {
    sleep: truncatedPages.sleep,
  });
  assert.equal(
    truncatedResult.evidence.push_classification,
    "unknown",
    "a truncated association list must be unknown, not direct",
  );
  assert.equal(
    truncatedResult.evidence.push_classification_reason,
    "associated_pr_list_truncated",
  );
  assert.equal(truncatedResult.evidence.push_forced, false);
  assert.equal(truncatedPages.calls.length, 6);
  assert.equal(truncatedResult.warnings.length, 1);
  assert.match(truncatedResult.warnings[0], /more than 500 associated pull requests/);

  // Direct push: an empty result is final by default (no retry, no sleep).
  const direct = recorder([ok([])]);
  const directResult = await classifyPushAction(target, direct.request, {
    sleep: direct.sleep,
  });
  assert.equal(directResult.evidence.push_classification, "direct");
  assert.equal(directResult.evidence.push_forced, false);
  assert.equal(direct.calls.length, 1);
  assert.deepEqual(direct.sleeps, []);

  // With retryOnNoMatch the empty result is retried up to the attempt budget,
  // with a delay between attempts, before the push is called direct.
  const directRetried = recorder([ok([])]);
  const directRetriedResult = await classifyPushAction(
    target,
    directRetried.request,
    { sleep: directRetried.sleep, retryOnNoMatch: true, delayMs: 7 },
  );
  assert.equal(directRetriedResult.evidence.push_classification, "direct");
  assert.equal(directRetried.calls.length, 3);
  assert.deepEqual(directRetried.sleeps, [7, 7]);

  // The commit/pulls index lagging a merge: empty, then the merged PR.
  const lagging = recorder([ok([]), ok([mergedPull])]);
  const laggingResult = await classifyPushAction(target, lagging.request, {
    sleep: lagging.sleep,
    retryOnNoMatch: true,
  });
  assert.equal(laggingResult.evidence.push_classification, "merged_pull_request");
  assert.equal(lagging.calls.length, 2);
  assert.equal(lagging.sleeps.length, 1);

  // Transient failures (network, 429, 5xx) are retried and a later success wins.
  for (const status of [0, 429, 502]) {
    const flaky = recorder([fail(status), ok([mergedPull])]);
    const flakyResult = await classifyPushAction(target, flaky.request, {
      sleep: flaky.sleep,
    });
    assert.equal(flakyResult.evidence.push_classification, "merged_pull_request", `status ${status}`);
    assert.equal(flaky.calls.length, 2, `status ${status}`);
    assert.deepEqual(flakyResult.warnings, []);
  }

  // An error followed by an empty result is a direct push, not a failure.
  const errorThenEmpty = recorder([fail(500), ok([])]);
  const errorThenEmptyResult = await classifyPushAction(
    target,
    errorThenEmpty.request,
    { sleep: errorThenEmpty.sleep },
  );
  assert.equal(errorThenEmptyResult.evidence.push_classification, "direct");
  assert.deepEqual(errorThenEmptyResult.warnings, []);

  // A confirmed empty result followed by errors is still direct: the empty
  // answer was real, and a later outage does not turn it into unknown.
  const emptyThenErrors = recorder([ok([]), fail(503), fail(503)]);
  const emptyThenErrorsResult = await classifyPushAction(
    target,
    emptyThenErrors.request,
    { sleep: emptyThenErrors.sleep, retryOnNoMatch: true },
  );
  assert.equal(emptyThenErrorsResult.evidence.push_classification, "direct");
  assert.equal(emptyThenErrorsResult.evidence.push_classification_reason, undefined);
  assert.equal(emptyThenErrors.calls.length, 3);
  assert.deepEqual(emptyThenErrorsResult.warnings, []);

  // Every attempt fails: fail closed with the unknown classification, and the
  // warning counts the failures.
  const down = recorder([fail(503)]);
  const downResult = await classifyPushAction(target, down.request, {
    sleep: down.sleep,
  });
  assert.equal(downResult.action, "repo.push");
  assert.equal(downResult.evidence.push_classification, "unknown");
  assert.equal(
    downResult.evidence.push_classification_reason,
    "associated_pr_lookup_failed",
  );
  assert.equal(downResult.evidence.push_forced, false);
  assert.equal(down.calls.length, 3);
  assert.equal(down.sleeps.length, 2);
  assert.equal(downResult.warnings.length, 1);
  assert.match(downResult.warnings[0], /after 3 failed attempts \(503\)/);
  assert.match(downResult.warnings[0], /treating push as direct/);

  // Two failures and then a definitive empty result: direct, no warning; the
  // failures did not make it unknown.
  const twoFailsThenEmpty = recorder([fail(500), fail(500), ok([])]);
  const twoFailsThenEmptyResult = await classifyPushAction(
    target,
    twoFailsThenEmpty.request,
    { sleep: twoFailsThenEmpty.sleep },
  );
  assert.equal(twoFailsThenEmptyResult.evidence.push_classification, "direct");
  assert.deepEqual(twoFailsThenEmptyResult.warnings, []);

  // Client errors are final: no retry, no sleep, unknown at once.
  for (const status of [401, 403, 404, 422]) {
    const denied = recorder([fail(status), ok([mergedPull])]);
    const deniedResult = await classifyPushAction(target, denied.request, {
      sleep: denied.sleep,
      retryOnNoMatch: true,
    });
    assert.equal(deniedResult.evidence.push_classification, "unknown", `status ${status}`);
    assert.equal(
      deniedResult.evidence.push_classification_reason,
      "associated_pr_lookup_failed",
    );
    assert.equal(denied.calls.length, 1, `status ${status}`);
    assert.deepEqual(denied.sleeps, []);
    assert.match(deniedResult.warnings[0], new RegExp(`after 1 failed attempt \\(${status}\\)`));
  }

  // A body that does not parse, or parses to something other than a list, is
  // final too.
  const unparseable = recorder([
    { ok: false, status: 200, data: [], error: "Unexpected token < in JSON" },
    ok([mergedPull]),
  ]);
  const unparseableResult = await classifyPushAction(target, unparseable.request, {
    sleep: unparseable.sleep,
  });
  assert.equal(unparseableResult.evidence.push_classification, "unknown");
  assert.equal(unparseable.calls.length, 1);
  assert.match(unparseableResult.warnings[0], /Unexpected token/);

  const notAList = recorder([ok({ message: "nope" }), ok([mergedPull])]);
  const notAListResult = await classifyPushAction(target, notAList.request, {
    sleep: notAList.sleep,
  });
  assert.equal(notAListResult.evidence.push_classification, "unknown");
  assert.equal(notAList.calls.length, 1);
  assert.match(notAListResult.warnings[0], /non-array/);

  // The attempt budget is honoured.
  const single = recorder([fail(500)]);
  await classifyPushAction(target, single.request, {
    sleep: single.sleep,
    attempts: 1,
  });
  assert.equal(single.calls.length, 1);
  assert.deepEqual(single.sleeps, []);
}

// Runs getPullRequestData for a push from BEFORE to AFTER on main with the
// given stand-in responses for the endpoints the push path touches.
async function pushWith({ pulls = ok([mergedPull]), compare, prCommits = ok([]), prFiles = prFilesOf(), event = {} } = {}) {
  const paths = [];
  const data = await getPullRequestData(
    { ref: "refs/heads/main", before: BEFORE, after: AFTER, forced: false, commits: [], ...event },
    async (path) => {
      paths.push(path);
      if (path.includes("/commits/") && path.includes("/pulls?")) return pulls;
      if (path.includes("/pulls/42/commits")) return prCommits;
      if (path.includes("/pulls/42/files")) return prFiles;
      if (path.includes("/compare/")) return compare;
      throw new Error(`unexpected request ${path}`);
    },
  );
  return { paths, data };
}

const commit = (sha, ...parents) => ({ sha, parents: parents.map((parent) => ({ sha: parent })) });
const file = (filename = "src/a.js", overrides = {}) => ({
  filename,
  status: "modified",
  additions: 1,
  deletions: 0,
  changes: 1,
  patch: `@@ -1,1 +1,1 @@ ${filename}\n context before\n-old\n+new\n context after`,
  ...overrides,
});
const compareOf = (commits, total = commits.length, files = [file()]) =>
  ok({ total_commits: total, commits, files });
const prCommitsOf = (...shas) => ok(shas.map((sha) => ({ sha })));
const prFilesOf = (...files) => ok(files.length > 0 ? files : [file()]);

async function reconciliationTests() {
  process.env.GITHUB_REPOSITORY = "aporthq/example";
  process.env.GITHUB_EVENT_NAME = "push";
  process.env.GITHUB_SHA = AFTER;

  // A merge commit merge: the PR commits plus a merge commit whose parents are
  // the old tip and the PR head.
  const mergeCommit = await pushWith({
    compare: compareOf([commit(P1, BEFORE), commit(HEAD, P1), commit(AFTER, BEFORE, HEAD)]),
    prCommits: prCommitsOf(P1, HEAD),
  });
  assert.equal(mergeCommit.data.pushClassification.push_classification, "merged_pull_request");
  assert.equal(mergeCommit.data.repositoryAction, "pr.merge");
  assert.equal(mergeCommit.data.pushClassification.pull_request_number, 42);
  assert.equal("pullRequest" in mergeCommit.data.pushClassification, false);
  assert.deepEqual(mergeCommit.data.warnings, []);
  assert(mergeCommit.paths.some((path) => path.includes("/pulls/42/commits?per_page=100")));

  // A squash merge: one new commit, none of the PR commits land as-is.
  const squash = await pushWith({
    compare: compareOf([commit(AFTER, BEFORE)]),
    prCommits: prCommitsOf(P1, HEAD),
  });
  assert.equal(squash.data.pushClassification.push_classification, "merged_pull_request");

  // A rebase merge: GitHub re-creates every PR commit with a new SHA.
  const rebase = await pushWith({
    compare: compareOf([commit(P2, BEFORE), commit(AFTER, P2)]),
    prCommits: prCommitsOf(P1, HEAD),
  });
  assert.equal(rebase.data.pushClassification.push_classification, "merged_pull_request");

  // `git push origin feature:main`: GitHub marks the open PR merged with its
  // own head as the merge commit. No merge happened; the branch was pushed.
  const fastForward = await pushWith({
    pulls: ok([{ ...mergedPull, head: { sha: AFTER } }]),
    compare: compareOf([commit(P1, BEFORE), commit(AFTER, P1)]),
    prCommits: prCommitsOf(P1, AFTER),
  });
  assert.equal(fastForward.data.pushClassification.push_classification, "direct");
  assert.equal(
    fastForward.data.pushClassification.push_classification_reason,
    "pull_request_head_pushed_directly",
  );
  assert.equal(fastForward.data.pushClassification.pull_request_number, 42);
  assert.equal(fastForward.data.repositoryAction, "repo.push");
  assert.equal(fastForward.paths.some((path) => path.includes("/pulls/42/commits")), false);
  assert.match(fastForward.data.warnings[0], /head of pull request #42 itself/);

  // A local merge pushed with a direct commit underneath: [P1, HEAD, D, M].
  // The PR lists a third commit so the count rule passes and the per-commit
  // check is what catches D.
  const localMerge = await pushWith({
    compare: compareOf([commit(P1, BEFORE), commit(HEAD, P1), commit(D, BEFORE), commit(AFTER, D, HEAD)]),
    prCommits: prCommitsOf(P1, HEAD, P2),
  });
  assert.equal(localMerge.data.pushClassification.push_classification, "direct");
  assert.equal(
    localMerge.data.pushClassification.push_classification_reason,
    "commits_outside_pull_request",
  );
  assert.match(localMerge.data.warnings[0], new RegExp(D.slice(0, 12)));

  // A locally forged merge can have the same parent graph as a GitHub merge
  // while adding extra file changes in the merge commit itself. Commit identity
  // checks alone cannot see that, so the landed file evidence must match the
  // pull request file evidence too.
  const forgedMerge = await pushWith({
    compare: compareOf(
      [commit(P1, BEFORE), commit(HEAD, P1), commit(AFTER, BEFORE, HEAD)],
      3,
      [file("src/a.js"), file("src/backdoor.js")],
    ),
    prCommits: prCommitsOf(P1, HEAD),
    prFiles: prFilesOf(file("src/a.js")),
  });
  assert.equal(forgedMerge.data.pushClassification.push_classification, "direct");
  assert.equal(
    forgedMerge.data.pushClassification.push_classification_reason,
    "pull_request_file_evidence_mismatch",
  );
  assert.match(forgedMerge.data.warnings[0], /files that landed/);

  // GitHub's PR-files and compare endpoints can report the same landed file
  // with different patch hunk text after base advancement. Stable file
  // identity and counters should classify this as the merged PR.
  const shiftedPatch = await pushWith({
    compare: compareOf(
      [commit(P1, BEFORE), commit(HEAD, P1), commit(AFTER, BEFORE, HEAD)],
      3,
      [file("src/a.js", { patch: "@@ -40,1 +40,1 @@\n context before\n-old\n+new\n context after" })],
    ),
    prCommits: prCommitsOf(P1, HEAD),
    prFiles: prFilesOf(file("src/a.js", { patch: "@@ -4,1 +4,1 @@\n context before\n-old\n+new\n context after" })),
  });
  assert.equal(
    shiftedPatch.data.pushClassification.push_classification,
    "merged_pull_request",
  );

  // If same-path content differs, the normalized patch signature still
  // fails closed even though absolute hunk line numbers are ignored.
  const contentMismatch = await pushWith({
    compare: compareOf(
      [commit(P1, BEFORE), commit(HEAD, P1), commit(AFTER, BEFORE, HEAD)],
      3,
      [file("src/a.js", { patch: "@@ -40,1 +40,1 @@\n context before\n-old\n+landed\n context after" })],
    ),
    prCommits: prCommitsOf(P1, HEAD),
    prFiles: prFilesOf(
      file("src/a.js", { patch: "@@ -4,1 +4,1 @@\n context before\n-old\n+pull-request\n context after" }),
    ),
  });
  assert.equal(contentMismatch.data.pushClassification.push_classification, "direct");
  assert.equal(
    contentMismatch.data.pushClassification.push_classification_reason,
    "pull_request_file_evidence_mismatch",
  );

  const locationMismatch = await pushWith({
    compare: compareOf(
      [commit(P1, BEFORE), commit(HEAD, P1), commit(AFTER, BEFORE, HEAD)],
      3,
      [file("src/a.js", { patch: "@@ -40,1 +40,1 @@\n first occurrence\n-old\n+new\n first tail" })],
    ),
    prCommits: prCommitsOf(P1, HEAD),
    prFiles: prFilesOf(
      file("src/a.js", { patch: "@@ -4,1 +4,1 @@\n second occurrence\n-old\n+new\n second tail" }),
    ),
  });
  assert.equal(locationMismatch.data.pushClassification.push_classification, "direct");
  assert.equal(
    locationMismatch.data.pushClassification.push_classification_reason,
    "pull_request_file_evidence_mismatch",
  );

  const missingPatch = await pushWith({
    compare: compareOf(
      [commit(P1, BEFORE), commit(HEAD, P1), commit(AFTER, BEFORE, HEAD)],
      3,
      [file("src/a.bin", { patch: undefined })],
    ),
    prCommits: prCommitsOf(P1, HEAD),
    prFiles: prFilesOf(file("src/a.bin", { patch: undefined })),
  });
  assert.equal(missingPatch.data.pushClassification.push_classification, "unknown");
  assert.equal(
    missingPatch.data.pushClassification.push_classification_reason,
    "pull_request_file_patch_unavailable",
  );

  const contextlessModifiedPatch = await pushWith({
    compare: compareOf(
      [commit(P1, BEFORE), commit(HEAD, P1), commit(AFTER, BEFORE, HEAD)],
      3,
      [file("src/a.js", { patch: "@@ -40,1 +40,1 @@\n-old\n+new" })],
    ),
    prCommits: prCommitsOf(P1, HEAD),
    prFiles: prFilesOf(file("src/a.js", { patch: "@@ -4,1 +4,1 @@\n-old\n+new" })),
  });
  assert.equal(
    contextlessModifiedPatch.data.pushClassification.push_classification,
    "unknown",
  );
  assert.equal(
    contextlessModifiedPatch.data.pushClassification.push_classification_reason,
    "pull_request_file_patch_unavailable",
  );

  const prFilesDown = await pushWith({
    compare: compareOf([commit(AFTER, BEFORE)]),
    prCommits: prCommitsOf(P1, HEAD),
    prFiles: fail(500),
  });
  assert.equal(prFilesDown.data.pushClassification.push_classification, "unknown");
  assert.equal(
    prFilesDown.data.pushClassification.push_classification_reason,
    "pull_request_files_unavailable",
  );
  assert.match(prFilesDown.data.warnings.join("\n"), /files of pull request #42/);

  const prFilesEmpty = await pushWith({
    compare: compareOf([commit(AFTER, BEFORE)]),
    prCommits: prCommitsOf(P1, HEAD),
    prFiles: ok([]),
  });
  assert.equal(prFilesEmpty.data.pushClassification.push_classification, "unknown");
  assert.equal(
    prFilesEmpty.data.pushClassification.push_classification_reason,
    "pull_request_files_unavailable",
  );
  assert.match(prFilesEmpty.data.warnings.join("\n"), /file evidence/);

  // The PR commits with one extra commit on top, pushed as the tip.
  const descendant = await pushWith({
    compare: compareOf([commit(P1, BEFORE), commit(HEAD, P1), commit(AFTER, HEAD)]),
    prCommits: prCommitsOf(P1, HEAD),
  });
  assert.equal(descendant.data.pushClassification.push_classification, "direct");
  assert.equal(
    descendant.data.pushClassification.push_classification_reason,
    "pull_request_head_pushed_directly",
  );

  // More commits than the PR plus a merge commit: direct on the count alone.
  const tooMany = await pushWith({
    compare: compareOf([commit(P1, BEFORE), commit(D, P1), commit(HEAD, D), commit(AFTER, BEFORE, HEAD)]),
    prCommits: prCommitsOf(P1, HEAD),
  });
  assert.equal(tooMany.data.pushClassification.push_classification, "direct");
  assert.equal(
    tooMany.data.pushClassification.push_classification_reason,
    "commits_outside_pull_request",
  );
  assert.match(tooMany.data.warnings[0], /carries 4 commits but pull request #42 has 2/);

  // What cannot be verified is unknown, never merged.
  const prCommitsDown = await pushWith({
    compare: compareOf([commit(AFTER, BEFORE)]),
    prCommits: fail(500),
  });
  assert.equal(prCommitsDown.data.pushClassification.push_classification, "unknown");
  assert.equal(
    prCommitsDown.data.pushClassification.push_classification_reason,
    "pull_request_commits_unavailable",
  );
  assert.match(prCommitsDown.data.warnings.join("\n"), /commits of pull request #42/);

  const compareDown = await pushWith({ compare: fail(502) });
  assert.equal(compareDown.data.pushClassification.push_classification, "unknown");
  assert.equal(
    compareDown.data.pushClassification.push_classification_reason,
    "push_compare_unavailable",
  );
  assert.equal(compareDown.data.evidenceTruncated.commits, true);
  assert.equal(compareDown.paths.some((path) => path.includes("/pulls/42/commits")), false);

  const capped = await pushWith({
    compare: compareOf([commit(AFTER, BEFORE, HEAD)], 2),
    prCommits: prCommitsOf(P1, HEAD),
  });
  assert.equal(capped.data.pushClassification.push_classification, "unknown");
  assert.equal(
    capped.data.pushClassification.push_classification_reason,
    "push_commits_truncated",
  );

  // A 200 compare with no commit evidence is unknown, not merged. Every shape
  // that produces an empty commit list gets the same answer: an explicit empty
  // array, a missing `commits` field, and a `commits` field that is not an
  // array. Without commits neither the count rule nor the parent rule can run,
  // so calling this merged_pull_request would let a locally pushed merge
  // carrying extra commits through protect-default-branch on no evidence.
  for (const [label, body] of [
    ["empty array", { total_commits: 0, commits: [], files: [] }],
    ["missing field", { total_commits: 0, files: [] }],
    ["non-array", { total_commits: 0, commits: {}, files: [] }],
  ]) {
    const noCommits = await pushWith({
      compare: ok(body),
      prCommits: prCommitsOf(P1, HEAD),
    });
    assert.equal(
      noCommits.data.pushClassification.push_classification,
      "unknown",
      `compare with ${label} commits must be unknown`,
    );
    assert.equal(
      noCommits.data.pushClassification.push_classification_reason,
      "push_commits_unavailable",
      `compare with ${label} commits must say why`,
    );
    assert.equal(noCommits.data.pushClassification.pull_request_number, 42);
    assert.equal(noCommits.data.repositoryAction, "repo.push");
    assert.equal(noCommits.data.evidenceTruncated.commits, true);
    assert.match(
      noCommits.data.warnings.join("\n"),
      /compare returned no commits/,
      `compare with ${label} commits must warn`,
    );
    // The PR commits are never fetched: there is nothing to compare them to.
    assert.equal(
      noCommits.paths.some((path) => path.includes("/pulls/42/commits")),
      false,
      `compare with ${label} commits must not fetch PR commits`,
    );
  }

  // The same push, one commit of evidence, is the squash-merge case above and
  // still resolves merged_pull_request. This is the control: it is the empty
  // commit list that flips the verdict, not anything else in the fixture.
  const oneCommit = await pushWith({
    compare: compareOf([commit(AFTER, BEFORE)]),
    prCommits: prCommitsOf(P1, HEAD),
  });
  assert.equal(oneCommit.data.pushClassification.push_classification, "merged_pull_request");

  // A non-branch ref is not a branch event. A new tag push carries
  // `created: true` and a zero before SHA exactly like a new branch, and an
  // updated tag carries two real SHAs like a direct push; both are `not_push`
  // because branch protection has no opinion on a tag.
  const newTag = await pushWith({
    compare: compareOf([commit(AFTER, BEFORE)]),
    event: { ref: "refs/tags/v1", before: ZERO, created: true },
  });
  assert.equal(newTag.data.pushClassification.push_classification, "not_push");
  assert.equal(
    newTag.data.pushClassification.push_classification_reason,
    "non_branch_ref",
  );
  assert.equal(newTag.data.pushClassification.push_forced, false);
  assert.equal(newTag.data.repositoryAction, "repo.push");
  // Classified from the ref alone: the PR association is never looked up.
  assert.equal(newTag.paths.some((path) => path.includes("/pulls?")), false);

  const movedTag = await pushWith({
    compare: compareOf([commit(AFTER, BEFORE)]),
    event: { ref: "refs/tags/v1" },
  });
  assert.equal(movedTag.data.pushClassification.push_classification, "not_push");
  assert.equal(
    movedTag.data.pushClassification.push_classification_reason,
    "non_branch_ref",
  );
  assert.equal(movedTag.paths.some((path) => path.includes("/pulls?")), false);

  // A forced tag push is still not_push: the ref check runs before `forced`,
  // because a rewritten tag is not a rewritten branch either.
  const forcedTag = await pushWith({
    compare: compareOf([commit(AFTER, BEFORE)]),
    event: { ref: "refs/tags/v1", forced: true },
  });
  assert.equal(forcedTag.data.pushClassification.push_classification, "not_push");

  // The branch cases the tag cases are being distinguished from still hold.
  const newBranch = await pushWith({
    event: { ref: "refs/heads/feature", before: ZERO, created: true },
  });
  assert.equal(newBranch.data.pushClassification.push_classification, "created");
  assert.equal(
    newBranch.data.pushClassification.push_classification_reason,
    "branch_created",
  );

  // resolvePushClassificationOutput passes not_push through instead of
  // coercing it to unknown, so a tag push does not fail a protected run.
  assert.equal(
    resolvePushClassificationOutput({
      eventName: "push",
      pushClassification: newTag.data.pushClassification,
    }),
    "not_push",
  );
  assert.equal(
    evaluateDefaultBranchProtection({
      enabled: true,
      eventName: "push",
      event: { ref: "refs/tags/v1", after: AFTER, repository: { default_branch: "main" } },
      pushClassification: newTag.data.pushClassification,
      env: {},
    }).blocked,
    false,
  );

  // isNonBranchRef is the one owner of the question; index.js and the
  // classifier both ask it. An absent ref is not a tag.
  assert.equal(isNonBranchRef("refs/tags/v1"), true);
  assert.equal(isNonBranchRef("refs/pull/7/merge"), true);
  assert.equal(isNonBranchRef("refs/heads/main"), false);
  assert.equal(isNonBranchRef("main"), false);
  assert.equal(isNonBranchRef(""), false);
  assert.equal(isNonBranchRef(undefined), false);

  // getPullRequestData reads `forced` off the payload and threads the lookup
  // options through to the classifier.
  const compare = compareOf([commit(AFTER, BEFORE)]);
  const forcedPaths = [];
  const forcedPush = await getPullRequestData(
    { ref: "refs/heads/main", before: BEFORE, after: AFTER, forced: true, commits: [] },
    async (path) => {
      forcedPaths.push(path);
      return compare;
    },
  );
  assert.equal(forcedPush.pushClassification.push_classification, "forced");
  assert.equal(forcedPush.pushClassification.push_forced, true);
  assert.equal(forcedPush.repositoryAction, "repo.push");
  assert.equal(forcedPaths.filter((path) => path.includes("/pulls?")).length, 0);
  assert.equal(forcedPaths.filter((path) => path.includes("/compare/")).length, 1);

  // The lookup and the compare run concurrently: the compare request goes out
  // before the lookup's retries have finished.
  const retriedPaths = [];
  const retriedSleeps = [];
  const retriedPush = await getPullRequestData(
    { ref: "refs/heads/main", before: BEFORE, after: AFTER, forced: false, commits: [] },
    async (path) => {
      retriedPaths.push(path);
      return path.includes("/pulls?") ? ok([]) : compare;
    },
    {
      pushLookup: {
        retryOnNoMatch: true,
        sleep: async (ms) => {
          retriedSleeps.push(ms);
        },
      },
    },
  );
  assert.equal(retriedPush.pushClassification.push_classification, "direct");
  assert.equal(retriedPaths.filter((path) => path.includes("/pulls?")).length, 3);
  assert.equal(retriedSleeps.length, 2);
  assert(retriedPaths[0].includes("/pulls?"));
  assert(retriedPaths[1].includes("/compare/"));
  assert.equal(retriedPush.warnings.filter((warning) => warning.includes("PR association")).length, 0);

  // Lookup warnings are reported once.
  const downPaths = [];
  const downPush = await getPullRequestData(
    { ref: "refs/heads/main", before: BEFORE, after: AFTER, forced: false, commits: [] },
    async (path) => {
      downPaths.push(path);
      return path.includes("/pulls?") ? fail(503) : compare;
    },
    { pushLookup: { sleep: async () => {} } },
  );
  assert.equal(downPush.pushClassification.push_classification, "unknown");
  assert.equal(
    downPush.warnings.filter((warning) => warning.includes("PR association")).length,
    1,
  );

  // The verify context carries the push facts to the verifier.
  const context = buildVerifyContext({
    event: {
      ref: "refs/heads/main",
      before: BEFORE,
      after: AFTER,
      forced: true,
      sender: { login: "octocat" },
      repository: { default_branch: "main" },
    },
    files: [],
    attribution: { class: "human", confidence: "high" },
    repositoryAction: "repo.push",
    pushClassification: {
      push_classification: "forced",
      push_forced: true,
      push_to_default_branch: true,
      default_branch: "main",
    },
  });
  assert.equal(context.action, "repo.push");
  assert.equal(context.evidence.push_classification, "forced");
  assert.equal(context.evidence.push_forced, true);
  assert.equal(context.evidence.push_to_default_branch, true);
  assert.equal(context.evidence.default_branch, "main");

  // Non-boolean values for the boolean fields are dropped, not coerced.
  const looseContext = buildVerifyContext({
    event: { ref: "refs/heads/main", before: BEFORE, after: AFTER },
    files: [],
    attribution: { class: "human", confidence: "high" },
    pushClassification: {
      push_classification: "direct",
      push_forced: "yes",
      push_to_default_branch: 1,
    },
  });
  assert.equal(looseContext.evidence.push_forced, undefined);
  assert.equal(looseContext.evidence.push_to_default_branch, undefined);

  delete process.env.GITHUB_EVENT_NAME;
  delete process.env.GITHUB_SHA;
}

classifierTests()
  .then(reconciliationTests)
  .then(() => {
    console.log("OK push-classification.test.js");
  })
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });

const assert = require("assert");
const {
  PUSH_CLASSIFICATIONS,
  describeBlockReason,
  describeProtectionState,
  evaluateDefaultBranchProtection,
  isDefaultBranchPush,
  pushedBranch,
  resolveDefaultBranch,
  resolvePushClassificationOutput,
} = require("../src/push-protection");

const AFTER = "b".repeat(40);
const env = { GITHUB_REF: "refs/heads/main", GITHUB_SHA: AFTER };
const mainPush = {
  ref: "refs/heads/main",
  after: AFTER,
  repository: { default_branch: "main" },
};

function highFindings(result) {
  return result.findings.filter((finding) => finding.severity === "high");
}

// The push-classification output.
assert.equal(
  resolvePushClassificationOutput({
    eventName: "pull_request",
    pushClassification: { push_classification: "direct" },
  }),
  "not_push",
);
assert.equal(resolvePushClassificationOutput({ eventName: "" }), "not_push");
assert.deepEqual(PUSH_CLASSIFICATIONS, [
  "direct",
  "merged_pull_request",
  "forced",
  "created",
  "unknown",
  "not_push",
]);
for (const value of PUSH_CLASSIFICATIONS) {
  assert.equal(
    resolvePushClassificationOutput({
      eventName: "push",
      pushClassification: { push_classification: value },
    }),
    value,
  );
}
// A push with no classification, or a value the classifier never emits, is
// reported as unknown rather than quietly called direct.
assert.equal(resolvePushClassificationOutput({ eventName: "push" }), "unknown");
assert.equal(
  resolvePushClassificationOutput({
    eventName: "push",
    pushClassification: { push_classification: "bogus" },
  }),
  "unknown",
);

// Default-branch detection.
assert.equal(isDefaultBranchPush({ event: mainPush, eventName: "push", env }), true);
assert.equal(
  isDefaultBranchPush({
    event: { ...mainPush, ref: "refs/heads/feature/x" },
    eventName: "push",
    env,
  }),
  false,
);
assert.equal(
  isDefaultBranchPush({ event: mainPush, eventName: "pull_request", env }),
  false,
);
assert.equal(
  isDefaultBranchPush({
    event: { ...mainPush, repository: {} },
    eventName: "push",
    env,
  }),
  false,
);
// Falls back to GITHUB_REF when the payload has no ref.
assert.equal(
  isDefaultBranchPush({
    event: { after: AFTER, repository: { default_branch: "main" } },
    eventName: "push",
    env,
  }),
  true,
);
// A tag named after the default branch is not the default branch.
assert.equal(
  isDefaultBranchPush({
    event: { ref: "refs/tags/main", repository: { default_branch: "main" } },
    eventName: "push",
    env: {},
  }),
  false,
);
// GITHUB_REF_NAME is the last resort, and only when the ref is a branch.
assert.equal(
  pushedBranch({}, { GITHUB_REF_TYPE: "branch", GITHUB_REF_NAME: "main" }),
  "main",
);
assert.equal(
  pushedBranch({}, { GITHUB_REF_TYPE: "tag", GITHUB_REF_NAME: "main" }),
  "",
);
assert.equal(pushedBranch({ ref: "refs/tags/main" }, { GITHUB_REF_TYPE: "branch", GITHUB_REF_NAME: "main" }), "main");
// An explicit default branch overrides the payload.
assert.equal(
  isDefaultBranchPush({
    event: { ...mainPush, repository: {} },
    eventName: "push",
    env,
    defaultBranch: "main",
  }),
  true,
);
assert.equal(
  isDefaultBranchPush({ event: mainPush, eventName: "push", env, defaultBranch: "trunk" }),
  false,
);
// Default branches with slashes work.
assert.equal(
  isDefaultBranchPush({
    event: {
      ref: "refs/heads/release/stable",
      repository: { default_branch: "release/stable" },
    },
    eventName: "push",
    env: {},
  }),
  true,
);

// Forced push to the default branch, protection on: blocking finding.
const forcedOn = evaluateDefaultBranchProtection({
  enabled: true,
  eventName: "push",
  event: { ...mainPush, forced: true },
  pushClassification: { push_classification: "forced", push_forced: true },
  env,
});
assert.equal(forcedOn.applies, true);
assert.equal(forcedOn.classification, "forced");
assert.equal(forcedOn.blocked, true);
assert.equal(forcedOn.reason, "forced");
assert.equal(forcedOn.findings.length, 1);
assert.equal(forcedOn.findings[0].code, "OAP.REPO.FORCE_PUSH");
assert.equal(forcedOn.findings[0].severity, "high");
assert.equal(forcedOn.findings[0].details.branch, "main");
assert.equal(forcedOn.findings[0].details.sha, AFTER);
assert.equal(forcedOn.findings[0].details.protect_default_branch, true);
assert.deepEqual(forcedOn.warnings, []);
assert.match(describeBlockReason(forcedOn), /protect-default-branch is enabled/);
assert.match(describeBlockReason(forcedOn), /main was forced/);

// Forced push, protection off: still reported, as a warning, never blocking.
const forcedOff = evaluateDefaultBranchProtection({
  enabled: false,
  eventName: "push",
  event: { ...mainPush, forced: true },
  pushClassification: { push_classification: "forced", push_forced: true },
  env,
});
assert.equal(forcedOff.blocked, false);
assert.equal(forcedOff.findings.length, 1);
assert.equal(forcedOff.findings[0].code, "OAP.REPO.FORCE_PUSH");
assert.equal(forcedOff.findings[0].severity, "warning");
assert.equal(forcedOff.findings[0].details.protect_default_branch, false);
assert.equal(describeBlockReason(forcedOff), "");

// Direct push to the default branch, protection on: blocking finding.
const directOn = evaluateDefaultBranchProtection({
  enabled: true,
  eventName: "push",
  event: mainPush,
  pushClassification: { push_classification: "direct", push_forced: false },
  env,
});
assert.equal(directOn.blocked, true);
assert.equal(directOn.reason, "direct");
assert.equal(highFindings(directOn).length, 1);
assert.equal(directOn.findings[0].code, "OAP.REPO.DIRECT_PUSH_DEFAULT_BRANCH");
assert.match(directOn.findings[0].message, /Open a pull request instead/);
assert.equal(directOn.findings[0].details.push_classification, "direct");
assert.match(
  describeBlockReason(directOn),
  /not the merge commit of a merged pull request/,
);

// Direct push, protection off: report-only stays report-only. No finding.
const directOff = evaluateDefaultBranchProtection({
  enabled: false,
  eventName: "push",
  event: mainPush,
  pushClassification: { push_classification: "direct", push_forced: false },
  env,
});
assert.equal(directOff.blocked, false);
assert.deepEqual(directOff.findings, []);
assert.equal(directOff.classification, "direct");

// Merged pull request landing on the default branch: allowed either way.
for (const enabled of [true, false]) {
  const merged = evaluateDefaultBranchProtection({
    enabled,
    eventName: "push",
    event: mainPush,
    pushClassification: {
      push_classification: "merged_pull_request",
      push_forced: false,
      pull_request_number: 42,
      merge_commit_sha: AFTER,
      merge_base_branch: "main",
    },
    env,
  });
  assert.equal(merged.applies, true);
  assert.equal(merged.blocked, false);
  assert.deepEqual(merged.findings, []);
  assert.equal(merged.classification, "merged_pull_request");
}

// Lookup failed (classification unknown), protection on: fail closed.
const unknownOn = evaluateDefaultBranchProtection({
  enabled: true,
  eventName: "push",
  event: mainPush,
  pushClassification: {
    push_classification: "unknown",
    push_classification_reason: "associated_pr_lookup_failed",
    push_forced: false,
  },
  env,
});
assert.equal(unknownOn.blocked, true);
assert.equal(unknownOn.reason, "lookup_failed");
assert.equal(unknownOn.findings[0].code, "OAP.REPO.DIRECT_PUSH_DEFAULT_BRANCH");
assert.equal(unknownOn.findings[0].severity, "high");
assert.equal(
  unknownOn.findings[0].details.push_classification_reason,
  "associated_pr_lookup_failed",
);
assert.match(unknownOn.findings[0].message, /could not be resolved/);
assert.match(describeBlockReason(unknownOn), /treated as a direct push/);

// Lookup failed, protection off: no finding, matching prior behaviour.
const unknownOff = evaluateDefaultBranchProtection({
  enabled: false,
  eventName: "push",
  event: mainPush,
  pushClassification: {
    push_classification: "unknown",
    push_classification_reason: "associated_pr_lookup_failed",
  },
  env,
});
assert.equal(unknownOff.blocked, false);
assert.deepEqual(unknownOff.findings, []);

// Push to a non-default branch, protection on: out of scope.
const featureOn = evaluateDefaultBranchProtection({
  enabled: true,
  eventName: "push",
  event: { ...mainPush, ref: "refs/heads/feature/x", forced: true },
  pushClassification: { push_classification: "forced", push_forced: true },
  env,
});
assert.equal(featureOn.applies, false);
assert.equal(featureOn.blocked, false);
assert.deepEqual(featureOn.findings, []);
assert.equal(featureOn.classification, "forced");
assert.equal(featureOn.branch, "feature/x");
assert.equal(featureOn.defaultBranch, "main");

// Non-push event, protection on: nothing to evaluate.
const pullRequestOn = evaluateDefaultBranchProtection({
  enabled: true,
  eventName: "pull_request",
  event: { pull_request: { number: 7 }, repository: { default_branch: "main" } },
  pushClassification: undefined,
  env: { GITHUB_REF: "refs/pull/7/merge" },
});
assert.equal(pullRequestOn.applies, false);
assert.equal(pullRequestOn.blocked, false);
assert.equal(pullRequestOn.classification, "not_push");
assert.deepEqual(pullRequestOn.findings, []);
assert.deepEqual(pullRequestOn.warnings, []);

// A push that creates the default branch (re-creating a deleted one looks the
// same) is not a direct push: no finding either way.
for (const enabled of [true, false]) {
  const created = evaluateDefaultBranchProtection({
    enabled,
    eventName: "push",
    event: { ...mainPush, before: "0".repeat(40), created: true },
    pushClassification: {
      push_classification: "created",
      push_classification_reason: "branch_created",
      push_forced: false,
    },
    env,
  });
  assert.equal(created.applies, true);
  assert.equal(created.classification, "created");
  assert.equal(created.blocked, false);
  assert.deepEqual(created.findings, []);
  assert.equal(created.reason, "");
}

// A direct verdict that came out of the merge reconciliation keeps its reason.
const reconciledDirect = evaluateDefaultBranchProtection({
  enabled: true,
  eventName: "push",
  event: mainPush,
  pushClassification: {
    push_classification: "direct",
    push_classification_reason: "commits_outside_pull_request",
    pull_request_number: 42,
  },
  env,
});
assert.equal(reconciledDirect.blocked, true);
assert.equal(reconciledDirect.reason, "direct");
assert.equal(
  reconciledDirect.findings[0].details.push_classification_reason,
  "commits_outside_pull_request",
);

// Push payload without a default branch, protection on, and no other source:
// fail closed rather than skip the check.
const noDefault = evaluateDefaultBranchProtection({
  enabled: true,
  eventName: "push",
  event: { ref: "refs/heads/main", after: AFTER },
  pushClassification: { push_classification: "direct", push_forced: false },
  env,
});
assert.equal(noDefault.applies, false);
assert.equal(noDefault.blocked, true);
assert.equal(noDefault.reason, "default_branch_unknown");
assert.equal(noDefault.defaultBranch, "");
assert.equal(noDefault.findings.length, 1);
assert.equal(noDefault.findings[0].code, "OAP.REPO.DIRECT_PUSH_DEFAULT_BRANCH");
assert.equal(noDefault.findings[0].severity, "high");
assert.match(noDefault.findings[0].message, /could not be determined/);
assert.match(noDefault.findings[0].message, /push to main/);
assert.equal(
  noDefault.findings[0].details.push_classification_reason,
  "default_branch_unknown",
);
assert.match(describeBlockReason(noDefault), /default branch could not be determined/);
assert.match(describeBlockReason(noDefault), /push to main was treated as a direct push/);
assert.equal(
  describeProtectionState(noDefault),
  "enabled (default branch unresolved; fail closed)",
);

// Branch creation is settled before unresolved-default fail-closed handling:
// the first push that creates a branch can have no default-branch evidence yet.
const noDefaultCreated = evaluateDefaultBranchProtection({
  enabled: true,
  eventName: "push",
  event: { ref: "refs/heads/main", after: AFTER, before: "0".repeat(40), created: true },
  pushClassification: {
    push_classification: "created",
    push_classification_reason: "branch_created",
    push_forced: false,
  },
  env,
});
assert.equal(noDefaultCreated.applies, false);
assert.equal(noDefaultCreated.blocked, false);
assert.equal(noDefaultCreated.reason, "");
assert.deepEqual(noDefaultCreated.findings, []);
assert.equal(describeProtectionState(noDefaultCreated), "enabled (branch created)");

// The same payload with the default branch supplied from elsewhere is a
// normal evaluation.
const suppliedDefault = evaluateDefaultBranchProtection({
  enabled: true,
  eventName: "push",
  event: { ref: "refs/heads/main", after: AFTER },
  pushClassification: { push_classification: "merged_pull_request" },
  env,
  defaultBranch: "main",
});
assert.equal(suppliedDefault.applies, true);
assert.equal(suppliedDefault.blocked, false);
assert.equal(suppliedDefault.defaultBranch, "main");

// No default branch, protection off: nothing to do, no finding.
const noDefaultOff = evaluateDefaultBranchProtection({
  enabled: false,
  eventName: "push",
  event: { ref: "refs/heads/main", after: AFTER },
  pushClassification: { push_classification: "direct" },
  env,
});
assert.equal(noDefaultOff.blocked, false);
assert.deepEqual(noDefaultOff.findings, []);

// No default branch, protection on, but a tag push: not a branch, nothing to
// protect.
const tagNoDefault = evaluateDefaultBranchProtection({
  enabled: true,
  eventName: "push",
  event: { ref: "refs/tags/v1", after: AFTER },
  pushClassification: { push_classification: "direct" },
  env: {},
});
assert.equal(tagNoDefault.blocked, false);
assert.deepEqual(tagNoDefault.findings, []);

// Resolving the default branch: payload, then input, then the API.
(async () => {
  const fromPayload = await resolveDefaultBranch({
    event: mainPush,
    eventName: "push",
    env,
    input: "trunk",
    lookup: async () => {
      throw new Error("not expected");
    },
  });
  assert.deepEqual(fromPayload, { defaultBranch: "main", source: "payload", warnings: [] });

  const fromInput = await resolveDefaultBranch({
    event: { ref: "refs/heads/main" },
    eventName: "push",
    env,
    input: " trunk ",
    lookup: async () => {
      throw new Error("not expected");
    },
  });
  assert.deepEqual(fromInput, { defaultBranch: "trunk", source: "input", warnings: [] });

  let lookups = 0;
  const fromApi = await resolveDefaultBranch({
    event: { ref: "refs/heads/main" },
    eventName: "push",
    env,
    lookup: async () => {
      lookups += 1;
      return { defaultBranch: "develop", error: "" };
    },
  });
  assert.deepEqual(fromApi, { defaultBranch: "develop", source: "api", warnings: [] });
  assert.equal(lookups, 1);

  const apiDown = await resolveDefaultBranch({
    event: { ref: "refs/heads/main" },
    eventName: "push",
    env,
    lookup: async () => ({ defaultBranch: "", error: "503: unavailable" }),
  });
  assert.equal(apiDown.defaultBranch, "");
  assert.equal(apiDown.source, "");
  assert.equal(apiDown.warnings.length, 1);
  assert.match(apiDown.warnings[0], /503: unavailable/);
  assert.match(apiDown.warnings[0], /default-branch input/);

  // No lookup for events that are not pushes, or for tag pushes.
  for (const args of [
    { event: { pull_request: { number: 1 } }, eventName: "pull_request", env: {} },
    { event: { ref: "refs/tags/v1" }, eventName: "push", env: {} },
  ]) {
    const skipped = await resolveDefaultBranch({
      ...args,
      lookup: async () => {
        throw new Error("not expected");
      },
    });
    assert.deepEqual(skipped, { defaultBranch: "", source: "", warnings: [] });
  }
})().catch((error) => {
  console.error(error);
  process.exit(1);
});

// The protection line shared by the run log and the job summary.
assert.equal(describeProtectionState({ enabled: false, applies: true }), "disabled");
assert.equal(describeProtectionState({ enabled: false, applies: false }), "disabled");
assert.equal(describeProtectionState({ enabled: true, applies: true }), "enabled");
assert.equal(
  describeProtectionState({ enabled: true, classification: "created", applies: false }),
  "enabled (branch created)",
);
assert.equal(
  describeProtectionState({ enabled: true, applies: false }),
  "enabled (not the default branch)",
);
assert.equal(describeProtectionState(null), "disabled");

assert.equal(describeBlockReason(null), "");
assert.equal(describeBlockReason({ blocked: false }), "");

console.log("OK push-protection.test.js");

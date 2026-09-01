const assert = require("assert");
const {
  buildVerifyContext,
  compactStructuralFindingsForVerify,
  makeIdempotencyKey,
  normalizeEventAction,
} = require("../src/context");

process.env.GITHUB_REPOSITORY = "aporthq/agent-passport";
process.env.GITHUB_ACTOR = "github-actions[bot]";
process.env.GITHUB_RUN_ID = "100";
process.env.GITHUB_RUN_ATTEMPT = "2";
process.env.GITHUB_SHA = "merge1234567890abcdef1234567890abcdef123456";

delete process.env.GITHUB_EVENT_NAME;
assert.equal(normalizeEventAction({ action: "opened" }), "pr.create");
process.env.GITHUB_EVENT_NAME = "push";
assert.equal(normalizeEventAction({}), "repo.push");
process.env.GITHUB_EVENT_NAME = "pull_request";

const context = buildVerifyContext({
  event: {
    action: "synchronize",
    pull_request: {
      number: 42,
      head: {
        ref: "feature/aport",
        sha: "1234567890abcdef1234567890abcdef12345678",
      },
      base: {
        ref: "main",
      },
    },
    sender: {
      login: "octocat",
    },
  },
  files: [
    { filename: "src/index.js", additions: 10, deletions: 2 },
    { filename: "README.md", additions: 3, deletions: 0 },
  ],
  attribution: {
    class: "coding_agent",
    confidence: "high",
  },
  repositoryPolicy: {
    source: ".aport/policy.yaml@1234567890ab",
    hash: "sha256:policy",
  },
  structuralFindings: [
    {
      code: "OAP.REPO.PROTECTED_PATH_TOUCHED",
      severity: "warning",
      message: "Protected repository paths changed.",
      paths: [".github/workflows/deploy.yml", "functions/api/verify/index.ts"],
    },
  ],
});

assert.equal(context.repository, "aporthq/agent-passport");
assert.equal(context.action, "pr.update");
assert.equal(context.branch, "feature/aport");
assert.equal(context.base_branch, "main");
assert.equal(context.sha, "merge1234567890abcdef1234567890abcdef123456");
assert.equal(context.head_sha, "1234567890abcdef1234567890abcdef12345678");
assert.equal(context.lines_added, 13);
assert.equal(context.lines_removed, 2);
assert.equal(context.files_changed, undefined);
assert.equal(context.authorization.provider, "github_actions_oidc");
assert.equal(context.authorization.require_oidc, true);
assert.equal(context.evidence.structural_findings[0].code, "OAP.REPO.PROTECTED_PATH_TOUCHED");
assert.equal(context.evidence.structural_findings[0].message, "Protected repository paths changed.");
assert.equal(context.evidence.structural_findings[0].path_count, 2);
assert.equal(context.evidence.structural_findings[0].paths, undefined);
assert.equal(context.evidence.repository_policy.hash, "sha256:policy");
assert.equal(context.evidence.pull_request_head_sha, "1234567890abcdef1234567890abcdef12345678");
assert.equal(context.evidence.evidence_format, "aport.github.pr.v1");
assert.equal(context.evidence.event_name, "pull_request");
assert.equal(context.evidence.event_action, "synchronize");
assert.equal(context.evidence.pull_request_number, 42);
assert.equal(context.evidence.files_analyzed, true);
assert.equal(context.evidence.commits_analyzed, true);
assert.deepEqual(context.evidence.files_changed, ["src/index.js", "README.md"]);
assert.equal(context.evidence.lines_added, 13);
assert.equal(context.evidence.lines_removed, 2);
assert.equal(context.structural_findings, undefined);

process.env.GITHUB_EVENT_NAME = "merge_group";
process.env.GITHUB_SHA = "dddddddddddddddddddddddddddddddddddddddd";
const mergeGroupContext = buildVerifyContext({
  event: {
    action: "checks_requested",
    merge_group: {
      base_sha: "cccccccccccccccccccccccccccccccccccccccc",
      head_sha: "dddddddddddddddddddddddddddddddddddddddd",
      base_ref: "refs/heads/main",
      head_ref: "refs/heads/gh-readonly-queue/main/pr-42",
    },
    sender: {
      login: "github-actions[bot]",
    },
  },
  files: [
    {
      filename: "src/queued.ts",
      additions: 7,
      deletions: 1,
    },
  ],
  attribution: {
    class: "coding_agent",
    confidence: "high",
  },
});

assert.equal(mergeGroupContext.action, "pr.update");
assert.equal(mergeGroupContext.sha, "dddddddddddddddddddddddddddddddddddddddd");
assert.equal(mergeGroupContext.branch, "gh-readonly-queue/main/pr-42");
assert.equal(mergeGroupContext.base_branch, "main");
assert.equal(mergeGroupContext.evidence.event_name, "merge_group");
assert.equal(mergeGroupContext.evidence.event_action, "checks_requested");
assert.equal(mergeGroupContext.evidence.files_analyzed, true);
assert.equal(mergeGroupContext.evidence.commits_analyzed, true);
assert.equal(mergeGroupContext.evidence.merge_group_head_sha, "dddddddddddddddddddddddddddddddddddddddd");
assert.equal(mergeGroupContext.evidence.merge_group_base_sha, "cccccccccccccccccccccccccccccccccccccccc");
delete process.env.GITHUB_EVENT_NAME;
process.env.GITHUB_SHA = "merge1234567890abcdef1234567890abcdef123456";

const literalPathContext = buildVerifyContext({
  event: { action: "synchronize", pull_request: { number: 43, head: {}, base: {} } },
  files: [
    { filename: " src/payload.js", additions: 1, deletions: 0 },
    { filename: "src/trailing.js ", additions: 1, deletions: 0 },
  ],
  attribution: { class: "human", confidence: "medium" },
});

assert.deepEqual(literalPathContext.evidence.files_changed, [
  " src/payload.js",
  "src/trailing.js ",
]);

const renamedContext = buildVerifyContext({
  event: { action: "synchronize", pull_request: { number: 43, head: {}, base: {} } },
  files: [
    {
      filename: "src/safe/config.js",
      previous_filename: ".github/workflows/deploy.yml",
      additions: 1,
      deletions: 1,
    },
  ],
  attribution: { class: "human", confidence: "medium" },
});

assert.deepEqual(renamedContext.evidence.files_changed, [
  "src/safe/config.js",
  ".github/workflows/deploy.yml",
]);

const cappedContext = buildVerifyContext({
  event: { action: "synchronize", pull_request: { number: 44, head: {}, base: {} } },
  files: Array.from({ length: 260 }, (_, index) => ({
    filename: `packages/very-long-workspace-name-${index}/src/deeply/nested/path/component-${index}.ts`,
    additions: 1,
    deletions: 0,
  })),
  attribution: { class: "coding_agent", confidence: "high" },
});

assert.equal(cappedContext.files_changed, undefined);
assert(cappedContext.evidence.files_changed.length < 260);
const cappedFinding = cappedContext.evidence.structural_findings.find(
  (finding) => finding.code === "OAP.REPO.FILE_EVIDENCE_CAPPED",
);
assert(cappedFinding);
assert.equal(cappedFinding.severity, "high");
assert(
  Buffer.byteLength(JSON.stringify({ context: cappedContext }), "utf8") <
    10 * 1024,
);

const compactedFindings = compactStructuralFindingsForVerify([
  {
    code: "OAP.REPO.SUSPICIOUS_OBFUSCATION",
    severity: "high",
    message: "Suspicious obfuscated code was introduced.",
    paths: Array.from({ length: 500 }, (_, index) => `src/${index}.js`),
    actions: ["actions/checkout@v4"],
    patterns: ["eval-base64-decoder", "remote-shell-pipe"],
    details: {
      files_truncated: true,
      warning: "x".repeat(500),
      nested: { ignored: true },
    },
  },
]);

assert.deepEqual(compactedFindings[0], {
  code: "OAP.REPO.SUSPICIOUS_OBFUSCATION",
  severity: "high",
  message: "Suspicious obfuscated code was introduced.",
  path_count: 500,
  action_count: 1,
  patterns: ["eval-base64-decoder", "remote-shell-pipe"],
  details: {
    files_truncated: true,
    warning: "x".repeat(300),
  },
});

assert.equal(
  makeIdempotencyKey({
    repository: "aporthq/agent-passport",
    action: "pr.update",
    prNumber: 42,
    sha: "abc",
    runId: "100",
  }),
  "github-aporthq-agent-passport-42-pr.update-abc",
);

assert.equal(
  makeIdempotencyKey({
    repository: "aporthq/agent-passport",
    action: "pr.update",
    prNumber: 42,
    sha: "abc",
    runId: "100",
    runAttempt: "1",
  }),
  makeIdempotencyKey({
    repository: "aporthq/agent-passport",
    action: "pr.update",
    prNumber: 42,
    sha: "abc",
    runId: "100",
    runAttempt: "2",
  }),
);

console.log("OK context.test.js");

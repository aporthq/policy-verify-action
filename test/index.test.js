const assert = require("assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const {
  basePolicyReadFindings,
  buildAttributionInput,
  fatalPushClassification,
  fatalRequiresHosted,
  fatalRequiresProtectedPush,
  handleFatalError,
  hostedStructuralFindings,
  parseBoolean,
  parseList,
  pushLookupOverrides,
  readManagedCredentials,
  resolvePolicyBranch,
  shouldFailWorkflow,
  shouldUseManagedCredentials,
} = require("../src/index");

assert.deepEqual(parseList(" .github/**, src/** ,"), [".github/**", "src/**"]);
assert.equal(parseBoolean("true"), true);
assert.equal(parseBoolean("1"), true);
assert.equal(parseBoolean("yes"), true);
assert.equal(parseBoolean("false"), false);
assert.equal(parseBoolean(""), false);
assert.deepEqual(
  readManagedCredentials({
    APORT_AGENT_ID: "ap_ambient",
    APORT_API_KEY: "apk_ambient",
  }),
  { agentId: "", apiKey: "" },
);
assert.deepEqual(
  readManagedCredentials({
    APORT_INPUT_AGENT_ID: "ap_input",
    APORT_INPUT_API_KEY: "apk_input",
  }),
  { agentId: "ap_input", apiKey: "apk_input" },
);
assert.equal(fatalRequiresHosted({ APORT_MODE: "hosted" }, {}), true);
assert.equal(fatalRequiresHosted({ APORT_MODE: "auto" }, {}), false);
assert.equal(
  fatalRequiresHosted(
    {
      APORT_MODE: "local-json",
      APORT_INPUT_AGENT_ID: "ap_managed",
      APORT_INPUT_API_KEY: "apk_managed",
    },
    {},
  ),
  false,
);
assert.equal(
  fatalRequiresHosted(
    {
      APORT_MODE: "evidence-only",
      APORT_INPUT_AGENT_ID: "ap_managed",
      APORT_INPUT_API_KEY: "apk_managed",
    },
    {},
  ),
  false,
);
assert.equal(
  fatalRequiresHosted(
    {
      APORT_MODE: "auto",
      APORT_INPUT_AGENT_ID: "ap_managed",
      APORT_INPUT_API_KEY: "apk_managed",
      GITHUB_REPOSITORY: "aporthq/agent-passport",
    },
    {
      pull_request: {
        number: 42,
        user: { login: "octocat" },
        head: { repo: { full_name: "aporthq/agent-passport" } },
      },
      repository: { full_name: "aporthq/agent-passport" },
    },
  ),
  true,
);
assert.equal(
  fatalRequiresHosted(
    {
      APORT_MODE: "auto",
      APORT_INPUT_AGENT_ID: "ap_incomplete",
      GITHUB_REPOSITORY: "aporthq/agent-passport",
    },
    {
      pull_request: {
        number: 42,
        user: { login: "octocat" },
        head: { repo: { full_name: "aporthq/agent-passport" } },
      },
      repository: { full_name: "aporthq/agent-passport" },
    },
  ),
  true,
);
assert.equal(
  fatalRequiresHosted(
    {
      APORT_MODE: "auto",
      APORT_INPUT_AGENT_ID: "ap_managed",
      GITHUB_REPOSITORY: "aporthq/agent-passport",
      GITHUB_ACTOR: "dependabot[bot]",
    },
    {
      pull_request: {
        number: 42,
        user: { login: "dependabot[bot]" },
        head: { repo: { full_name: "aporthq/agent-passport" } },
      },
      repository: { full_name: "aporthq/agent-passport" },
    },
  ),
  false,
);

const originalEnv = {
  GITHUB_BASE_REF: process.env.GITHUB_BASE_REF,
  GITHUB_ACTOR: process.env.GITHUB_ACTOR,
  GITHUB_EVENT_NAME: process.env.GITHUB_EVENT_NAME,
  GITHUB_REF: process.env.GITHUB_REF,
  GITHUB_REF_NAME: process.env.GITHUB_REF_NAME,
  GITHUB_REF_TYPE: process.env.GITHUB_REF_TYPE,
};

process.env.GITHUB_BASE_REF = "main";
process.env.GITHUB_EVENT_NAME = "pull_request";
assert.equal(resolvePolicyBranch({}, { base: { ref: "release" } }), "release");

delete process.env.GITHUB_BASE_REF;
process.env.GITHUB_EVENT_NAME = "push";
delete process.env.GITHUB_REF;
delete process.env.GITHUB_REF_NAME;
delete process.env.GITHUB_REF_TYPE;
assert.equal(
  resolvePolicyBranch({ ref: "refs/heads/hotfix/production" }, {}),
  "hotfix/production",
);

process.env.GITHUB_REF = "refs/tags/v1.2.3";
process.env.GITHUB_REF_TYPE = "tag";
process.env.GITHUB_REF_NAME = "v1.2.3";
assert.equal(resolvePolicyBranch({}, {}), "");

for (const [key, value] of Object.entries(originalEnv)) {
  if (value === undefined) {
    delete process.env[key];
  } else {
    process.env[key] = value;
  }
}

process.env.GITHUB_EVENT_NAME = "pull_request";
assert.equal(
  shouldUseManagedCredentials({
    pr: { head: { repo: { full_name: "external/fork" } } },
    repository: "aporthq/agent-passport",
  }),
  false,
);
assert.equal(
  shouldUseManagedCredentials({
    pr: { head: { repo: { full_name: "aporthq/agent-passport" } } },
    repository: "aporthq/agent-passport",
  }),
  true,
);
process.env.GITHUB_ACTOR = "dependabot[bot]";
assert.equal(
  shouldUseManagedCredentials({
    pr: {
      number: 42,
      user: { login: "dependabot[bot]" },
      head: { repo: { full_name: "aporthq/agent-passport" } },
    },
    repository: "aporthq/agent-passport",
  }),
  false,
);
process.env.GITHUB_ACTOR = originalEnv.GITHUB_ACTOR || "";
process.env.GITHUB_EVENT_NAME = "pull_request_review";
assert.equal(
  shouldUseManagedCredentials({
    event: {
      pull_request: { head: { repo: { full_name: "external/fork" } } },
    },
    repository: "aporthq/agent-passport",
  }),
  false,
);
process.env.GITHUB_EVENT_NAME = "push";
assert.equal(
  shouldUseManagedCredentials({
    repository: "aporthq/agent-passport",
  }),
  true,
);
for (const [key, value] of Object.entries(originalEnv)) {
  if (value === undefined) {
    delete process.env[key];
  } else {
    process.env[key] = value;
  }
}

assert.equal(shouldFailWorkflow("hosted", { success: false }), true);
assert.equal(shouldFailWorkflow("hosted", { success: true }), false);
assert.equal(
  shouldFailWorkflow("hosted", { success: true, decision: { allow: false } }),
  true,
);
assert.equal(
  shouldFailWorkflow("auto", { success: true, decision: { allow: false } }),
  false,
);
assert.equal(
  shouldFailWorkflow("hosted", { success: true, decision: { allow: true } }, [
    { code: "OAP.REPO.BASE_POLICY_UNAVAILABLE", severity: "high" },
  ]),
  true,
);
assert.equal(
  shouldFailWorkflow("auto", { success: true, decision: { allow: true } }, [
    { code: "OAP.REPO.BASE_POLICY_UNAVAILABLE", severity: "high" },
  ]),
  false,
);
assert.equal(shouldFailWorkflow("auto", { success: false }), false);
assert.equal(
  shouldFailWorkflow("auto", { success: false, requiresHosted: true }),
  true,
);
assert.equal(
  shouldFailWorkflow(
    "auto",
    { success: true, requiresHosted: true, decision: { allow: false } },
  ),
  true,
);
assert.equal(shouldFailWorkflow("evidence-only", { success: false }), false);

// Default-branch protection is the only thing that fails a report-only run,
// and it does so in every mode.
assert.equal(
  shouldFailWorkflow("auto", { success: true }, [], { blocked: true }),
  true,
);
assert.equal(
  shouldFailWorkflow("evidence-only", { success: false }, [], { blocked: true }),
  true,
);
assert.equal(
  shouldFailWorkflow(
    "hosted",
    { success: true, decision: { allow: true } },
    [{ code: "OAP.REPO.DIRECT_PUSH_DEFAULT_BRANCH", severity: "high" }],
    { blocked: true },
  ),
  true,
);
assert.equal(
  shouldFailWorkflow("auto", { success: true }, [], { blocked: false }),
  false,
);
// A warning-level force-push finding with protection off never blocks.
assert.equal(
  shouldFailWorkflow(
    "auto",
    { success: true },
    [{ code: "OAP.REPO.FORCE_PUSH", severity: "warning" }],
    { enabled: false, blocked: false },
  ),
  false,
);
assert.equal(
  shouldFailWorkflow(
    "hosted",
    { success: true, decision: { allow: true } },
    [{ code: "OAP.REPO.FORCE_PUSH", severity: "warning" }],
    { enabled: false, blocked: false },
  ),
  false,
);

assert.deepEqual(pushLookupOverrides({}), {});
assert.deepEqual(pushLookupOverrides({ APORT_PUSH_LOOKUP_DELAY_MS: "" }), {});
assert.deepEqual(pushLookupOverrides({ APORT_PUSH_LOOKUP_DELAY_MS: "abc" }), {});
assert.deepEqual(pushLookupOverrides({ APORT_PUSH_LOOKUP_DELAY_MS: "-5" }), {});
assert.deepEqual(
  pushLookupOverrides({ APORT_PUSH_LOOKUP_DELAY_MS: "0" }),
  { delayMs: 0 },
);
assert.deepEqual(
  pushLookupOverrides({ APORT_PUSH_LOOKUP_DELAY_MS: "250" }),
  { delayMs: 250 },
);

assert.deepEqual(
  basePolicyReadFindings({ source: ".aport/policy.yaml" }, [
    "Could not read base file .aport/policy.yaml from GitHub API (500): server error",
  ]),
  [],
);
assert.deepEqual(basePolicyReadFindings(null, []), []);
assert.deepEqual(
  basePolicyReadFindings(null, [
    "Could not read base file .aport/policy.yaml from GitHub API (404): not found",
  ]),
  [],
);
assert.equal(
  basePolicyReadFindings(null, [
    "Could not read base file .aport/policy.yaml from GitHub API (500): server error",
  ])[0].code,
  "OAP.REPO.BASE_POLICY_UNAVAILABLE",
);
assert.equal(
  basePolicyReadFindings(null, [
    "Base file .aport/policy.yml was found but could not be decoded.",
  ])[0].severity,
  "high",
);

// The default-branch push findings never go to the hosted verifier; every
// other finding does.
const pushFinding = { code: "OAP.REPO.DIRECT_PUSH_DEFAULT_BRANCH", severity: "high" };
const forceFinding = { code: "OAP.REPO.FORCE_PUSH", severity: "warning" };
const pathFinding = { code: "OAP.REPO.PROTECTED_PATH", severity: "warning" };
assert.deepEqual(
  hostedStructuralFindings([pathFinding, pushFinding, forceFinding], {
    findings: [pushFinding, forceFinding],
  }),
  [pathFinding],
);
assert.deepEqual(hostedStructuralFindings([pathFinding], null), [pathFinding]);
assert.deepEqual(hostedStructuralFindings([], { findings: [pushFinding] }), []);

// A fatal error on a protected push fails the step; anywhere else the
// existing hosted rule decides.
assert.equal(
  fatalRequiresProtectedPush({ GITHUB_EVENT_NAME: "push", APORT_PROTECT_DEFAULT_BRANCH: "true" }),
  true,
);
assert.equal(
  fatalRequiresProtectedPush({ GITHUB_EVENT_NAME: "push", APORT_PROTECT_DEFAULT_BRANCH: "false" }),
  false,
);
assert.equal(
  fatalRequiresProtectedPush({ GITHUB_EVENT_NAME: "pull_request", APORT_PROTECT_DEFAULT_BRANCH: "true" }),
  false,
);
assert.equal(fatalRequiresProtectedPush({}), false);
// The fatal path has the same scope as the evaluation: only a push to the
// default branch fails, a tag push never does, and an unknown default branch
// fails closed.
const fatalPushEnv = { GITHUB_EVENT_NAME: "push", APORT_PROTECT_DEFAULT_BRANCH: "true" };
const mainDefault = { repository: { default_branch: "main" } };
assert.equal(
  fatalRequiresProtectedPush(fatalPushEnv, { ref: "refs/heads/main", ...mainDefault }),
  true,
);
assert.equal(
  fatalPushClassification(fatalPushEnv, { ref: "refs/heads/main", ...mainDefault }),
  "unknown",
);
assert.equal(
  fatalRequiresProtectedPush(fatalPushEnv, { ref: "refs/heads/feature/x", ...mainDefault }),
  false,
);
assert.equal(
  fatalRequiresProtectedPush(fatalPushEnv, { ref: "refs/tags/v1", ...mainDefault }),
  false,
);
assert.equal(
  fatalPushClassification(fatalPushEnv, { ref: "refs/tags/v1", ...mainDefault }),
  "not_push",
);
assert.equal(
  fatalRequiresProtectedPush(
    fatalPushEnv,
    { ref: "refs/heads/main", before: "0".repeat(40), created: true, ...mainDefault },
  ),
  false,
);
assert.equal(
  fatalPushClassification(
    fatalPushEnv,
    { ref: "refs/heads/main", before: "0".repeat(40), created: true, ...mainDefault },
  ),
  "created",
);
assert.equal(
  fatalRequiresProtectedPush(
    fatalPushEnv,
    { ref: "refs/heads/main", before: "0".repeat(40), created: true, forced: true, ...mainDefault },
  ),
  true,
);
assert.equal(
  fatalRequiresProtectedPush(
    { ...fatalPushEnv, GITHUB_REF: "refs/tags/v1", GITHUB_REF_TYPE: "tag", GITHUB_REF_NAME: "v1" },
    mainDefault,
  ),
  false,
);
assert.equal(
  fatalRequiresProtectedPush(
    { ...fatalPushEnv, GITHUB_REF: "refs/heads/feature/x" },
    mainDefault,
  ),
  false,
);
assert.equal(
  fatalRequiresProtectedPush({ ...fatalPushEnv, GITHUB_REF: "refs/heads/main" }, mainDefault),
  true,
);
// The default-branch input stands in for a payload without the name.
assert.equal(
  fatalRequiresProtectedPush(
    { ...fatalPushEnv, APORT_DEFAULT_BRANCH: "trunk" },
    { ref: "refs/heads/feature/x" },
  ),
  false,
);
assert.equal(
  fatalRequiresProtectedPush(
    { ...fatalPushEnv, APORT_DEFAULT_BRANCH: "trunk" },
    { ref: "refs/heads/trunk" },
  ),
  true,
);
// No default branch anywhere: fail closed for a branch push.
assert.equal(
  fatalRequiresProtectedPush(fatalPushEnv, { ref: "refs/heads/feature/x" }),
  true,
);
// The input off: never.
assert.equal(
  fatalRequiresProtectedPush(
    { GITHUB_EVENT_NAME: "push", APORT_PROTECT_DEFAULT_BRANCH: "false" },
    { ref: "refs/heads/main", ...mainDefault },
  ),
  false,
);

function withFatalEnv(env, run, eventPayload = null) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "aport-fatal-"));
  const outputPath = path.join(dir, "output.txt");
  const summaryPath = path.join(dir, "summary.md");
  fs.writeFileSync(outputPath, "");
  fs.writeFileSync(summaryPath, "");
  if (eventPayload) {
    const eventPath = path.join(dir, "event.json");
    fs.writeFileSync(eventPath, JSON.stringify(eventPayload));
    env = { ...env, GITHUB_EVENT_PATH: eventPath };
  }
  const saved = {};
  // GITHUB_REF and friends are cleared too: a CI runner sets them, and the
  // fatal path reads them to tell a default-branch push from any other.
  const keys = [
    "GITHUB_EVENT_NAME",
    "GITHUB_EVENT_PATH",
    "GITHUB_OUTPUT",
    "GITHUB_STEP_SUMMARY",
    "GITHUB_REF",
    "GITHUB_REF_NAME",
    "GITHUB_REF_TYPE",
    "APORT_MODE",
    "APORT_PROTECT_DEFAULT_BRANCH",
    "APORT_DEFAULT_BRANCH",
  ];
  for (const key of keys) {
    saved[key] = process.env[key];
    delete process.env[key];
  }
  Object.assign(process.env, { GITHUB_OUTPUT: outputPath, GITHUB_STEP_SUMMARY: summaryPath, APORT_MODE: "evidence-only" }, env);
  const exitCode = process.exitCode;
  process.exitCode = undefined;
  const write = process.stdout.write;
  let stdout = "";
  process.stdout.write = (chunk) => {
    stdout += chunk;
    return true;
  };
  try {
    run();
    return {
      exitCode: process.exitCode,
      stdout,
      output: fs.readFileSync(outputPath, "utf8"),
      summary: fs.readFileSync(summaryPath, "utf8"),
    };
  } finally {
    process.stdout.write = write;
    process.exitCode = exitCode;
    for (const key of keys) {
      if (saved[key] === undefined) delete process.env[key];
      else process.env[key] = saved[key];
    }
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

const fatalProtected = withFatalEnv(
  { GITHUB_EVENT_NAME: "push", APORT_PROTECT_DEFAULT_BRANCH: "true" },
  () => handleFatalError(new Error("boom")),
);
assert.equal(fatalProtected.exitCode, 1);
assert.match(fatalProtected.output, /^push-classification=unknown$/m);
assert.match(fatalProtected.summary, /Default branch protection could not complete/);
assert.match(fatalProtected.summary, /Error: boom/);
assert.match(fatalProtected.stdout, /::error title=APort Repository Guard could not complete::boom/);

// A push to another branch with the input on: report-only, even on a fatal
// error, because the protection never applied to it.
const fatalCreatedBranch = withFatalEnv(
  {
    GITHUB_EVENT_NAME: "push",
    APORT_PROTECT_DEFAULT_BRANCH: "true",
  },
  () => handleFatalError(new Error("boom")),
  {
    ref: "refs/heads/main",
    before: "0".repeat(40),
    created: true,
    repository: { default_branch: "main" },
  },
);
assert.equal(fatalCreatedBranch.exitCode, undefined);
assert.match(fatalCreatedBranch.output, /^push-classification=created$/m);
assert.match(fatalCreatedBranch.summary, /Report-only mode could not complete/);
assert.ok(!fatalCreatedBranch.stdout.includes("::error title=APort Repository Guard could not complete::"));

const fatalOtherBranch = withFatalEnv(
  {
    GITHUB_EVENT_NAME: "push",
    APORT_PROTECT_DEFAULT_BRANCH: "true",
    GITHUB_REF: "refs/heads/feature/x",
    APORT_DEFAULT_BRANCH: "main",
  },
  () => handleFatalError(new Error("boom")),
);
assert.equal(fatalOtherBranch.exitCode, undefined);
assert.match(fatalOtherBranch.output, /^push-classification=unknown$/m);
assert.match(fatalOtherBranch.summary, /Report-only mode could not complete/);
assert.ok(!fatalOtherBranch.stdout.includes("::error title=APort Repository Guard could not complete::"));

const fatalReportOnly = withFatalEnv(
  { GITHUB_EVENT_NAME: "push", APORT_PROTECT_DEFAULT_BRANCH: "false" },
  () => handleFatalError(new Error("boom")),
);
assert.equal(fatalReportOnly.exitCode, undefined);
assert.match(fatalReportOnly.output, /^push-classification=unknown$/m);
assert.match(fatalReportOnly.summary, /Report-only mode could not complete/);

const fatalPullRequest = withFatalEnv(
  { GITHUB_EVENT_NAME: "pull_request", APORT_PROTECT_DEFAULT_BRANCH: "true" },
  () => handleFatalError(new Error("boom")),
);
assert.equal(fatalPullRequest.exitCode, undefined);
assert.match(fatalPullRequest.output, /^push-classification=not_push$/m);

const fatalHosted = withFatalEnv(
  { GITHUB_EVENT_NAME: "pull_request", APORT_MODE: "hosted" },
  () => handleFatalError(new Error("boom")),
);
assert.equal(fatalHosted.exitCode, 1);
assert.match(fatalHosted.summary, /Hosted verification could not complete/);

const reviewAttribution = buildAttributionInput({
  event: {
    sender: {
      login: "human-reviewer",
      type: "User",
    },
  },
  pr: {
    user: {
      login: "dependabot[bot]",
      type: "Bot",
    },
    head: {
      ref: "dependabot/npm/package",
    },
  },
  commits: [],
});

assert.equal(reviewAttribution.actor, "dependabot[bot]");
assert.equal(reviewAttribution.actorType, "Bot");

console.log("OK index.test.js");

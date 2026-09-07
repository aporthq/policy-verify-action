const assert = require("assert");
const {
  basePolicyReadFindings,
  buildAttributionInput,
  fatalRequiresHosted,
  parseBoolean,
  parseList,
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

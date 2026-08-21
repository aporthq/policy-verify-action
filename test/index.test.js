const assert = require("assert");
const {
  basePolicyReadFindings,
  buildAttributionInput,
  parseList,
  resolvePolicyBranch,
  shouldFailWorkflow,
} = require("../src/index");

assert.deepEqual(parseList(" .github/**, src/** ,"), [".github/**", "src/**"]);

const originalEnv = {
  GITHUB_BASE_REF: process.env.GITHUB_BASE_REF,
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

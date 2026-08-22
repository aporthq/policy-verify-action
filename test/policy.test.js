const assert = require("assert");
const {
  buildPolicyEvidence,
  parseRepositoryPolicy,
  repositoryPolicyFindings,
  resolveProtectedPaths,
} = require("../src/policy");
const { DEFAULT_PROTECTED_PATHS } = require("../src/structural");

const policy = parseRepositoryPolicy(`
version: oap-github-policy/1

repository:
  allowed_base_branches:
    - main
    - "release/*"
  protected_paths:
    - .github/workflows/**
    - 'functions/api/verify/**'
    - policies/**

github:
  require_pinned_actions: true
`);

assert.deepEqual(policy.repository.protected_paths, [
  ".github/workflows/**",
  "functions/api/verify/**",
  "policies/**",
]);
assert.deepEqual(policy.repository.allowed_base_branches, ["main", "release/*"]);
assert.equal(policy.github.require_pinned_actions, true);

const inlinePolicy = parseRepositoryPolicy(`
"repository": { "allowed_base_branches": ["main", "release/*"], protected_paths: [".github/workflows/**", "policies/**"] }
"github": { "require_pinned_actions": true }
`);

assert.deepEqual(inlinePolicy.repository.allowed_base_branches, [
  "main",
  "release/*",
]);
assert.deepEqual(inlinePolicy.repository.protected_paths, [
  ".github/workflows/**",
  "policies/**",
]);
assert.equal(inlinePolicy.github.require_pinned_actions, true);

assert.deepEqual(
  resolveProtectedPaths({
    inputPaths: ["explicit/**"],
    policy,
  }),
  [...DEFAULT_PROTECTED_PATHS, "explicit/**"],
);
assert.deepEqual(resolveProtectedPaths({ inputPaths: [], policy }), [
  ...DEFAULT_PROTECTED_PATHS,
]);
assert.deepEqual(
  resolveProtectedPaths({
    inputPaths: ["infra/**"],
    policy: {
      repository: {
        protected_paths: [".github/workflows/**", "secrets/**"],
      },
    },
  }),
  [...DEFAULT_PROTECTED_PATHS, "secrets/**", "infra/**"],
);

const evidence = buildPolicyEvidence({
  path: ".aport/policy.yaml",
  ref: "abcdef1234567890",
  source: ".aport/policy.yaml@abcdef123456",
  text: `
repository:
  protected_paths: [package.json, pnpm-lock.yaml]
github:
  require_pinned_actions: false
`,
});

assert.equal(evidence.source, ".aport/policy.yaml@abcdef123456");
assert.equal(evidence.path, ".aport/policy.yaml");
assert.equal(evidence.hash.startsWith("sha256:"), true);
assert.deepEqual(evidence.protected_paths, ["package.json", "pnpm-lock.yaml"]);
assert.equal(evidence.require_pinned_actions, false);

assert.deepEqual(
  repositoryPolicyFindings({ policy, baseBranch: "release/2026-08" }),
  [],
);
assert.deepEqual(
  repositoryPolicyFindings({
    policy: { repository: { allowed_base_branches: [" * "] } },
    baseBranch: "feature/aport-policy",
  }),
  [],
);
assert.equal(
  repositoryPolicyFindings({ policy, baseBranch: "develop" })[0].code,
  "OAP.REPO.BASE_BRANCH_FORBIDDEN",
);

console.log("OK policy.test.js");

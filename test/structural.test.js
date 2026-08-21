const assert = require("assert");
const { detectStructuralFindings, findUnpinnedActions } = require("../src/structural");

const findings = detectStructuralFindings({
  files: [
    {
      filename: ".github/workflows/ci.yml",
      patch: [
        "@@",
        "+on:",
        "+  pull_request_target:",
        "+permissions: write-all",
        "+id-token: write",
      ].join("\n"),
    },
    {
      filename: "src/app.js",
      patch: "+console.log('safe')",
    },
  ],
});

assert(findings.find((finding) => finding.code === "OAP.REPO.PROTECTED_PATH_TOUCHED"));
assert(findings.find((finding) => finding.code === "OAP.REPO.PULL_REQUEST_TARGET_INTRODUCED"));
assert(findings.find((finding) => finding.code === "OAP.REPO.WORKFLOW_PERMISSION_ESCALATION"));

const noFindings = detectStructuralFindings({
  files: [{ filename: "src/app.js", patch: "+console.log('safe')" }],
});

assert.equal(noFindings.length, 0);

const inlineFindings = detectStructuralFindings({
  files: [
    {
      filename: ".github/workflows/inline.yml",
      patch: [
        "@@",
        "+on: [pull_request, pull_request_target]",
        "+permissions: { contents: write, id-token: write, pull-requests: write }",
      ].join("\n"),
    },
  ],
});

assert(inlineFindings.find((finding) => finding.code === "OAP.REPO.PULL_REQUEST_TARGET_INTRODUCED"));
assert(inlineFindings.find((finding) => finding.code === "OAP.REPO.WORKFLOW_PERMISSION_ESCALATION"));

const inlineNonWriteFindings = detectStructuralFindings({
  files: [
    {
      filename: ".github/workflows/inline-read.yml",
      patch: "+permissions: { contents: read, id-token: write-token }",
    },
  ],
});
assert(
  !inlineNonWriteFindings.find(
    (finding) => finding.code === "OAP.REPO.WORKFLOW_PERMISSION_ESCALATION",
  ),
);

const inlineObjectFindings = detectStructuralFindings({
  files: [
    {
      filename: ".github/workflows/inline-object.yml",
      patch: "+on: { pull_request_target: {} }",
    },
  ],
});

assert(inlineObjectFindings.find((finding) => finding.code === "OAP.REPO.PULL_REQUEST_TARGET_INTRODUCED"));

const scalarTriggerFindings = detectStructuralFindings({
  files: [
    {
      filename: ".github/workflows/scalar.yml",
      patch: "+on: pull_request_target # elevated trigger",
    },
  ],
});
assert(scalarTriggerFindings.find((finding) => finding.code === "OAP.REPO.PULL_REQUEST_TARGET_INTRODUCED"));

const quotedTriggerFindings = detectStructuralFindings({
  files: [
    {
      filename: ".github/workflows/quoted.yml",
      patch: [
        '+"on": "pull_request_target"',
        "+'pull_request_target':",
      ].join("\n"),
    },
  ],
});
assert(quotedTriggerFindings.find((finding) => finding.code === "OAP.REPO.PULL_REQUEST_TARGET_INTRODUCED"));

const nonCorePermissionFindings = detectStructuralFindings({
  files: [
    {
      filename: ".github/workflows/packages.yml",
      patch: [
        "@@",
        "+permissions:",
        "+  packages: write",
        "+  deployments: write",
      ].join("\n"),
    },
  ],
});
assert(
  nonCorePermissionFindings.find(
    (finding) => finding.code === "OAP.REPO.WORKFLOW_PERMISSION_ESCALATION",
  ),
);

const actionInputWriteFindings = detectStructuralFindings({
  files: [
    {
      filename: ".github/workflows/input-mode.yml",
      patch: [
        "@@",
        "+jobs:",
        "+  build:",
        "+    steps:",
        "+      - uses: example/action@v1",
        "+        with:",
        "+          mode: write",
      ].join("\n"),
    },
  ],
});
assert(
  !actionInputWriteFindings.find(
    (finding) => finding.code === "OAP.REPO.WORKFLOW_PERMISSION_ESCALATION",
  ),
);

const actionInputPermissionNameFindings = detectStructuralFindings({
  files: [
    {
      filename: ".github/workflows/input-contents.yml",
      patch: [
        "@@",
        "+jobs:",
        "+  build:",
        "+    steps:",
        "+      - uses: example/action@v1",
        "+        with:",
        "+          contents: write",
      ].join("\n"),
    },
  ],
});
assert(
  !actionInputPermissionNameFindings.find(
    (finding) => finding.code === "OAP.REPO.WORKFLOW_PERMISSION_ESCALATION",
  ),
);

const envPermissionNameFindings = detectStructuralFindings({
  files: [
    {
      filename: ".github/workflows/env-contents.yml",
      patch: [
        "@@",
        "+env:",
        "+  contents: write",
      ].join("\n"),
    },
  ],
});
assert(
  !envPermissionNameFindings.find(
    (finding) => finding.code === "OAP.REPO.WORKFLOW_PERMISSION_ESCALATION",
  ),
);

const contextPermissionBlockFindings = detectStructuralFindings({
  files: [
    {
      filename: ".github/workflows/existing-permissions.yml",
      patch: [
        "@@",
        " permissions:",
        "-  contents: read",
        "+  contents: write",
      ].join("\n"),
    },
  ],
});
assert(
  contextPermissionBlockFindings.find(
    (finding) => finding.code === "OAP.REPO.WORKFLOW_PERMISSION_ESCALATION",
  ),
);

const missingHeaderPermissionFindings = detectStructuralFindings({
  files: [
    {
      filename: ".github/workflows/existing-large-permissions.yml",
      patch: [
        "@@",
        "   statuses: read",
        "+  id-token: write",
      ].join("\n"),
    },
  ],
});
assert(
  missingHeaderPermissionFindings.find(
    (finding) => finding.code === "OAP.REPO.WORKFLOW_PERMISSION_ESCALATION",
  ),
);

const quotedPermissionFindings = detectStructuralFindings({
  files: [
    {
      filename: ".github/workflows/quoted-permissions.yml",
      patch: [
        "@@",
        "+\"permissions\": \"write-all\"",
        "+permissions:",
        "+  \"contents\": \"write\"",
        "+'permissions': { 'pull-requests': 'write' }",
      ].join("\n"),
    },
  ],
});
assert(
  quotedPermissionFindings.find(
    (finding) => finding.code === "OAP.REPO.WORKFLOW_PERMISSION_ESCALATION",
  ),
);

const renamedProtectedFindings = detectStructuralFindings({
  files: [
    {
      filename: "src/moved-ci.yml",
      previous_filename: ".github/workflows/ci.yml",
      patch: "+name: moved",
    },
  ],
});
const renamedProtectedFinding = renamedProtectedFindings.find(
  (finding) => finding.code === "OAP.REPO.PROTECTED_PATH_TOUCHED",
);
assert(renamedProtectedFinding);
assert(renamedProtectedFinding.paths.includes(".github/workflows/ci.yml"));

const missingPatchFindings = detectStructuralFindings({
  files: [{ filename: ".github/workflows/large.yml" }],
});
assert(missingPatchFindings.find((finding) => finding.code === "OAP.REPO.WORKFLOW_DIFF_UNAVAILABLE"));

const contentFallbackFindings = detectStructuralFindings({
  files: [{ filename: ".github/workflows/full.yml" }],
  fileContents: {
    ".github/workflows/full.yml": [
      "on:",
      "  pull_request_target:",
      "permissions: write-all",
    ].join("\n"),
  },
});
assert(contentFallbackFindings.find((finding) => finding.code === "OAP.REPO.PULL_REQUEST_TARGET_INTRODUCED"));
assert(contentFallbackFindings.find((finding) => finding.code === "OAP.REPO.WORKFLOW_PERMISSION_ESCALATION"));

const policyFindings = detectStructuralFindings({
  files: [{ filename: ".aport/policy.yaml", patch: "+version: oap-github-policy/1" }],
});
assert(policyFindings.find((finding) => finding.code === "OAP.GH.POLICY_HEAD_UNTRUSTED"));

const pinnedFindings = detectStructuralFindings({
  requirePinnedActions: true,
  files: [
    {
      filename: ".github/workflows/pin.yml",
      patch: [
        "@@",
        "+steps:",
        "+  - uses: actions/checkout@v4",
        "+  - uses: aporthq/policy-verify-action@0123456789abcdef0123456789abcdef01234567",
      ].join("\n"),
    },
  ],
});
const unpinnedFinding = pinnedFindings.find((finding) => finding.code === "OAP.REPO.UNPINNED_ACTION");
assert(unpinnedFinding);
assert.deepEqual(unpinnedFinding.actions, ["actions/checkout@v4"]);

const commentedUsesFindings = detectStructuralFindings({
  requirePinnedActions: true,
  files: [
    {
      filename: ".github/workflows/commented-uses.yml",
      patch: "+  - uses: actions/setup-node@v4 # install node",
    },
  ],
});
const commentedUsesFinding = commentedUsesFindings.find(
  (finding) => finding.code === "OAP.REPO.UNPINNED_ACTION",
);
assert(commentedUsesFinding);
assert.deepEqual(commentedUsesFinding.actions, ["actions/setup-node@v4"]);

const truncatedFindings = detectStructuralFindings({
  evidenceTruncated: { files: true, commits: false, maxPages: 20 },
});
const truncatedFinding = truncatedFindings.find(
  (finding) => finding.code === "OAP.REPO.EVIDENCE_TRUNCATED",
);
assert(truncatedFinding);
assert.equal(truncatedFinding.severity, "high");

assert.deepEqual(findUnpinnedActions("+uses: ./local/action\n+uses: docker://alpine:3"), []);

console.log("OK structural.test.js");

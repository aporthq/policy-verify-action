const assert = require("assert");
const {
  buildWorkflowBadgeMarkdown,
  renderSummary,
  workflowFileFromRef,
} = require("../src/summary");

const summary = renderSummary({
  repository: "aporthq/agent-passport",
  prNumber: 310,
  actor: "octocat",
  attribution: {
    class: "human",
    confidence: "high",
    signals: [
      {
        name: "branch|name",
        hit: true,
        detail: "detail|with|pipes",
      },
    ],
  },
  structuralFindings: [
    {
      code: "OAP.REPO.PROTECTED_PATH_TOUCHED",
      severity: "warning",
      message: "Protected `path` changed\nwith newline",
      paths: ["src/`break`\n## injected.md"],
    },
  ],
  repositoryPolicy: { source: ".aport/policy.yaml@base" },
  verification: {
    mode: "auto",
    provenance: "unattributed",
    decision: { allow: true, outcome: "allow", decision_id: "dec_1" },
  },
  eventName: "pull_request",
  workflowRef:
    "aporthq/agent-passport/.github/workflows/aport-guard.yml@refs/heads/main",
  warnings: ["warning with\n## injected heading"],
});

assert(summary.includes("# APort Repository Guard"));
assert(summary.includes("Porter, the APort Repository Guard mascot"));
assert(summary.includes("| Event | pull_request |"));
assert(summary.includes("https://aport.io/quickstart/#github"));
assert(summary.includes("detail\\|with\\|pipes"));
assert(summary.includes("``src/`break` ## injected.md``"));
assert(!summary.includes("\n## injected.md"));
assert(!summary.includes("\n## injected heading"));

const hostedSummary = renderSummary({
  repository: "aporthq/agent-passport",
  prNumber: 310,
  actor: "octocat",
  configuredMode: "hosted",
  attribution: {
    class: "human",
    confidence: "high",
    signals: [],
  },
  structuralFindings: [
    {
      code: "OAP.REPO.BASE_POLICY_UNAVAILABLE",
      severity: "high",
      message: "Trusted base repository policy could not be read.",
    },
  ],
  verification: {
    mode: "hosted",
    provenance: "ci_time",
    decision: { allow: false, outcome: "deny", decision_id: "dec_2" },
  },
  eventName: "pull_request",
  workflowRef:
    "aporthq/agent-passport/.github/workflows/aport-guard.yml@refs/heads/main",
  warnings: [],
  willFail: true,
});

assert(hostedSummary.includes("Hosted enforcement is enabled."));
assert(!hostedSummary.includes("always exits 0"));
assert(hostedSummary.includes("**Blocked.**"));

const autoHostedSummary = renderSummary({
  repository: "aporthq/agent-passport",
  prNumber: 310,
  actor: "octocat",
  configuredMode: "auto",
  attribution: {
    class: "human",
    confidence: "high",
    signals: [],
  },
  structuralFindings: [
    {
      code: "OAP.REPO.BASE_POLICY_UNAVAILABLE",
      severity: "high",
      message: "Trusted base repository policy could not be read.",
    },
  ],
  verification: {
    mode: "hosted",
    provenance: "ci_time",
    decision: { allow: false, outcome: "deny", decision_id: "dec_3" },
  },
  warnings: [],
});

assert(autoHostedSummary.includes("Report-only agent attribution"));
assert(autoHostedSummary.includes("always exits 0"));
assert(!autoHostedSummary.includes("Hosted enforcement is enabled."));
assert(autoHostedSummary.includes("**Needs review.**"));

const reportOnlyDenySummary = renderSummary({
  repository: "aporthq/agent-passport",
  prNumber: 310,
  actor: "octocat",
  configuredMode: "auto",
  attribution: {
    class: "human",
    confidence: "high",
    signals: [],
  },
  structuralFindings: [],
  repositoryPolicy: { source: "built-in default" },
  verification: {
    mode: "local-json",
    provenance: "local_json",
    decision: { allow: false, outcome: "deny", decision_id: "dec_4" },
  },
  warnings: [],
  willFail: false,
});

assert(reportOnlyDenySummary.includes("**Needs review.**"));
assert(reportOnlyDenySummary.includes("APort returned a deny decision in non-blocking mode."));
assert(!reportOnlyDenySummary.includes("**Report ready.**"));

assert.strictEqual(
  workflowFileFromRef(
    "aporthq/agent-passport/.github/workflows/aport-guard.yml@refs/heads/main",
  ),
  "aport-guard.yml",
);
assert.strictEqual(
  workflowFileFromRef(
    "aporthq/agent-passport/.github/workflows/repository guard.yml@refs/heads/main",
  ),
  "repository guard.yml",
);
assert.strictEqual(
  workflowFileFromRef(
    "aporthq/agent-passport/.github/workflows/a\n::stop-commands::x.yml@refs/heads/main",
  ),
  "",
);
assert.strictEqual(
  buildWorkflowBadgeMarkdown({
    repository: "aporthq/agent-passport",
    workflowRef:
      "aporthq/agent-passport/.github/workflows/aport-guard.yml@refs/heads/main",
  }),
  "[![APort Repository Guard](https://github.com/aporthq/agent-passport/actions/workflows/aport-guard.yml/badge.svg)](https://github.com/aporthq/agent-passport/actions/workflows/aport-guard.yml)",
);
assert.strictEqual(
  buildWorkflowBadgeMarkdown({
    repository: "aporthq/agent-passport",
    workflowRef:
      "aporthq/agent-passport/.github/workflows/repository guard.yml@refs/heads/main",
  }),
  "[![APort Repository Guard](https://github.com/aporthq/agent-passport/actions/workflows/repository%20guard.yml/badge.svg)](https://github.com/aporthq/agent-passport/actions/workflows/repository%20guard.yml)",
);
assert.strictEqual(
  buildWorkflowBadgeMarkdown({
    repository: "aporthq/agent-passport\n::warning::x",
    workflowRef:
      "aporthq/agent-passport/.github/workflows/aport-guard.yml@refs/heads/main",
  }),
  "",
);

console.log("OK summary.test.js");

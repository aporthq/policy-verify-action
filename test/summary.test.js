const assert = require("assert");
const { renderSummary } = require("../src/summary");

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
  warnings: ["warning with\n## injected heading"],
});

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
  warnings: [],
});

assert(hostedSummary.includes("Hosted enforcement is enabled."));
assert(!hostedSummary.includes("always exits 0"));

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

console.log("OK summary.test.js");

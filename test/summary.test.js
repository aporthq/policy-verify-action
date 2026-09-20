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
    requiresHosted: true,
    provenance: "ci_time",
    decision: { allow: false, outcome: "deny", decision_id: "dec_3" },
  },
  warnings: [],
  willFail: true,
});

assert(autoHostedSummary.includes("Hosted enforcement"));
assert(autoHostedSummary.includes("Hosted enforcement is enabled."));
assert(!autoHostedSummary.includes("always exits 0"));
assert(autoHostedSummary.includes("**Blocked.**"));

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

// The claim call to action.
//
// A hosted run issues a passport for this repository from its OIDC token and
// that passport starts unclaimed, so the link belongs where the maintainers
// already are: in the comment the run just posted.
const claimCtaSummary = renderSummary({
  repository: "acme/widgets",
  prNumber: 7,
  actor: "someone",
  attribution: {},
  structuralFindings: [],
  repositoryPolicy: {},
  configuredMode: "hosted",
  verification: {
    mode: "hosted",
    provenance: "ci_time",
    oidcRepositoryPassport: true,
    decision: { decision_id: "dec_1", agent_id: "ap_abc123", allow: true },
  },
  eventName: "pull_request",
  workflowRef: "",
  warnings: [],
  willFail: false,
});

assert.match(claimCtaSummary, /## This Repository's Passport/);
// Neutral about claim state: hosted issuance reuses the same passport, and
// this summary has no claim-state signal, so it must not keep telling a
// claimed repository that its passport is unclaimed.
assert.ok(!/is unclaimed/.test(claimCtaSummary));
assert.match(claimCtaSummary, /https:\/\/aport\.io\/claim\?agent_id=ap_abc123/);
// The requirement is stated up front rather than discovered after signing in.
assert.match(claimCtaSummary, /admin/);
assert.match(claimCtaSummary, /maintain/);

// Evidence-only mode issues no passport, so a claim link would point at nothing
// and teach people the link is noise.
const evidenceOnlySummary = renderSummary({
  repository: "acme/widgets",
  prNumber: 7,
  actor: "someone",
  attribution: {},
  structuralFindings: [],
  repositoryPolicy: {},
  configuredMode: "auto",
  verification: { mode: "evidence-only" },
  eventName: "pull_request",
  workflowRef: "",
  warnings: [],
  willFail: false,
});

assert.ok(!evidenceOnlySummary.includes("This Repository's Passport"));

console.log("OK summary.test.js");

// A hosted run with a MANAGED agent id skips OIDC issuance, so its passport is
// not a repository guard and a repository claim link can only end in
// not_a_repository_passport.
const managedSummary = renderSummary({
  repository: "acme/widgets",
  prNumber: 7,
  actor: "someone",
  attribution: {},
  structuralFindings: [],
  repositoryPolicy: {},
  configuredMode: "hosted",
  verification: {
    mode: "hosted",
    provenance: "ci_time",
    oidcRepositoryPassport: false,
    decision: { decision_id: "dec_2", agent_id: "ap_managed", allow: true },
  },
  eventName: "pull_request",
  workflowRef: "",
  warnings: [],
  willFail: false,
});

assert.ok(!managedSummary.includes("This Repository's Passport"));

console.log("OK summary.test.js (claim gating)");

// Everything a claim-link case holds constant. Four of them differ only in the
// api-url and the agent id, and spelling the other ten fields out four times
// made the one line under test the hardest thing to find.
const claimCtaBase = {
  repository: "acme/widgets",
  prNumber: 7,
  actor: "someone",
  attribution: {},
  structuralFindings: [],
  repositoryPolicy: {},
  configuredMode: "hosted",
  eventName: "pull_request",
  workflowRef: "",
  warnings: [],
  willFail: false,
};

// The claim link must point at the deployment that issued the passport.
// Hard-coding aport.io sent maintainers of a staging or self-hosted deployment
// to production, where the agent id does not exist and the claim is not_found.
const stagingSummary = renderSummary({
  ...claimCtaBase,
  verification: {
    mode: "hosted",
    provenance: "ci_time",
    oidcRepositoryPassport: true,
    decision: { decision_id: "dec_3", agent_id: "ap_staging", allow: true },
  },
  apiUrl: "https://staging.aport.io",
});

assert.match(stagingSummary, /https:\/\/staging\.aport\.io\/claim\?agent_id=ap_staging/);
assert.ok(!stagingSummary.includes("https://aport.io/claim"));

// The default split-host API form still resolves to the app origin.
const defaultHostSummary = renderSummary({
  ...claimCtaBase,
  verification: {
    mode: "hosted",
    provenance: "ci_time",
    oidcRepositoryPassport: true,
    decision: { decision_id: "dec_4", agent_id: "ap_default", allow: true },
  },
  apiUrl: "https://api.aport.io",
});

assert.match(defaultHostSummary, /https:\/\/aport\.io\/claim\?agent_id=ap_default/);

// A self-hosted deployment is not always on port 443.
//
// The first version of this derivation used `url.hostname`, which drops the
// port: http://gh.internal:8787 became http://gh.internal, and the maintainer
// followed a link to whatever answers on port 80 of that host. `url.host`
// keeps the authority intact.
const selfHostedSummary = renderSummary({
  ...claimCtaBase,
  verification: {
    mode: "hosted",
    provenance: "ci_time",
    oidcRepositoryPassport: true,
    decision: { decision_id: "dec_5", agent_id: "ap_selfhosted", allow: true },
  },
  apiUrl: "http://gh.internal:8787",
});

assert.match(
  selfHostedSummary,
  /http:\/\/gh\.internal:8787\/claim\?agent_id=ap_selfhosted/,
);
assert.ok(!selfHostedSummary.includes("http://gh.internal/claim"));

// And a deployment served under a path prefix keeps the prefix. `api-url`
// names the API, so the trailing /api is the API's own and comes off; what is
// left in front of it is where the application lives.
const prefixedSummary = renderSummary({
  ...claimCtaBase,
  verification: {
    mode: "hosted",
    provenance: "ci_time",
    oidcRepositoryPassport: true,
    decision: { decision_id: "dec_6", agent_id: "ap_prefixed", allow: true },
  },
  apiUrl: "https://gh.internal:9443/aport/api",
});

assert.match(
  prefixedSummary,
  /https:\/\/gh\.internal:9443\/aport\/claim\?agent_id=ap_prefixed/,
);

console.log("OK summary.test.js (claim url follows deployment)");

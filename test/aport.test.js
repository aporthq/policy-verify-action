const assert = require("assert");
const { generateKeyPairSync, sign } = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");
const {
  SIGNATURE_INVALID,
  defaultVerifyDecisionSignature,
  evidenceAudienceForContext,
  normalizeMode,
  runAportVerification,
  runHostedVerify,
  runLocalJsonVerify,
} = require("../src/aport");

async function main() {
  assert.throws(
    () => normalizeMode("hostd"),
    /Invalid APort verification mode "hostd"/,
  );

  const calls = [];
  const requestJson = async (url, options) => {
    calls.push({ url, options });
    if (url.endsWith("/api/github/oidc/issue")) {
      return {
        success: true,
        data: {
          agent_id: "ap_hosted_github",
          reused: false,
        },
      };
    }
    if (url.endsWith("/api/verify/policy/code.repository.merge.v1")) {
      return {
        decision: {
          decision_id: "dec_hosted_1",
          agent_id: JSON.parse(options.body).context.agent_id,
          allow: true,
          outcome: "allow",
          provenance: "ci_time",
          signature: "ed25519:test",
          kid: "oap:registry:key-2025-01",
        },
      };
    }
    throw new Error(`Unexpected URL ${url}`);
  };

  const hostedEvidence = {
    source: "github_action_runner",
    evidence_format: "aport.github.pr.v1",
    event_name: "pull_request",
    event_action: "synchronize",
    pull_request_number: 42,
    pull_request_merged: false,
    files_analyzed: true,
    commits_analyzed: true,
    files_changed: ["src/index.js"],
    lines_added: 10,
    lines_removed: 2,
    pull_request_head_sha: "abcdefabcdefabcdefabcdefabcdefabcdefabcd",
    structural_findings: [],
  };
  const oidcAudiences = [];
  const hosted = await runHostedVerify({
    apiUrl: "https://api.aport.io",
    verifyContext: {
      repository: "aporthq/agent-passport",
      action: "pr.update",
      branch: "main",
      evidence: hostedEvidence,
    },
    requestJson,
    getOidcToken: async (audience) => {
      oidcAudiences.push(audience);
      return `oidc:${audience}`;
    },
    verifyDecisionSignature: async () => ({ ok: true }),
  });

  assert.equal(hosted.success, true);
  assert.equal(hosted.agentId, "ap_hosted_github");
  assert.equal(hosted.decision.decision_id, "dec_hosted_1");
  assert.equal(hosted.signatureVerified, true);
  assert.equal(calls.length, 2);
  assert(calls[0].url.endsWith("/api/github/oidc/issue"));
  assert(calls[1].url.endsWith("/api/verify/policy/code.repository.merge.v1"));
  assert.deepEqual(oidcAudiences, [
    "aport.io",
    evidenceAudienceForContext({ evidence: hostedEvidence }, "aport.io"),
  ]);
  assert.equal(calls[0].options.headers["X-APort-OIDC"], "oidc:aport.io");
  assert.equal(
    calls[1].options.headers["X-APort-OIDC"],
    `oidc:${evidenceAudienceForContext(
      { evidence: hostedEvidence },
      "aport.io",
    )}`,
  );
  assert.equal(
    JSON.parse(calls[1].options.body).context.agent_id,
    "ap_hosted_github",
  );

  const customOidcAudiences = [];
  await runHostedVerify({
    apiUrl: "https://api.aport.io",
    oidcAudience: "https://staging.aport.io",
    verifyContext: {
      repository: "aporthq/agent-passport",
      action: "pr.update",
      branch: "main",
      evidence: hostedEvidence,
    },
    requestJson,
    getOidcToken: async (audience) => {
      customOidcAudiences.push(audience);
      return `oidc:${audience}`;
    },
    verifyDecisionSignature: async () => ({ ok: true }),
  });
  assert.deepEqual(customOidcAudiences, [
    "https://staging.aport.io",
    evidenceAudienceForContext(
      { evidence: hostedEvidence },
      "https://staging.aport.io",
    ),
  ]);

  await assert.rejects(
    () =>
      runHostedVerify({
        apiUrl: "https://api.aport.io",
        verifyContext: {
          repository: "aporthq/agent-passport",
          action: "pr.update",
          branch: "main",
        },
        requestJson,
        getOidcToken: async () => "oidc-token",
        verifyDecisionSignature: async () => ({
          ok: false,
          message: "test signature mismatch",
        }),
      }),
    (error) => error.message.includes(SIGNATURE_INVALID),
  );

  const invalidAutoFallback = await runAportVerification({
    mode: "auto",
    fallbackMode: "evidence-only",
    apiUrl: "https://api.aport.io",
    verifyContext: {},
    requestJson,
    getOidcToken: async () => "oidc-token",
    verifyDecisionSignature: async () => ({
      ok: false,
      message: "test signature mismatch",
    }),
  });
  assert.equal(invalidAutoFallback.mode, "auto-fallback");
  assert.equal(invalidAutoFallback.provenance, "unattributed");

  const missingSignature = await defaultVerifyDecisionSignature({
    apiUrl: "https://api.aport.io",
    decision: { decision_id: "dec_unsigned" },
    requestJson: async () => {
      throw new Error("must not fetch JWKS for unsigned decisions");
    },
  });
  assert.equal(missingSignature.ok, false);

  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const publicJwk = publicKey.export({ format: "jwk" });
  const signedDecision = {
    decision_id: "dec_signed_control_plane",
    passport_id: "ap_hosted_github",
    policy_id: "code.repository.merge.v1",
    agent_id: "ap_hosted_github",
    owner_id: "ap_org_github_free",
    assurance_level: "L2",
    allow: true,
    reasons: [
      {
        code: "oap.allowed",
        message: "Repository operation within limits and policy requirements",
        severity: "info",
      },
    ],
    issued_at: "2026-08-19T00:00:00.000Z",
    expires_at: "2026-08-20T00:00:00.000Z",
    passport_digest: "sha256:test",
    outcome: "allow",
    provenance: "ci_time",
    policy_hash: "sha256:policy",
    policy_version: "1.0.0",
    github: {
      action: "pr.update",
      actor: "github-actions[bot]",
      head_sha: "abc123",
      repository: "aporthq/agent-passport",
    },
    kid: "oap:registry:key-test",
  };
  const signedPayload = stableStringify({
    decision_id: signedDecision.decision_id,
    passport_id: signedDecision.passport_id,
    policy_id: signedDecision.policy_id,
    agent_id: signedDecision.agent_id,
    owner_id: signedDecision.owner_id,
    assurance_level: signedDecision.assurance_level,
    allow: signedDecision.allow,
    reasons: signedDecision.reasons,
    issued_at: signedDecision.issued_at,
    expires_at: signedDecision.expires_at,
    passport_digest: signedDecision.passport_digest,
    outcome: signedDecision.outcome,
    provenance: signedDecision.provenance,
    policy_hash: signedDecision.policy_hash,
    policy_version: signedDecision.policy_version,
    github: signedDecision.github,
  });
  signedDecision.signature = `ed25519:${sign(
    null,
    Buffer.from(signedPayload),
    privateKey,
  ).toString("base64")}`;

  const verifiedSignature = await defaultVerifyDecisionSignature({
    apiUrl: "https://api.aport.io",
    decision: signedDecision,
    requestJson: async (url) => {
      assert(url.endsWith("/.well-known/oap/jwks.json"));
      return {
        keys: [
          {
            ...publicJwk,
            kid: "key-test",
            alg: "EdDSA",
            use: "sig",
          },
        ],
      };
    },
  });
  assert.equal(verifiedSignature.ok, true);

  const fallback = await runAportVerification({
    mode: "auto",
    fallbackMode: "evidence-only",
    apiUrl: "https://api.aport.io",
    verifyContext: {},
    requestJson: async () => {
      throw new Error("network unavailable");
    },
    getOidcToken: async () => "oidc-token",
  });
  assert.equal(fallback.mode, "auto-fallback");
  assert.equal(fallback.provenance, "unattributed");

  const evidence = await runAportVerification({
    mode: "evidence-only",
    verifyContext: {},
    requestJson: async () => {
      throw new Error("must not call network");
    },
  });
  assert.equal(evidence.mode, "evidence-only");
  assert.equal(evidence.decision, null);

  const passportPath = path.join(os.tmpdir(), `aport-passport-${Date.now()}.json`);
  fs.writeFileSync(
    passportPath,
    JSON.stringify({
      agent_id: "ap_local_github",
      owner_id: "ap_org_demo",
      status: "active",
      capabilities: [{ id: "repo.pr.create" }],
      limits: { allowed_repos: ["aporthq/*"], allowed_base_branches: ["*"] },
    }),
  );
  const localCalls = [];
  const local = await runLocalJsonVerify({
    apiUrl: "https://api.aport.io",
    passportPath,
    verifyContext: {
      repository: "aporthq/agent-passport",
      action: "pr.update",
      branch: "main",
      require_oidc: true,
      authorization: {
        provider: "github_actions_oidc",
        require_oidc: true,
        action: "pr.update",
      },
    },
    requestJson: async (url, options) => {
      localCalls.push({ url, options });
      return {
        decision: {
          decision_id: "dec_local_1",
          allow: true,
          provenance: "local_json",
        },
      };
    },
  });
  fs.unlinkSync(passportPath);

  assert.equal(local.success, true);
  assert.equal(local.agentId, "ap_local_github");
  assert.equal(localCalls.length, 1);
  const localBody = JSON.parse(localCalls[0].options.body);
  assert.equal(localBody.passport.agent_id, "ap_local_github");
  assert.equal(localBody.context.agent_id, "ap_local_github");
  assert.equal(localBody.context.require_oidc, undefined);
  assert.equal(localBody.context.authorization, undefined);

  const trustedLocal = await runLocalJsonVerify({
    apiUrl: "https://api.aport.io",
    passportPath: ".aport/passport.json",
    verifyContext: {
      repository: "aporthq/agent-passport",
      action: "pr.update",
      branch: "main",
    },
    readTrustedPassport: async (requestedPath) => {
      assert.equal(requestedPath, ".aport/passport.json");
      return JSON.stringify({
        agent_id: "ap_trusted_base",
        owner_id: "ap_org_demo",
        status: "active",
        capabilities: [{ id: "repo.pr.create" }],
        limits: { allowed_repos: ["aporthq/*"], allowed_base_branches: ["*"] },
      });
    },
    requestJson: async () => ({
      decision: {
        decision_id: "dec_trusted_local_1",
        allow: true,
        provenance: "local_json",
      },
    }),
  });

  assert.equal(trustedLocal.success, true);
  assert.equal(trustedLocal.agentId, "ap_trusted_base");
}

main()
  .then(() => {
    console.log("OK aport.test.js");
  })
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });

function stableStringify(value) {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => stableStringify(item)).join(",")}]`;
  }
  const keys = Object.keys(value)
    .filter((key) => value[key] !== undefined)
    .sort();
  return `{${keys
    .map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`)
    .join(",")}}`;
}

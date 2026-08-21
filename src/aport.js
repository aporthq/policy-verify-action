const fs = require("fs");
const https = require("https");
const { createHash, createPublicKey, verify } = require("crypto");

const POLICY_ID = "code.repository.merge.v1";
const SIGNATURE_INVALID = "OAP.DECISION.SIGNATURE_INVALID";
const VALID_MODES = new Set(["auto", "hosted", "local-json", "evidence-only"]);

async function runAportVerification({
  mode,
  apiUrl,
  passportPath,
  fallbackMode,
  verifyContext,
  requestJson = defaultRequestJson,
  getOidcToken = defaultGetOidcToken,
  verifyDecisionSignature = defaultVerifyDecisionSignature,
  readTrustedPassport,
  oidcAudience,
}) {
  const normalizedMode = normalizeMode(mode);
  if (normalizedMode === "evidence-only") {
    return evidenceOnlyResult("evidence-only");
  }

  if (normalizedMode === "local-json") {
    return runLocalJsonVerify({
      apiUrl,
      passportPath,
      verifyContext,
      requestJson,
      readTrustedPassport,
    });
  }

  try {
    return await runHostedVerify({
      apiUrl,
      verifyContext,
      requestJson,
      getOidcToken,
      verifyDecisionSignature,
      oidcAudience,
    });
  } catch (error) {
    if (normalizedMode === "auto" && fallbackMode === "evidence-only") {
      return {
        ...evidenceOnlyResult("auto-fallback"),
        warning: `Hosted verification unavailable; fell back to evidence-only: ${error.message}`,
      };
    }
    return {
      mode: normalizedMode,
      provenance: "unattributed",
      success: false,
      warning: error.message,
    };
  }
}

async function runHostedVerify({
  apiUrl,
  verifyContext,
  requestJson = defaultRequestJson,
  getOidcToken = defaultGetOidcToken,
  verifyDecisionSignature = defaultVerifyDecisionSignature,
  oidcAudience = "aport.io",
}) {
  const baseAudience = normalizeOidcAudience(oidcAudience);
  const issueOidcToken = await getOidcToken(baseAudience);
  const issue = await requestJson(joinUrl(apiUrl, "/api/github/oidc/issue"), {
    method: "POST",
    headers: {
      "X-APort-OIDC": issueOidcToken,
    },
  });

  const agentId =
    issue?.data?.agent_id || issue?.data?.passport_id || issue?.agent_id;
  if (!agentId) {
    throw new Error("APort issue endpoint did not return agent_id");
  }

  const verifyAudience = evidenceAudienceForContext(verifyContext, baseAudience);
  const verifyOidcToken =
    verifyAudience === baseAudience
      ? issueOidcToken
      : await getOidcToken(verifyAudience);
  const decisionResponse = await requestJson(
    joinUrl(apiUrl, `/api/verify/policy/${POLICY_ID}`),
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-APort-OIDC": verifyOidcToken,
        "X-APort-Require-OIDC": "github",
      },
      body: JSON.stringify({
        context: {
          ...verifyContext,
          agent_id: agentId,
        },
      }),
    },
  );

  const result = normalizeDecisionResult("hosted", decisionResponse, {
    agentId,
    issueReused: Boolean(issue?.data?.reused),
  });
  const signature = await verifyDecisionSignature({
    apiUrl,
    decision: result.decision,
    requestJson,
  });
  if (!signature.ok) {
    throw new Error(`${SIGNATURE_INVALID}: ${signature.message}`);
  }

  return {
    ...result,
    signatureVerified: true,
  };
}

async function runLocalJsonVerify({
  apiUrl,
  passportPath,
  verifyContext,
  requestJson = defaultRequestJson,
  readTrustedPassport,
}) {
  if (!passportPath) {
    throw new Error("passport-path is required for local-json mode");
  }

  const passportText = readTrustedPassport
    ? await readTrustedPassport(passportPath)
    : fs.readFileSync(passportPath, "utf8");
  const passport = JSON.parse(passportText);
  const localContext = buildLocalJsonVerifyContext(verifyContext, passport);
  const decisionResponse = await requestJson(
    joinUrl(apiUrl, `/api/verify/policy/${POLICY_ID}`),
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        passport,
        context: localContext,
      }),
    },
  );

  return normalizeDecisionResult("local-json", decisionResponse, {
    agentId: passport.agent_id,
  });
}

function buildLocalJsonVerifyContext(verifyContext = {}, passport = {}) {
  const {
    authorization: _authorization,
    require_oidc: _requireOidc,
    ...context
  } = verifyContext || {};
  return {
    ...context,
    agent_id: context.agent_id || passport.agent_id,
  };
}

function normalizeDecisionResult(mode, response, extra = {}) {
  const decision = response?.decision || response?.data?.decision;
  return {
    mode,
    success: Boolean(decision),
    provenance: decision?.provenance || (mode === "hosted" ? "ci_time" : "local_json"),
    decision,
    ...extra,
  };
}

function evidenceOnlyResult(mode) {
  return {
    mode,
    success: true,
    provenance: "unattributed",
    decision: null,
  };
}

function normalizeMode(mode) {
  const rawValue = String(mode || "").trim();
  const value = rawValue ? rawValue.toLowerCase() : "auto";
  if (VALID_MODES.has(value)) {
    return value;
  }
  throw new Error(
    `Invalid APort verification mode "${rawValue}". Expected one of: ${Array.from(VALID_MODES).join(", ")}`,
  );
}

function normalizeOidcAudience(audience) {
  const value = String(audience || "").trim();
  return value || "aport.io";
}

function evidenceAudienceForContext(context = {}, baseAudience = "aport.io") {
  const evidence = context?.evidence;
  if (!evidence || typeof evidence !== "object" || Array.isArray(evidence)) {
    return baseAudience;
  }
  if (
    evidence.source !== "github_action_runner" ||
    evidence.evidence_format !== "aport.github.pr.v1"
  ) {
    return baseAudience;
  }
  const hash = createHash("sha256")
    .update(stableStringify(evidence))
    .digest("hex");
  return `${baseAudience}:evidence:${hash}`;
}

function joinUrl(base, path) {
  const normalizedBase = String(base || "https://api.aport.io").replace(/\/+$/, "");
  return `${normalizedBase}${path}`;
}

function defaultGetOidcToken(audience) {
  const requestUrl = process.env.ACTIONS_ID_TOKEN_REQUEST_URL;
  const requestToken = process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
  if (!requestUrl || !requestToken) {
    throw new Error("GitHub OIDC token is unavailable. Add `permissions: id-token: write`.");
  }

  const url = new URL(requestUrl);
  url.searchParams.set("audience", audience);
  return defaultRequestJson(url.toString(), {
    method: "GET",
    headers: {
      Authorization: `bearer ${requestToken}`,
    },
  }).then((result) => {
    if (!result?.value) {
      throw new Error("GitHub OIDC token response did not include value");
    }
    return result.value;
  });
}

function defaultRequestJson(url, options = {}) {
  return new Promise((resolve, reject) => {
    const body = options.body || "";
    const request = https.request(
      url,
      {
        method: options.method || "GET",
        headers: {
          Accept: "application/json",
          "User-Agent": "APort-Policy-Verify-Action/1.0",
          ...(body ? { "Content-Length": Buffer.byteLength(body) } : {}),
          ...(options.headers || {}),
        },
        timeout: 10000,
      },
      (response) => {
        let payload = "";
        response.setEncoding("utf8");
        response.on("data", (chunk) => {
          payload += chunk;
        });
        response.on("end", () => {
          let parsed = {};
          try {
            parsed = payload ? JSON.parse(payload) : {};
          } catch {
            parsed = { raw: payload.slice(0, 500) };
          }

          if (response.statusCode < 200 || response.statusCode >= 300) {
            reject(
              new Error(
                parsed.message ||
                  parsed.error ||
                  `HTTP ${response.statusCode} from ${url}`,
              ),
            );
            return;
          }
          resolve(parsed);
        });
      },
    );

    request.on("error", reject);
    request.on("timeout", () => {
      request.destroy(new Error(`Request timed out: ${url}`));
    });
    if (body) request.write(body);
    request.end();
  });
}

async function defaultVerifyDecisionSignature({ apiUrl, decision, requestJson = defaultRequestJson }) {
  if (!decision || typeof decision !== "object") {
    return { ok: false, message: "Hosted verification did not return a decision" };
  }

  const signature = String(decision.signature || "");
  const kid = String(decision.kid || "");
  if (!signature.startsWith("ed25519:") || signature === "ed25519:fallback-signature") {
    return { ok: false, message: "Hosted decision is not Ed25519-signed" };
  }
  if (!kid) {
    return { ok: false, message: "Hosted decision is missing key id" };
  }

  const jwks = await requestJson(joinUrl(apiUrl, "/.well-known/oap/jwks.json"));
  const key = findJwksKey(jwks, kid);
  if (!key) {
    return { ok: false, message: "No matching APort registry public key found" };
  }

  try {
    const publicKey = importEd25519Jwk(key);
    const payload = canonicalDecisionPayload(decision);
    const verified = verify(
      null,
      Buffer.from(payload),
      publicKey,
      base64ToUint8Array(signature.slice("ed25519:".length)),
    );
    return verified
      ? { ok: true }
      : { ok: false, message: "Hosted decision signature verification failed" };
  } catch (error) {
    return {
      ok: false,
      message: `Hosted decision signature verification failed: ${error.message}`,
    };
  }
}

function findJwksKey(jwks, kid) {
  const keys = Array.isArray(jwks?.keys) ? jwks.keys : [];
  const normalizedKid = normalizeKid(kid);
  return keys.find((key) => {
    const keyId = String(key?.kid || "");
    return (
      keyId === kid ||
      `oap:registry:${keyId}` === kid ||
      normalizeKid(keyId) === normalizedKid
    );
  });
}

function normalizeKid(kid) {
  return String(kid || "").replace(/^oap:registry:/, "");
}

function canonicalDecisionPayload(decision) {
  const hasControlPlaneFields =
    decision.outcome ||
    decision.provenance ||
    decision.policy_hash ||
    decision.policy_version ||
    decision.github;
  const payload = omitUndefined({
    decision_id: decision.decision_id,
    passport_id: decision.passport_id,
    policy_id: decision.policy_id,
    agent_id: decision.agent_id,
    owner_id: decision.owner_id,
    assurance_level: decision.assurance_level,
    allow: decision.allow,
    reasons: decision.reasons,
    issued_at: decision.issued_at,
    expires_at: decision.expires_at,
    passport_digest: decision.passport_digest,
    ...(hasControlPlaneFields
      ? {
          outcome: decision.outcome,
          provenance: decision.provenance,
          policy_hash: decision.policy_hash,
          policy_version: decision.policy_version,
          github: decision.github,
        }
      : {}),
  });
  return hasControlPlaneFields
    ? stableStringify(payload)
    : JSON.stringify(payload, Object.keys(payload).sort());
}

function omitUndefined(value) {
  return Object.fromEntries(
    Object.entries(value).filter(([, entryValue]) => entryValue !== undefined),
  );
}

function base64ToUint8Array(base64) {
  const binary = Buffer.from(base64, "base64");
  return new Uint8Array(binary.buffer, binary.byteOffset, binary.byteLength);
}

function importEd25519Jwk(jwk) {
  if (jwk?.kty !== "OKP" || jwk?.crv !== "Ed25519" || !jwk?.x) {
    throw new Error("APort registry key is not an Ed25519 JWK");
  }
  const rawPublicKey = base64UrlToBuffer(jwk.x);
  if (rawPublicKey.length !== 32) {
    throw new Error("APort registry key has invalid Ed25519 length");
  }
  const spkiHeader = Buffer.from("302a300506032b6570032100", "hex");
  return createPublicKey({
    key: Buffer.concat([spkiHeader, rawPublicKey]),
    format: "der",
    type: "spki",
  });
}

function base64UrlToBuffer(value) {
  const normalized = String(value).replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
  return Buffer.from(padded, "base64");
}

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

module.exports = {
  POLICY_ID,
  SIGNATURE_INVALID,
  defaultVerifyDecisionSignature,
  evidenceAudienceForContext,
  runAportVerification,
  runHostedVerify,
  runLocalJsonVerify,
  buildLocalJsonVerifyContext,
  normalizeMode,
  joinUrl,
};

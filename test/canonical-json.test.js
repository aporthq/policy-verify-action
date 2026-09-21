const assert = require("assert");
const { createPrivateKey, createPublicKey, sign } = require("crypto");
const { canonicalize, decisionSignaturePayload } = require("../src/canonical-json");
const { defaultVerifyDecisionSignature } = require("../src/aport");

async function main() {
  assert.equal(canonicalize({ "2": 2, "10": 10, b: { z: 2, a: 1 } }), '{"10":10,"2":2,"b":{"a":1,"z":2}}');
  assert.throws(() => canonicalize({ limits: { max: Infinity } }), /finite/);
  assert.throws(() => canonicalize("\ud800"), /Unicode/);
  const privateKey = createPrivateKey({
    key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.alloc(32, 7)]),
    format: "der", type: "pkcs8",
  });
  const key = { ...createPublicKey(privateKey).export({ format: "jwk" }), kid: "test-key" };
  const decision = {
    decision_id: "dec-fixed", passport_id: "ap_test", agent_id: "ap_test",
    owner_id: "owner-test", policy_id: "finance.payment.charge.v1", assurance_level: "L2",
    allow: true, reasons: [{ code: "oap.allowed", message: "Allowed" }],
    issued_at: "2026-01-01T00:00:00.000Z", expires_at: "2026-01-01T00:01:00.000Z",
    passport_digest: "sha256:test-fixture", kid: "oap:registry:test-key",
  };
  const verify = () => defaultVerifyDecisionSignature({
    apiUrl: "https://example.test", decision, requestJson: async () => ({ keys: [key] }),
  });
  decision.signature = `ed25519:${sign(null, Buffer.from(canonicalize(decisionSignaturePayload(decision))), privateKey).toString("base64")}`;
  assert.equal((await verify()).ok, true, "non-control-plane RFC 8785 signature verifies");
  decision.reasons[0].code = "oap.limit_exceeded";
  assert.equal((await verify()).ok, false, "modified nested reason invalidates signature");
  const payload = decisionSignaturePayload(decision);
  decision.signature = `ed25519:${sign(null, Buffer.from(JSON.stringify(payload, Object.keys(payload).sort())), privateKey).toString("base64")}`;
  assert.equal((await verify()).ok, false, "legacy lossy signatures are rejected");
  console.log("OK canonical-json.test.js");
}
main().catch((error) => { console.error(error); process.exitCode = 1; });

"use strict";

// Shared by the Workers signer and the standalone Action verifier. This lives
// in the Action package so its release contains the same implementation.
// RFC 8785: https://www.rfc-editor.org/rfc/rfc8785#section-3.2
function canonicalize(value) {
  if (value === null || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "string") {
    // Reject lone surrogates in values AND property names. Do not normalize Unicode.
    if (/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(value)) {
      throw new TypeError("JCS requires valid Unicode strings");
    }
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("JCS requires finite numbers");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${Array.from(value, canonicalize).join(",")}]`;
  }
  if (typeof value !== "object" ||
      (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null)) {
    throw new TypeError("JCS requires JSON data");
  }
  // Adapt optional in-memory fields to their wire representation: JSON omits
  // undefined object properties. Undefined array entries are not accepted.
  const keys = Object.keys(value).filter((key) => value[key] !== undefined).sort();
  // Emit pairs directly: constructing an object would re-order integer keys.
  return `{${keys.map((key) => `${canonicalize(key)}:${canonicalize(value[key])}`).join(",")}}`;
}

function decisionSignaturePayload(decision) {
  const fields = [
    "decision_id", "passport_id", "policy_id", "agent_id", "owner_id",
    "assurance_level", "allow", "reasons", "issued_at", "expires_at",
    "passport_digest", "outcome", "provenance", "policy_hash", "policy_version", "github",
  ];
  return Object.fromEntries(fields
    .filter((field) => decision[field] !== undefined)
    .map((field) => [field, decision[field]]));
}

module.exports = { canonicalize, decisionSignaturePayload };

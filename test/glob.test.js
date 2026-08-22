const assert = require("assert");
const { matchesGlob, normalizePath, normalizeRepositoryPath } = require("../src/glob");

assert.equal(matchesGlob("aporthq/*", "aporthq/agent-passport"), true);
assert.equal(matchesGlob("aporthq/*", "evilaporthq/agent-passport"), false);
assert.equal(matchesGlob(".github/workflows/**", ".github/workflows/ci.yml"), true);
assert.equal(matchesGlob(".github/workflows/**", ".github/actions/build/action.yml"), false);
assert.equal(matchesGlob("next.config.*", "next.config.js"), true);
assert.equal(matchesGlob("next.config.*", "src/next.config.js"), false);
assert.equal(matchesGlob("policies/**", "policies/code.repository.merge.v1/policy.json"), true);
assert.equal(matchesGlob("policies/**", "../policies/code.repository.merge.v1/policy.json"), false);
assert.equal(matchesGlob("src/**", "src\\payload.js"), false);
assert.equal(matchesGlob("src/**", "src/payload.js"), true);
assert.equal(normalizePath("\\.github\\workflows\\ci.yml"), ".github/workflows/ci.yml");
assert.equal(normalizeRepositoryPath("src\\payload.js"), "src\\payload.js");

console.log("OK glob.test.js");

const assert = require("assert");
const fs = require("fs");
const path = require("path");
const { classify, parseTrailers } = require("../src/attribution");

const cases = JSON.parse(
  fs.readFileSync(path.join(__dirname, "..", "fixtures", "attribution-cases.json"), "utf8"),
);

assert(cases.length >= 12, "attribution fixture suite must include at least 12 compact labelled cases");
assert(
  cases.filter((testCase) => testCase.expectedClass === "human").length >= 3,
  "attribution fixture suite must include at least 3 human cases",
);

for (const testCase of cases) {
  const result = classify(testCase.input);

  assert.equal(
    result.class,
    testCase.expectedClass,
    `${testCase.name} expected ${testCase.expectedClass}, got ${result.class}`,
  );

  if (testCase.expectedConfidence) {
    assert.equal(
      result.confidence,
      testCase.expectedConfidence,
      `${testCase.name} expected confidence ${testCase.expectedConfidence}, got ${result.confidence}`,
    );
  }

  if (testCase.expectedClass === "human") {
    assert.notEqual(result.class, "coding_agent", `${testCase.name} must not be classified as coding_agent`);
  }

  assert(result.signals?.length, `${testCase.name} should report checked attribution signals`);
}

assert.equal(parseTrailers("Subject\n\nAPort-Session: abc\nAPort-Decision: dec_123")["aport-decision"], "dec_123");

console.log("OK attribution.test.js");

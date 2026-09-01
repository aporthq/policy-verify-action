const assert = require("assert");
const {
  emitRunLog,
  escapeWorkflowCommandMessage,
  escapeWorkflowCommandProperty,
  sanitizePlainLogValue,
  stripTerminalControlBytes,
} = require("../src/logging");

assert.equal(
  escapeWorkflowCommandMessage("line1\nline2\r100%"),
  "line1%0Aline2%0D100%25",
);
assert.equal(
  escapeWorkflowCommandProperty("src/a:b,c%\n.js"),
  "src/a%3Ab%2Cc%25%0A.js",
);
assert.equal(
  sanitizePlainLogValue("web/next.config.js\n::stop-commands::x"),
  "web/next.config.js : :stop-commands: :x",
);
assert.equal(stripTerminalControlBytes("safe\u001b[31mred\u001b[0m"), "safered");
assert.equal(stripTerminalControlBytes("title\u001b]0;owned\u0007after"), "titleafter");
assert.equal(
  sanitizePlainLogValue("web/\u001b[2Knext.config.js\n::stop-commands::x"),
  "web/next.config.js : :stop-commands: :x",
);
assert.equal(
  escapeWorkflowCommandMessage("line1\u001b[31mred\nline2"),
  "line1red%0Aline2",
);
assert.equal(
  escapeWorkflowCommandProperty("src/\u001b[2Kfile:a,b\n.js"),
  "src/file%3Aa%2Cb%0A.js",
);

function captureStdout(fn) {
  const originalWrite = process.stdout.write;
  let output = "";
  process.stdout.write = (chunk) => {
    output += chunk;
    return true;
  };
  try {
    fn();
  } finally {
    process.stdout.write = originalWrite;
  }
  return output;
}

const output = captureStdout(() =>
  emitRunLog({
    repository: "aporthq/example",
    prNumber: 42,
    configuredMode: "hosted",
    verification: {
      mode: "hosted",
      decision: {
        allow: false,
        decision_id: "dec_123",
        outcome: "deny",
        reasons: [
          {
            code: "oap.blocked",
            message: "Workflow permission escalation",
          },
        ],
      },
    },
    structuralFindings: [
      {
        code: "OAP.REPO.WORKFLOW_PERMISSION_ESCALATION",
        severity: "high",
        message: "Workflow write permissions were introduced or expanded.",
        paths: [".github/workflows/deploy.yml"],
      },
      {
        code: "OAP.REPO.PROTECTED_PATH_TOUCHED",
        severity: "warning",
        message: "Protected repository paths changed.",
        paths: ["src/index.js", "web/\u001b[2Knext.config.js\n::stop-commands::x"],
      },
    ],
    warnings: ["Could not read optional base policy\u001b[31m\n::warning::injected"],
    willFail: true,
  }),
);

assert(output.includes("APort Repository Guard"));
assert(output.includes("-----------------------"));
assert(output.includes("Repository: aporthq/example"));
assert(output.includes("Pull request: #42"));
assert(output.includes("Decision: deny"));
assert(output.includes("Decision ID: dec_123"));
assert(output.includes("- oap.blocked: Workflow permission escalation"));
assert(
  output.includes(
    "- HIGH OAP.REPO.WORKFLOW_PERMISSION_ESCALATION: Workflow write permissions were introduced or expanded. (.github/workflows/deploy.yml)",
  ),
);
assert(
  output.includes(
    "::error title=Blocking APort finding%3A OAP.REPO.WORKFLOW_PERMISSION_ESCALATION,file=.github/workflows/deploy.yml::Workflow write permissions were introduced or expanded. (.github/workflows/deploy.yml)",
  ),
);
assert(
  output.includes(
    "::warning title=APort finding%3A OAP.REPO.PROTECTED_PATH_TOUCHED,file=src/index.js::Protected repository paths changed. (src/index.js)",
  ),
);
assert(
  output.includes(
    "- WARNING OAP.REPO.PROTECTED_PATH_TOUCHED: Protected repository paths changed. (src/index.js, web/next.config.js : :stop-commands: :x)",
  ),
);
assert(!output.includes("\u001b"));
assert(!output.includes("\n::stop-commands::x"));
assert(!output.includes("\n::warning::injected"));
assert(
  output.includes(
    "file=web/next.config.js%0A%3A%3Astop-commands%3A%3Ax::Protected repository paths changed. (web/next.config.js%0A::stop-commands::x)",
  ),
);
assert(
  output.includes(
    "::error title=APort Repository Guard blocked this workflow::Hosted enforcement failed because APort returned a deny decision",
  ),
);

console.log("OK logging.test.js");

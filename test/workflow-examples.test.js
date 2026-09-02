const assert = require("assert");
const fs = require("fs");
const path = require("path");

const root = path.join(__dirname, "..");
const files = [
  ".github/workflows/aport-guard.yml",
  "simple-example.yml",
  "example-usage.yml",
  "example-repo/README.md",
  "README.md",
];

for (const file of files) {
  const text = fs.readFileSync(path.join(root, file), "utf8");
  assert(
    /\n\s*push:\n/.test(text),
    `${file} should include push detection for protected branches`,
  );
  assert(
    text.includes("aporthq/policy-verify-action@v1") ||
      file === ".github/workflows/aport-guard.yml",
    `${file} should point users at the stable v1 action`,
  );
}

console.log("OK workflow-examples.test.js");

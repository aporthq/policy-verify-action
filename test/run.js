const { spawnSync } = require("child_process");
const fs = require("fs");
const path = require("path");

const testDir = __dirname;
const testFiles = fs
  .readdirSync(testDir)
  .filter((file) => file.endsWith(".test.js"))
  .sort();

for (const file of testFiles) {
  const result = spawnSync(process.execPath, [path.join(testDir, file)], {
    stdio: "inherit",
  });

  if (result.status !== 0) {
    process.exit(result.status || 1);
  }
}

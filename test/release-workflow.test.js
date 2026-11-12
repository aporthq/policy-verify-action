const assert = require("assert");
const { spawnSync } = require("child_process");
const fs = require("fs");
const path = require("path");

const workflowPath = path.join(
  __dirname,
  "..",
  ".github",
  "workflows",
  "release.yml",
);
const workflow = fs.readFileSync(workflowPath, "utf8");

function indexOfRequired(value, description) {
  const index = workflow.indexOf(value);
  assert.notEqual(index, -1, `${description} was not found`);
  return index;
}

const integrityIndex=indexOfRequired(
  'uses: aporthq/policy-verify-action/integrity@d1ccc3aa355c449018ee1adef5a59b3b79c92fb2',
  'immutable integrity scan',
);
assert(integrityIndex < indexOfRequired('run: npm test','candidate test command'),
  'scan Git objects before candidate tests or release commands');
assert(workflow.includes('head: ${{ steps.integrity-revision.outputs.sha }}'));
assert(!workflow.includes('continue-on-error:'),'release integrity cannot be bypassed');
const monitor=fs.readFileSync(path.join(__dirname,'..','.github/workflows/repository-integrity.yml'),'utf8');
assert(monitor.includes("branches: ['**']")&&monitor.includes("tags: ['**']"),'monitor all branch and tag pushes');
assert(monitor.includes('policy-verify-action/integrity@d1ccc3aa355c449018ee1adef5a59b3b79c92fb2'));

function extractReleaseScript() {
  const stepIndex = workflow.indexOf("- name: Create next patch release");
  assert.notEqual(stepIndex, -1, "release step was not found");

  const marker = "        run: |\n";
  const runIndex = workflow.indexOf(marker, stepIndex);
  assert.notEqual(runIndex, -1, "release run block was not found");

  const lines = workflow.slice(runIndex + marker.length).split(/\r?\n/);
  const scriptLines = [];
  for (const line of lines) {
    if (line.startsWith("          ")) {
      scriptLines.push(line.slice(10));
    } else if (!line.trim()) {
      scriptLines.push("");
    } else {
      break;
    }
  }
  return scriptLines.join("\n");
}

assert(
  !workflow.includes("Current commit already has a semver release tag; skipping."),
  "workflow must not skip just because the current commit is tagged",
);
assert(
  !/git tag --points-at "\$current_sha"[\s\S]{0,500}exit 0/.test(workflow),
  "existing-tag path must resume release artifacts instead of exiting early",
);

const currentTagIndex = indexOfRequired(
  'current_tag="$(git tag --points-at "$current_sha"',
  "current commit tag lookup",
);
const latestTagIndex = indexOfRequired(
  'latest_tag="$(printf "%s\\n" "$semver_tags"',
  "latest semver tag lookup",
);
const resumeIndex = indexOfRequired(
  "resuming release artifacts",
  "resume message for already-tagged commits",
);
const historicalIndex = indexOfRequired(
  "historical release tag",
  "historical tag resume path",
);
const releaseNotesIndex = indexOfRequired(
  "} > release_notes.md",
  "release notes generation",
);
const releaseViewIndex = indexOfRequired(
  'gh release view "$next_tag"',
  "release existence check",
);
const releaseEditIndex = indexOfRequired(
  'gh release edit "$next_tag"',
  "existing release repair",
);
const releaseCreateIndex = indexOfRequired(
  'gh release create "$next_tag"',
  "missing release creation",
);
const majorAliasIndex = indexOfRequired(
  'major_sha="$(git rev-parse',
  "major alias verification",
);
const minorAliasIndex = indexOfRequired(
  'minor_sha="$(git rev-parse',
  "minor alias verification",
);
const skipAliasIndex = indexOfRequired(
  "Skipping stable alias updates for historical release",
  "historical alias skip",
);

assert(currentTagIndex > latestTagIndex);
assert(resumeIndex > currentTagIndex);
assert(historicalIndex > currentTagIndex);
assert(releaseNotesIndex > resumeIndex);
assert(releaseViewIndex > releaseNotesIndex);
assert(releaseEditIndex > releaseViewIndex);
assert(releaseCreateIndex > releaseViewIndex);
assert(skipAliasIndex > releaseViewIndex);
assert(majorAliasIndex > skipAliasIndex);
assert(minorAliasIndex > majorAliasIndex);

assert(workflow.includes("--title \"APort Repository Guard ${next_tag}\""));
assert(workflow.includes("--notes-file release_notes.md"));
assert(workflow.includes("--latest"));
assert(workflow.includes("--latest=false"));
assert(workflow.includes('gh release edit "$latest_tag" --latest'));
assert(workflow.includes('git push origin "refs/tags/${major_tag}" --force'));
assert(workflow.includes('git push origin "refs/tags/${minor_tag}" --force'));

const syntaxCheck = spawnSync("bash", ["-n"], {
  input: extractReleaseScript(),
  encoding: "utf8",
});
assert.equal(syntaxCheck.status, 0, syntaxCheck.stderr);

console.log("OK release-workflow.test.js");

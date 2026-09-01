const assert = require("assert");
const { spawnSync } = require("child_process");
const fs = require("fs");
const path = require("path");

const workflowPath = path.join(
  process.cwd(),
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

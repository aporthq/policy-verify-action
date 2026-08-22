const assert = require("assert");
const {
  buildGitHubApiUrl,
  getPullRequestData,
  readBaseFile,
  readBasePolicy,
} = require("../src/github");

async function main() {
  process.env.GITHUB_REPOSITORY = "aporthq/agent-passport";

  const calls = [];
  const result = await readBasePolicy(
    {
      pull_request: {
        base: {
          sha: "base-sha-123",
          ref: "main",
        },
      },
    },
    async (path) => {
      calls.push(path);
      if (path.includes(".aport/policy.yaml")) {
        return { ok: false, status: 404, data: [], error: "not found" };
      }
      return {
        ok: true,
        status: 200,
        data: {
          encoding: "base64",
          content: Buffer.from("repository:\n  protected_paths:\n    - policies/**\n").toString("base64"),
        },
      };
    },
  );

  assert.equal(calls.length, 2);
  assert(calls[0].includes("ref=base-sha-123"));
  assert.equal(result.policy.path, ".aport/policy.yml");
  assert.equal(result.policy.ref, "base-sha-123");
  assert(result.policy.text.includes("protected_paths"));
  assert.deepEqual(result.warnings, []);

  process.env.GITHUB_EVENT_NAME = "push";
  const trustedPushPolicy = await readBasePolicy(
    {
      before: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      after: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    },
    async (path) => {
      assert(path.includes("ref=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
      return {
        ok: true,
        status: 200,
        data: {
          encoding: "base64",
          content: Buffer.from("github:\n  require_pinned_actions: true\n").toString("base64"),
        },
      };
    },
  );

  assert.equal(trustedPushPolicy.policy.path, ".aport/policy.yaml");
  assert.equal(trustedPushPolicy.policy.ref, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
  assert(trustedPushPolicy.policy.text.includes("require_pinned_actions"));
  assert.deepEqual(trustedPushPolicy.warnings, []);
  delete process.env.GITHUB_EVENT_NAME;

  process.env.GITHUB_EVENT_NAME = "merge_group";
  const trustedMergeGroupPolicy = await readBasePolicy(
    {
      action: "checks_requested",
      merge_group: {
        base_sha: "cccccccccccccccccccccccccccccccccccccccc",
        head_sha: "dddddddddddddddddddddddddddddddddddddddd",
      },
    },
    async (path) => {
      assert(path.includes("ref=cccccccccccccccccccccccccccccccccccccccc"));
      return {
        ok: true,
        status: 200,
        data: {
          encoding: "base64",
          content: Buffer.from("github:\n  require_pinned_actions: true\n").toString("base64"),
        },
      };
    },
  );

  assert.equal(trustedMergeGroupPolicy.policy.path, ".aport/policy.yaml");
  assert.equal(trustedMergeGroupPolicy.policy.ref, "cccccccccccccccccccccccccccccccccccccccc");
  assert(trustedMergeGroupPolicy.policy.text.includes("require_pinned_actions"));
  assert.deepEqual(trustedMergeGroupPolicy.warnings, []);
  delete process.env.GITHUB_EVENT_NAME;

  const baseFile = await readBaseFile(
    {
      pull_request: {
        base: {
          sha: "base-sha-789",
        },
      },
    },
    ".aport/passport.json",
    async (path) => {
      assert(path.includes("/contents/.aport/passport.json?"));
      return {
        ok: true,
        status: 200,
        data: {
          encoding: "base64",
          content: Buffer.from('{"agent_id":"ap_base"}').toString("base64"),
        },
      };
    },
  );

  assert.equal(baseFile.file.ref, "base-sha-789");
  assert.equal(baseFile.file.text, '{"agent_id":"ap_base"}');
  assert.deepEqual(baseFile.warnings, []);
  assert.equal(
    buildGitHubApiUrl(
      "/repos/aporthq/agent-passport/pulls/1/files",
      "https://ghe.example/api/v3",
    ).toString(),
    "https://ghe.example/api/v3/repos/aporthq/agent-passport/pulls/1/files",
  );

  const missing = await readBasePolicy(
    {
      pull_request: {
        base: {
          sha: "base-sha-456",
        },
      },
    },
    async () => ({ ok: false, status: 404, data: [], error: "not found" }),
  );
  assert.equal(missing.policy, null);
  assert.deepEqual(missing.warnings, []);

  const paths = [];
  const prData = await getPullRequestData(
    {
      pull_request: {
        number: 9,
      },
    },
    async (path) => {
      paths.push(path);
      const page = new URL(path, "https://api.github.test").searchParams.get("page");
      if (path.includes("/files?")) {
        return {
          ok: true,
          status: 200,
          data: page === "1"
            ? Array.from({ length: 100 }, (_, index) => ({
                filename: `src/file-${index}.ts`,
              }))
            : [{ filename: "src/file-100.ts" }],
        };
      }
      return {
        ok: true,
        status: 200,
        data: page === "1"
          ? Array.from({ length: 100 }, (_, index) => ({ sha: `sha-${index}` }))
          : [{ sha: "sha-100" }],
      };
    },
  );

  assert.equal(prData.files.length, 101);
  assert.equal(prData.commits.length, 101);
  assert(paths.some((path) => path.includes("files?per_page=100&page=2")));
  assert(paths.some((path) => path.includes("commits?per_page=100&page=2")));

  const partialFailure = await getPullRequestData(
    {
      pull_request: {
        number: 10,
      },
    },
    async (path) => {
      const page = new URL(path, "https://api.github.test").searchParams.get("page");
      if (path.includes("/files?") && page === "2") {
        return { ok: false, status: 502, data: [], error: "gateway" };
      }
      return {
        ok: true,
        status: 200,
        data: Array.from({ length: page === "1" ? 100 : 1 }, (_, index) => ({
          filename: `src/partial-${page}-${index}.ts`,
          sha: `sha-${page}-${index}`,
        })),
      };
    },
  );

  assert.equal(partialFailure.evidenceTruncated.files, true);
  assert(partialFailure.warnings.some((warning) => warning.includes("Could not fetch PR files")));

  process.env.GITHUB_EVENT_NAME = "push";
  process.env.GITHUB_SHA = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
  const pushPaths = [];
  const pushData = await getPullRequestData(
    {
      before: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      after: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      commits: [],
    },
    async (path) => {
      pushPaths.push(path);
      return {
        ok: true,
        status: 200,
        data: {
          total_commits: 1,
          commits: [{ sha: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" }],
          files: [
            {
              filename: ".github/workflows/deploy.yml",
              additions: 4,
              deletions: 0,
            },
          ],
        },
      };
    },
  );

  assert.equal(pushData.files.length, 1);
  assert.equal(pushData.commits.length, 1);
  assert.equal(pushData.evidenceTruncated.files, false);
  assert.equal(pushData.evidenceTruncated.commits, false);
  assert(pushPaths[0].includes("/compare/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa...bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"));

  const pushFallback = await getPullRequestData(
    {
      before: "0000000000000000000000000000000000000000",
      after: "cccccccccccccccccccccccccccccccccccccccc",
      commits: [
        {
          id: "cccccccccccccccccccccccccccccccccccccccc",
          added: ["src/new.ts"],
          modified: [".github/workflows/ci.yml"],
          removed: ["old.js"],
        },
      ],
    },
    async () => {
      throw new Error("compare should not be called for zero before SHA");
    },
  );

  assert.deepEqual(
    pushFallback.files.map((file) => file.filename),
    ["src/new.ts", ".github/workflows/ci.yml", "old.js"],
  );
  assert.equal(pushFallback.evidenceTruncated.files, true);
  assert.equal(pushFallback.evidenceTruncated.commits, true);
  assert(pushFallback.warnings.some((warning) => warning.includes("marking evidence incomplete")));
  delete process.env.GITHUB_EVENT_NAME;

  process.env.GITHUB_EVENT_NAME = "merge_group";
  process.env.GITHUB_SHA = "dddddddddddddddddddddddddddddddddddddddd";
  const mergeGroupPaths = [];
  const mergeGroupData = await getPullRequestData(
    {
      action: "checks_requested",
      merge_group: {
        base_sha: "cccccccccccccccccccccccccccccccccccccccc",
        head_sha: "dddddddddddddddddddddddddddddddddddddddd",
        base_ref: "refs/heads/main",
        head_ref: "refs/heads/gh-readonly-queue/main/pr-12",
        head_commit: {
          id: "dddddddddddddddddddddddddddddddddddddddd",
          message: "merge queue candidate",
        },
      },
    },
    async (path) => {
      mergeGroupPaths.push(path);
      return {
        ok: true,
        status: 200,
        data: {
          total_commits: 1,
          commits: [{ sha: "dddddddddddddddddddddddddddddddddddddddd" }],
          files: [
            {
              filename: "src/queued.ts",
              additions: 7,
              deletions: 1,
            },
          ],
        },
      };
    },
  );

  assert.equal(mergeGroupData.files.length, 1);
  assert.equal(mergeGroupData.commits.length, 1);
  assert.equal(mergeGroupData.evidenceTruncated.files, false);
  assert.equal(mergeGroupData.evidenceTruncated.commits, false);
  assert(mergeGroupPaths[0].includes("/compare/cccccccccccccccccccccccccccccccccccccccc...dddddddddddddddddddddddddddddddddddddddd"));
  delete process.env.GITHUB_EVENT_NAME;
  delete process.env.GITHUB_SHA;
}

main()
  .then(() => {
    console.log("OK github.test.js");
  })
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });

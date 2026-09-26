const assert = require("assert");
const {
  assertSafeGitHubApiUrl,
  buildGitHubApiUrl,
  classifyPushAction,
  getPullRequestData,
  getRepositoryDefaultBranch,
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
      ref: "refs/heads/main",
      before: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      after: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      commits: [],
    },
    async (path) => {
      pushPaths.push(path);
      if (path.includes("/commits/") && path.includes("/pulls?")) {
        return {
          ok: true,
          status: 200,
          data: [],
        };
      }
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
  assert.equal(pushData.repositoryAction, "repo.push");
  assert.equal(pushData.pushClassification.push_classification, "direct");
  // per_page is asserted with the page parameter appended, not as a bare
  // substring: "per_page=10" is a prefix of "per_page=100", so the looser form
  // passed either way and measured nothing.
  assert(pushPaths.some((path) => path.includes("/commits/") && path.includes("/pulls?per_page=100&page=1")));
  assert(pushPaths.some((path) => path.includes("/compare/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa...bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")));

  const mergePushPaths = [];
  const mergePushData = await getPullRequestData(
    {
      ref: "refs/heads/main",
      before: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      after: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      commits: [],
    },
    async (path) => {
      mergePushPaths.push(path);
      if (path.includes("/commits/") && path.includes("/pulls?")) {
        return {
          ok: true,
          status: 200,
          data: [
            {
              number: 42,
              state: "closed",
              merged_at: "2026-09-04T12:00:00Z",
              base: {
                ref: "main",
              },
              head: { sha: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" },
              merge_commit_sha: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            },
          ],
        };
      }
      if (path.includes("/pulls/42/commits")) {
        // A squash merge: the pull request's own commits never land as-is.
        return { ok: true, status: 200, data: [{ sha: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" }] };
      }
      if (path.includes("/pulls/42/files")) {
        return {
          ok: true,
          status: 200,
          data: [
            {
              filename: "src/merged.js",
              status: "modified",
              additions: 2,
              deletions: 1,
              changes: 3,
              patch: "@@ -10,3 +10,4 @@\n context before\n-old\n+new one\n+new two\n context after",
            },
          ],
        };
      }
      return {
        ok: true,
        status: 200,
        data: {
          total_commits: 1,
          commits: [
            {
              sha: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
              parents: [{ sha: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }],
            },
          ],
          files: [
            {
              filename: "src/merged.js",
              status: "modified",
              additions: 2,
              deletions: 1,
              changes: 3,
              patch: "@@ -10,3 +10,4 @@\n context before\n-old\n+new one\n+new two\n context after",
            },
          ],
        },
      };
    },
  );

  assert.equal(mergePushData.repositoryAction, "pr.merge");
  assert.equal(mergePushData.pushClassification.push_classification, "merged_pull_request");
  assert.equal(mergePushData.pushClassification.pull_request_number, 42);
  assert.equal(mergePushData.evidenceTruncated.files, false);
  assert.equal(mergePushData.evidenceTruncated.commits, false);
  assert(mergePushPaths.some((path) => path.includes("/compare/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa...bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")));
  assert(mergePushPaths.some((path) => path.includes("/pulls/42/commits?per_page=100")));
  assert(mergePushPaths.some((path) => path.includes("/pulls/42/files?per_page=100")));
  assert.deepEqual(mergePushData.warnings, []);

  const rateLimitedLookupCalls = [];
  const rateLimitedLookup = await classifyPushAction(
    {
      owner: "aporthq",
      repo: "agent-passport",
      before: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      after: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      branch: "main",
      ref: "refs/heads/main",
    },
    async (path) => {
      rateLimitedLookupCalls.push(path);
      if (rateLimitedLookupCalls.length === 1) {
        return {
          ok: false,
          status: 403,
          headers: { "x-ratelimit-remaining": "0" },
          data: [],
          error: "API rate limit exceeded",
        };
      }
      return {
        ok: true,
        status: 200,
        data: [
          {
            number: 43,
            state: "closed",
            merged_at: "2026-09-04T12:00:00Z",
            base: { ref: "main" },
            merge_commit_sha: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
          },
        ],
      };
    },
    { attempts: 2, delayMs: 0, sleep: async () => {} },
  );
  assert.equal(rateLimitedLookupCalls.length, 2);
  assert.equal(rateLimitedLookup.action, "pr.merge");
  assert.equal(rateLimitedLookup.evidence.push_classification, "merged_pull_request");

  const forbiddenLookupCalls = [];
  const forbiddenLookup = await classifyPushAction(
    {
      owner: "aporthq",
      repo: "agent-passport",
      before: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      after: "cccccccccccccccccccccccccccccccccccccccc",
      branch: "main",
      ref: "refs/heads/main",
    },
    async (path) => {
      forbiddenLookupCalls.push(path);
      return { ok: false, status: 403, data: [], error: "Resource not accessible by integration" };
    },
    { attempts: 3, delayMs: 0, sleep: async () => {} },
  );
  assert.equal(forbiddenLookupCalls.length, 1);
  assert.equal(forbiddenLookup.action, "repo.push");
  assert.equal(forbiddenLookup.evidence.push_classification, "unknown");
  assert.match(forbiddenLookup.warnings[0], /after 1 failed attempt/);

  const pagedMergeCalls = [];
  const pagedMergeLookup = await classifyPushAction(
    {
      owner: "aporthq",
      repo: "agent-passport",
      before: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      after: "dddddddddddddddddddddddddddddddddddddddd",
      branch: "main",
      ref: "refs/heads/main",
    },
    async (path) => {
      pagedMergeCalls.push(path);
      const page = new URL(path, "https://api.github.test").searchParams.get("page");
      if (page === "1") {
        return {
          ok: true,
          status: 200,
          data: [
            {
              number: 44,
              state: "closed",
              merged_at: "2026-09-04T12:00:00Z",
              base: { ref: "main" },
              merge_commit_sha: "dddddddddddddddddddddddddddddddddddddddd",
            },
            ...Array.from({ length: 99 }, (_, index) => ({ number: index + 1000 })),
          ],
        };
      }
      return { ok: false, status: 503, data: [], error: "page two down" };
    },
    { attempts: 3, delayMs: 0, sleep: async () => {} },
  );
  assert.equal(pagedMergeCalls.length, 2);
  assert.equal(pagedMergeLookup.action, "pr.merge");
  assert.equal(pagedMergeLookup.evidence.push_classification, "merged_pull_request");
  assert.equal(pagedMergeLookup.evidence.pull_request_number, 44);

  const exactCapCalls = [];
  const exactCapLookup = await classifyPushAction(
    {
      owner: "aporthq",
      repo: "agent-passport",
      before: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      after: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
      branch: "main",
      ref: "refs/heads/main",
    },
    async (path) => {
      exactCapCalls.push(path);
      const page = Number(new URL(path, "https://api.github.test").searchParams.get("page"));
      return {
        ok: true,
        status: 200,
        data: page <= 5
          ? Array.from({ length: 100 }, (_, index) => ({ number: (page - 1) * 100 + index + 1 }))
          : [],
      };
    },
    { attempts: 1, delayMs: 0, sleep: async () => {} },
  );
  assert.equal(exactCapCalls.length, 6);
  assert.equal(exactCapLookup.action, "repo.push");
  assert.equal(exactCapLookup.evidence.push_classification, "direct");
  assert.deepEqual(exactCapLookup.warnings, []);

  const overCapCalls = [];
  const overCapLookup = await classifyPushAction(
    {
      owner: "aporthq",
      repo: "agent-passport",
      before: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      after: "ffffffffffffffffffffffffffffffffffffffff",
      branch: "main",
      ref: "refs/heads/main",
    },
    async (path) => {
      overCapCalls.push(path);
      const page = Number(new URL(path, "https://api.github.test").searchParams.get("page"));
      return {
        ok: true,
        status: 200,
        data: page <= 6
          ? Array.from({ length: 100 }, (_, index) => ({ number: (page - 1) * 100 + index + 1 }))
          : [],
      };
    },
    { attempts: 1, delayMs: 0, sleep: async () => {} },
  );
  assert.equal(overCapCalls.length, 6);
  assert.equal(overCapLookup.action, "repo.push");
  assert.equal(overCapLookup.evidence.push_classification, "unknown");
  assert.equal(overCapLookup.evidence.push_classification_reason, "associated_pr_list_truncated");
  assert.match(overCapLookup.warnings[0], /more than 500 associated pull requests/);

  const pushFallbackPaths = [];
  const pushFallback = await getPullRequestData(
    {
      ref: "refs/heads/main",
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
    async (path) => {
      pushFallbackPaths.push(path);
      throw new Error(`no API call is expected for a branch creation, got ${path}`);
    },
  );

  assert.deepEqual(
    pushFallback.files.map((file) => file.filename),
    ["src/new.ts", ".github/workflows/ci.yml", "old.js"],
  );
  assert.equal(pushFallback.evidenceTruncated.files, true);
  assert.equal(pushFallback.evidenceTruncated.commits, true);
  assert.equal(pushFallback.repositoryAction, "repo.push");
  assert.equal(pushFallback.pushClassification.push_classification, "created");
  assert.equal(pushFallback.pushClassification.push_classification_reason, "branch_created");
  assert.deepEqual(pushFallbackPaths, []);
  assert(pushFallback.warnings.some((warning) => warning.includes("marking evidence incomplete")));

  // A branch deletion never looks up pull requests or compares.
  const deletionPaths = [];
  const deletion = await getPullRequestData(
    {
      ref: "refs/heads/feature/x",
      before: "cccccccccccccccccccccccccccccccccccccccc",
      after: "0000000000000000000000000000000000000000",
      deleted: true,
      commits: [],
    },
    async (path) => {
      deletionPaths.push(path);
      throw new Error(`no API call is expected for a branch deletion, got ${path}`);
    },
  );
  assert.equal(deletion.pushClassification.push_classification, "direct");
  assert.equal(deletion.pushClassification.push_classification_reason, "branch_deleted");
  assert.deepEqual(deletionPaths, []);

  // Cleartext GitHub API URLs: loopback only, unless explicitly allowed.
  assertSafeGitHubApiUrl(new URL("https://api.github.com/"), {});
  assertSafeGitHubApiUrl(new URL("http://127.0.0.1:8080/"), {});
  assertSafeGitHubApiUrl(new URL("http://localhost:8080/"), {});
  assertSafeGitHubApiUrl(new URL("http://[::1]:8080/"), {});
  // Credentials and ports do not change the host; a lookalike host is not
  // loopback; credentials that spell "localhost" still resolve to the real
  // host. Numeric forms of 127.0.0.1 are normalised by the URL parser.
  assertSafeGitHubApiUrl(new URL("http://user:pw@localhost:9/"), {});
  assertSafeGitHubApiUrl(new URL("http://127.1/"), {});
  assertSafeGitHubApiUrl(new URL("HTTP://LOCALHOST/"), {});
  for (const url of [
    "http://localhost.evil.test/",
    "http://127.0.0.1.evil.test/",
    "http://localhost:8080@evil.test/",
    "http://[::ffff:127.0.0.1]/",
    "http://0.0.0.0/",
  ]) {
    assert.throws(() => assertSafeGitHubApiUrl(new URL(url), {}), /plain http/, url);
  }
  assert.throws(
    () => assertSafeGitHubApiUrl(new URL("http://ghe.example/api/v3/"), {}),
    /Refusing to send the GitHub token over plain http to ghe\.example/,
  );
  assert.throws(
    () => assertSafeGitHubApiUrl(new URL("http://ghe.example/api/v3/"), { APORT_ALLOW_INSECURE_GITHUB_API: "true" }),
    /plain http/,
  );
  assertSafeGitHubApiUrl(new URL("http://ghe.example/api/v3/"), { APORT_ALLOW_INSECURE_GITHUB_API: "1" });
  assert.throws(
    () => assertSafeGitHubApiUrl(new URL("ftp://ghe.example/"), {}),
    /unsupported protocol/,
  );

  // GET /repos/{owner}/{repo} default branch lookup.
  process.env.GITHUB_REPOSITORY = "aporthq/agent-passport";
  const defaultBranchPaths = [];
  const defaultBranch = await getRepositoryDefaultBranch(async (path) => {
    defaultBranchPaths.push(path);
    return { ok: true, status: 200, data: { default_branch: "trunk" } };
  });
  assert.deepEqual(defaultBranch, { defaultBranch: "trunk", error: "" });
  assert.deepEqual(defaultBranchPaths, ["/repos/aporthq/agent-passport"]);
  const defaultBranchDown = await getRepositoryDefaultBranch(async () => ({
    ok: false,
    status: 503,
    data: [],
    error: "unavailable",
  }));
  assert.equal(defaultBranchDown.defaultBranch, "");
  assert.match(defaultBranchDown.error, /503/);
  const defaultBranchMissing = await getRepositoryDefaultBranch(async () => ({
    ok: true,
    status: 200,
    data: {},
  }));
  assert.equal(defaultBranchMissing.defaultBranch, "");
  assert.match(defaultBranchMissing.error, /no default_branch/);
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

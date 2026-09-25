// Runs src/index.js as the action would, against a local stand-in for the
// GitHub API, and checks the exit code, the push-classification output, and
// the summary for each default-branch protection case.
const assert = require("assert");
const { spawn } = require("child_process");
const fs = require("fs");
const http = require("http");
const os = require("os");
const path = require("path");

const AFTER = "b".repeat(40);
const BEFORE = "a".repeat(40);
const HEAD = "e".repeat(40);
const P1 = "1".repeat(40);
const D = "d".repeat(40);
const ZERO = "0".repeat(40);
const REPOSITORY = "aporthq/example";
const entry = path.join(__dirname, "..", "src", "index.js");

const mergedPull = {
  number: 42,
  state: "closed",
  merged_at: "2026-09-04T12:00:00Z",
  base: { ref: "main" },
  head: { sha: HEAD },
  merge_commit_sha: AFTER,
};

const commit = (sha, ...parents) => ({ sha, parents: parents.map((parent) => ({ sha: parent })) });
const file = (filename = "src/a.js", overrides = {}) => ({
  filename,
  status: "modified",
  additions: 1,
  deletions: 0,
  changes: 1,
  patch: "@@ -1,3 +1,3 @@\n context before\n-old\n+new\n context after",
  ...overrides,
});
const squashCompare = () => ({
  status: 200,
  body: {
    total_commits: 1,
    commits: [commit(AFTER, BEFORE)],
    files: [file()],
  },
});

function startApi() {
  const state = {};
  const reset = () => {
    state.pulls = () => ({ status: 200, body: [] });
    state.compare = squashCompare;
    state.prCommits = () => ({ status: 200, body: [{ sha: P1 }, { sha: HEAD }] });
    state.prFiles = () => ({ status: 200, body: [file()] });
    state.repo = () => ({ status: 200, body: { default_branch: "main" } });
    state.pullsCalls = 0;
    state.repoCalls = 0;
    state.prCommitsCalls = 0;
    state.prFilesCalls = 0;
  };
  reset();
  state.reset = reset;
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, "http://localhost");
    const send = (status, body, headers = {}) => {
      res.writeHead(status, { "content-type": "application/json", ...headers });
      res.end(JSON.stringify(body));
    };
    if (/\/commits\/[a-f0-9]{40}\/pulls$/.test(url.pathname)) {
      state.pullsCalls += 1;
      const reply = state.pulls();
      send(reply.status, reply.body, reply.headers);
      return;
    }
    if (url.pathname.includes("/compare/")) {
      const reply = state.compare();
      send(reply.status, reply.body);
      return;
    }
    if (/\/pulls\/\d+\/commits$/.test(url.pathname)) {
      state.prCommitsCalls += 1;
      const reply = state.prCommits();
      send(reply.status, reply.body);
      return;
    }
    if (/\/pulls\/\d+\/files$/.test(url.pathname)) {
      state.prFilesCalls += 1;
      const reply = state.prFiles();
      send(reply.status, reply.body);
      return;
    }
    if (url.pathname === `/repos/${REPOSITORY}`) {
      state.repoCalls += 1;
      const reply = state.repo();
      send(reply.status, reply.body);
      return;
    }
    send(404, { message: "Not Found" });
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      resolve({ server, state, port: server.address().port });
    });
  });
}

// The API stand-in lives in this process, so the action must run asynchronously
// or the server can never answer it.
function spawnAction(env) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [entry], { env });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });
    child.on("close", (status) => resolve({ status, stdout, stderr }));
  });
}

async function runAction({ port, event, eventName, ref, protect, extraEnv = {}, apiUrl }) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "aport-push-e2e-"));
  const eventPath = path.join(dir, "event.json");
  const outputPath = path.join(dir, "output.txt");
  const summaryPath = path.join(dir, "summary.md");
  fs.writeFileSync(eventPath, JSON.stringify(event));
  fs.writeFileSync(outputPath, "");
  fs.writeFileSync(summaryPath, "");

  const result = await spawnAction({
      PATH: process.env.PATH,
      GITHUB_EVENT_NAME: eventName,
      GITHUB_EVENT_PATH: eventPath,
      GITHUB_OUTPUT: outputPath,
      GITHUB_STEP_SUMMARY: summaryPath,
      GITHUB_REPOSITORY: REPOSITORY,
      GITHUB_REF: ref,
      GITHUB_SHA: AFTER,
      GITHUB_ACTOR: "octocat",
      GITHUB_API_URL: apiUrl || `http://127.0.0.1:${port}`,
      GITHUB_TOKEN: "test-token",
      APORT_MODE: "evidence-only",
      APORT_PROTECT_DEFAULT_BRANCH: protect ? "true" : "false",
      APORT_PUSH_LOOKUP_DELAY_MS: "0",
      ...extraEnv,
  });

  const outputs = Object.fromEntries(
    fs
      .readFileSync(outputPath, "utf8")
      .split("\n")
      .filter((line) => line.includes("="))
      .map((line) => {
        const index = line.indexOf("=");
        return [line.slice(0, index), line.slice(index + 1)];
      }),
  );
  const summary = fs.readFileSync(summaryPath, "utf8");
  fs.rmSync(dir, { recursive: true, force: true });
  return { status: result.status, stdout: result.stdout, stderr: result.stderr, outputs, summary };
}

function pushEvent(overrides = {}) {
  return {
    ref: "refs/heads/main",
    before: BEFORE,
    after: AFTER,
    forced: false,
    created: false,
    deleted: false,
    commits: [],
    sender: { login: "octocat", type: "User" },
    repository: { full_name: REPOSITORY, default_branch: "main" },
    ...overrides,
  };
}

async function main() {
  const { server, state, port } = await startApi();
  try {
    // Forced push to main, protection on: fails, no PR lookup.
    state.pullsCalls = 0;
    const forced = await runAction({
      port,
      event: pushEvent({ forced: true }),
      eventName: "push",
      ref: "refs/heads/main",
      protect: true,
    });
    assert.equal(forced.status, 1, forced.stdout + forced.stderr);
    assert.equal(forced.outputs["push-classification"], "forced");
    assert.match(forced.summary, /OAP\.REPO\.FORCE_PUSH/);
    assert.match(forced.summary, /\*\*Blocked\.\*\*/);
    assert.match(forced.stdout, /::error title=APort Repository Guard blocked this workflow::protect-default-branch is enabled and the push to main was forced\./);
    assert.equal(state.pullsCalls, 0);

    // Direct push to main, protection on: fails after the retry budget.
    state.reset();
    const direct = await runAction({
      port,
      event: pushEvent(),
      eventName: "push",
      ref: "refs/heads/main",
      protect: true,
    });
    assert.equal(direct.status, 1, direct.stdout + direct.stderr);
    assert.equal(direct.outputs["push-classification"], "direct");
    assert.match(direct.summary, /OAP\.REPO\.DIRECT_PUSH_DEFAULT_BRANCH/);
    assert.match(direct.summary, /\| Push classification \| direct \|/);
    assert.match(direct.summary, /\| Default branch protection \| enabled \|/);
    assert.equal(state.pullsCalls, 3);

    // Merged pull request (a squash) landing on main, protection on: passes,
    // and the pull request commits were checked against the push.
    state.reset();
    state.pulls = () => ({ status: 200, body: [mergedPull] });
    const merged = await runAction({
      port,
      event: pushEvent(),
      eventName: "push",
      ref: "refs/heads/main",
      protect: true,
    });
    assert.equal(merged.status, 0, merged.stdout + merged.stderr);
    assert.equal(merged.outputs["push-classification"], "merged_pull_request");
    assert.doesNotMatch(merged.summary, /OAP\.REPO\.DIRECT_PUSH_DEFAULT_BRANCH/);
    assert.doesNotMatch(merged.summary, /OAP\.REPO\.FORCE_PUSH/);
    assert.equal(state.pullsCalls, 1);
    assert.equal(state.prCommitsCalls, 1);
    assert.equal(state.prFilesCalls, 1);
    assert.equal(state.repoCalls, 0);

    // A merge commit merge: the PR commits plus the merge commit. Passes.
    state.reset();
    state.pulls = () => ({ status: 200, body: [mergedPull] });
    state.compare = () => ({
      status: 200,
      body: {
        total_commits: 3,
        commits: [commit(P1, BEFORE), commit(HEAD, P1), commit(AFTER, BEFORE, HEAD)],
        files: [file()],
      },
    });
    const mergeCommit = await runAction({
      port,
      event: pushEvent(),
      eventName: "push",
      ref: "refs/heads/main",
      protect: true,
    });
    assert.equal(mergeCommit.status, 0, mergeCommit.stdout + mergeCommit.stderr);
    assert.equal(mergeCommit.outputs["push-classification"], "merged_pull_request");

    // `git push origin feature:main`: GitHub reports the PR merged with its own
    // head as the merge commit. Fails as a direct push.
    state.reset();
    state.pulls = () => ({ status: 200, body: [{ ...mergedPull, head: { sha: AFTER } }] });
    state.compare = () => ({
      status: 200,
      body: {
        total_commits: 2,
        commits: [commit(P1, BEFORE), commit(AFTER, P1)],
        files: [file()],
      },
    });
    const fastForward = await runAction({
      port,
      event: pushEvent(),
      eventName: "push",
      ref: "refs/heads/main",
      protect: true,
    });
    assert.equal(fastForward.status, 1, fastForward.stdout + fastForward.stderr);
    assert.equal(fastForward.outputs["push-classification"], "direct");
    assert.match(fastForward.summary, /OAP\.REPO\.DIRECT_PUSH_DEFAULT_BRANCH/);
    assert.match(fastForward.summary, /head of pull request #42 itself/);
    assert.equal(state.prCommitsCalls, 0);

    // A local merge pushed with an extra direct commit: [P1, HEAD, D, M].
    // Fails as a direct push and names the commit.
    state.reset();
    state.pulls = () => ({ status: 200, body: [mergedPull] });
    state.prCommits = () => ({ status: 200, body: [{ sha: P1 }, { sha: HEAD }, { sha: "f".repeat(40) }] });
    state.compare = () => ({
      status: 200,
      body: {
        total_commits: 4,
        commits: [commit(P1, BEFORE), commit(HEAD, P1), commit(D, BEFORE), commit(AFTER, D, HEAD)],
        files: [file()],
      },
    });
    const localMerge = await runAction({
      port,
      event: pushEvent(),
      eventName: "push",
      ref: "refs/heads/main",
      protect: true,
    });
    assert.equal(localMerge.status, 1, localMerge.stdout + localMerge.stderr);
    assert.equal(localMerge.outputs["push-classification"], "direct");
    assert.match(localMerge.summary, /OAP\.REPO\.DIRECT_PUSH_DEFAULT_BRANCH/);
    assert.match(localMerge.summary, new RegExp(`not part of pull request #42 \\(${D.slice(0, 12)}\\)`));

    // The PR commits cannot be read: unknown, fail closed.
    state.reset();
    state.pulls = () => ({ status: 200, body: [mergedPull] });
    state.prCommits = () => ({ status: 500, body: { message: "boom" } });
    const prCommitsDown = await runAction({
      port,
      event: pushEvent(),
      eventName: "push",
      ref: "refs/heads/main",
      protect: true,
    });
    assert.equal(prCommitsDown.status, 1, prCommitsDown.stdout + prCommitsDown.stderr);
    assert.equal(prCommitsDown.outputs["push-classification"], "unknown");
    assert.match(prCommitsDown.summary, /commits of pull request #42/);

    // A push that creates the default branch: not a direct push, no lookup.
    state.reset();
    const created = await runAction({
      port,
      event: pushEvent({ before: ZERO, created: true }),
      eventName: "push",
      ref: "refs/heads/main",
      protect: true,
    });
    assert.equal(created.status, 0, created.stdout + created.stderr);
    assert.equal(created.outputs["push-classification"], "created");
    assert.doesNotMatch(created.summary, /OAP\.REPO\.DIRECT_PUSH_DEFAULT_BRANCH/);
    assert.match(created.summary, /\| Push classification \| created \|/);
    assert.equal(state.pullsCalls, 0);

    // PR lookup keeps failing, protection on: retried, then fail closed.
    state.reset();
    state.pulls = () => ({ status: 503, body: { message: "unavailable" } });
    const down = await runAction({
      port,
      event: pushEvent(),
      eventName: "push",
      ref: "refs/heads/main",
      protect: true,
    });
    assert.equal(down.status, 1, down.stdout + down.stderr);
    assert.equal(down.outputs["push-classification"], "unknown");
    assert.match(down.summary, /OAP\.REPO\.DIRECT_PUSH_DEFAULT_BRANCH/);
    assert.match(down.summary, /after 3 failed attempts \(503\)/);
    assert.equal(state.pullsCalls, 3);

    // A 403 is final: one attempt, unknown, fail closed.
    state.reset();
    state.pulls = () => ({ status: 403, body: { message: "forbidden" } });
    const forbidden = await runAction({
      port,
      event: pushEvent(),
      eventName: "push",
      ref: "refs/heads/main",
      protect: true,
    });
    assert.equal(forbidden.status, 1, forbidden.stdout + forbidden.stderr);
    assert.equal(forbidden.outputs["push-classification"], "unknown");
    assert.match(forbidden.summary, /after 1 failed attempt \(403\)/);
    assert.equal(state.pullsCalls, 1);

    // GitHub reports some API rate limits as 403. Those carry rate-limit
    // evidence and stay retryable; ordinary permission 403s above do not.
    state.reset();
    state.pulls = () =>
      state.pullsCalls === 1
        ? {
            status: 403,
            headers: { "x-ratelimit-remaining": "0" },
            body: { message: "API rate limit exceeded" },
          }
        : { status: 200, body: [mergedPull] };
    const rateLimited = await runAction({
      port,
      event: pushEvent(),
      eventName: "push",
      ref: "refs/heads/main",
      protect: true,
    });
    assert.equal(rateLimited.status, 0, rateLimited.stdout + rateLimited.stderr);
    assert.equal(rateLimited.outputs["push-classification"], "merged_pull_request");
    assert.equal(state.pullsCalls, 2);

    // PR lookup fails once, then finds the merge: passes.
    state.reset();
    state.pulls = () =>
      state.pullsCalls === 1
        ? { status: 502, body: { message: "bad gateway" } }
        : { status: 200, body: [mergedPull] };
    const recovered = await runAction({
      port,
      event: pushEvent(),
      eventName: "push",
      ref: "refs/heads/main",
      protect: true,
    });
    assert.equal(recovered.status, 0, recovered.stdout + recovered.stderr);
    assert.equal(recovered.outputs["push-classification"], "merged_pull_request");
    assert.equal(state.pullsCalls, 2);

    // Direct push to main, protection off: report-only, exit 0. The lookup is
    // still retried on an empty result so the output matches the enforcing
    // run.
    state.reset();
    const directOff = await runAction({
      port,
      event: pushEvent(),
      eventName: "push",
      ref: "refs/heads/main",
      protect: false,
    });
    assert.equal(directOff.status, 0, directOff.stdout + directOff.stderr);
    assert.equal(directOff.outputs["push-classification"], "direct");
    assert.doesNotMatch(directOff.summary, /OAP\.REPO\.DIRECT_PUSH_DEFAULT_BRANCH/);
    assert.match(directOff.summary, /\| Default branch protection \| disabled \|/);
    assert.match(directOff.stdout, /Default branch protection: disabled\n/);
    assert.equal(state.pullsCalls, 3);

    // Forced push to main, protection off: exit 0 with a warning finding.
    state.reset();
    const forcedOff = await runAction({
      port,
      event: pushEvent({ forced: true }),
      eventName: "push",
      ref: "refs/heads/main",
      protect: false,
    });
    assert.equal(forcedOff.status, 0, forcedOff.stdout + forcedOff.stderr);
    assert.equal(forcedOff.outputs["push-classification"], "forced");
    assert.match(forcedOff.summary, /\*\*WARNING\*\* `OAP\.REPO\.FORCE_PUSH`/);

    // Direct push to a non-default branch, protection on: out of scope.
    state.reset();
    const feature = await runAction({
      port,
      event: pushEvent({ ref: "refs/heads/feature/x" }),
      eventName: "push",
      ref: "refs/heads/feature/x",
      protect: true,
    });
    assert.equal(feature.status, 0, feature.stdout + feature.stderr);
    assert.equal(feature.outputs["push-classification"], "direct");
    assert.doesNotMatch(feature.summary, /OAP\.REPO\.DIRECT_PUSH_DEFAULT_BRANCH/);
    assert.match(feature.summary, /enabled \(not the default branch\)/);
    assert.match(feature.stdout, /Default branch protection: enabled \(not the default branch\)/);
    assert.equal(state.pullsCalls, 1);

    // Direct push to a non-default branch, protection off: "disabled" in both
    // the summary and the log.
    state.reset();
    const featureOff = await runAction({
      port,
      event: pushEvent({ ref: "refs/heads/feature/x" }),
      eventName: "push",
      ref: "refs/heads/feature/x",
      protect: false,
    });
    assert.equal(featureOff.status, 0, featureOff.stdout + featureOff.stderr);
    assert.match(featureOff.summary, /\| Default branch protection \| disabled \|/);
    assert.match(featureOff.stdout, /Default branch protection: disabled\n/);

    // Payload without repository.default_branch: read it from the API.
    state.reset();
    const apiDefault = await runAction({
      port,
      event: pushEvent({ repository: { full_name: REPOSITORY } }),
      eventName: "push",
      ref: "refs/heads/main",
      protect: true,
    });
    assert.equal(apiDefault.status, 1, apiDefault.stdout + apiDefault.stderr);
    assert.equal(apiDefault.outputs["push-classification"], "direct");
    assert.match(apiDefault.summary, /OAP\.REPO\.DIRECT_PUSH_DEFAULT_BRANCH/);
    assert.match(apiDefault.summary, /\| Default branch protection \| enabled \|/);
    assert.equal(state.repoCalls, 1);
    assert.equal(state.pullsCalls, 3);

    // Payload without repository.default_branch and the input names it: no
    // API call, and a merge on it passes.
    state.reset();
    state.pulls = () => ({ status: 200, body: [mergedPull] });
    const inputDefault = await runAction({
      port,
      event: pushEvent({ repository: { full_name: REPOSITORY } }),
      eventName: "push",
      ref: "refs/heads/main",
      protect: true,
      extraEnv: { APORT_DEFAULT_BRANCH: "main" },
    });
    assert.equal(inputDefault.status, 0, inputDefault.stdout + inputDefault.stderr);
    assert.equal(inputDefault.outputs["push-classification"], "merged_pull_request");
    assert.equal(state.repoCalls, 0);

    // No default branch anywhere, protection on: fail closed.
    state.reset();
    state.repo = () => ({ status: 500, body: { message: "boom" } });
    const noDefault = await runAction({
      port,
      event: pushEvent({ repository: { full_name: REPOSITORY } }),
      eventName: "push",
      ref: "refs/heads/main",
      protect: true,
    });
    assert.equal(noDefault.status, 1, noDefault.stdout + noDefault.stderr);
    assert.equal(noDefault.outputs["push-classification"], "direct");
    assert.match(noDefault.summary, /OAP\.REPO\.DIRECT_PUSH_DEFAULT_BRANCH/);
    assert.match(noDefault.summary, /default branch could not be determined/);
    assert.match(noDefault.summary, /Set the default-branch input/);
    assert.equal(state.repoCalls, 1);

    // No default branch anywhere, protection off: exit 0, still a warning.
    state.reset();
    state.repo = () => ({ status: 500, body: { message: "boom" } });
    const noDefaultOff = await runAction({
      port,
      event: pushEvent({ repository: { full_name: REPOSITORY } }),
      eventName: "push",
      ref: "refs/heads/main",
      protect: false,
    });
    assert.equal(noDefaultOff.status, 0, noDefaultOff.stdout + noDefaultOff.stderr);
    assert.doesNotMatch(noDefaultOff.summary, /OAP\.REPO\.DIRECT_PUSH_DEFAULT_BRANCH/);
    assert.match(noDefaultOff.summary, /Set the default-branch input/);

    // A cleartext GitHub API URL that is not loopback is refused before any
    // request carries the token. With protection on, that failure exits 1 and
    // still reports the push as unknown.
    state.reset();
    const insecure = await runAction({
      port,
      event: pushEvent(),
      eventName: "push",
      ref: "refs/heads/main",
      protect: true,
      apiUrl: "http://ghe.invalid/api/v3",
    });
    assert.equal(insecure.status, 1, insecure.stdout + insecure.stderr);
    assert.equal(insecure.outputs["push-classification"], "unknown");
    assert.match(insecure.summary, /Default branch protection could not complete/);
    assert.match(insecure.summary, /plain http to ghe\.invalid/);
    assert.match(insecure.stdout, /::error title=APort Repository Guard could not complete::/);
    assert.equal(state.pullsCalls, 0);

    // The same failure on a push to another branch, protection on: the
    // protection never applied, so the run stays report-only.
    state.reset();
    const insecureFeature = await runAction({
      port,
      event: pushEvent({ ref: "refs/heads/feature/x" }),
      eventName: "push",
      ref: "refs/heads/feature/x",
      protect: true,
      apiUrl: "http://ghe.invalid/api/v3",
    });
    assert.equal(insecureFeature.status, 0, insecureFeature.stdout + insecureFeature.stderr);
    assert.equal(insecureFeature.outputs["push-classification"], "unknown");
    assert.match(insecureFeature.summary, /Report-only mode could not complete/);
    assert.equal(state.pullsCalls, 0);

    // The same failure with protection off stays report-only.
    state.reset();
    const insecureOff = await runAction({
      port,
      event: pushEvent(),
      eventName: "push",
      ref: "refs/heads/main",
      protect: false,
      apiUrl: "http://ghe.invalid/api/v3",
    });
    assert.equal(insecureOff.status, 0, insecureOff.stdout + insecureOff.stderr);
    assert.equal(insecureOff.outputs["push-classification"], "unknown");
    assert.match(insecureOff.summary, /Report-only mode could not complete/);

    // Pull request event, protection on: not a push.
    state.reset();
    const pullRequest = await runAction({
      port,
      event: {
        action: "synchronize",
        number: 7,
        pull_request: {
          number: 7,
          user: { login: "octocat", type: "User" },
          head: { ref: "feature/x", sha: "c".repeat(40), repo: { full_name: REPOSITORY } },
          base: { ref: "main", sha: BEFORE },
        },
        repository: { full_name: REPOSITORY, default_branch: "main" },
        sender: { login: "octocat", type: "User" },
      },
      eventName: "pull_request",
      ref: "refs/pull/7/merge",
      protect: true,
    });
    assert.equal(pullRequest.status, 0, pullRequest.stdout + pullRequest.stderr);
    assert.equal(pullRequest.outputs["push-classification"], "not_push");
    assert.doesNotMatch(pullRequest.summary, /\| Push classification \|/);
    assert.equal(state.pullsCalls, 0);
  } finally {
    server.close();
  }
}

main()
  .then(() => {
    console.log("OK push-protection-e2e.test.js");
  })
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });

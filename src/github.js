const fs = require("fs");
const http = require("http");
const https = require("https");
const { branchFromGitRef, isNonBranchRef, isZeroSha } = require("./git-ref");

const LOOPBACK_HOSTS = new Set(["127.0.0.1", "localhost", "[::1]", "::1"]);

/**
 * Refuse to send the GitHub token over cleartext. GITHUB_API_URL is https on
 * github.com and GHES. Plain http is only accepted for a loopback host (the
 * end-to-end tests run a local stand-in for the API) or when the operator
 * sets APORT_ALLOW_INSECURE_GITHUB_API=1 on purpose.
 */
function assertSafeGitHubApiUrl(url, env = process.env) {
  if (url.protocol === "https:") return;
  if (url.protocol !== "http:") {
    throw new Error(`Refusing GitHub API URL with unsupported protocol: ${url.protocol}`);
  }
  if (LOOPBACK_HOSTS.has(url.hostname)) return;
  if (String(env.APORT_ALLOW_INSECURE_GITHUB_API || "").trim() === "1") return;
  throw new Error(
    `Refusing to send the GitHub token over plain http to ${url.host}. Use an https GITHUB_API_URL, or set APORT_ALLOW_INSECURE_GITHUB_API=1 if this is intended.`,
  );
}

function readEventPayload() {
  const eventPath = process.env.GITHUB_EVENT_PATH;
  if (!eventPath) return {};

  try {
    return JSON.parse(fs.readFileSync(eventPath, "utf8"));
  } catch (error) {
    return { __error: `Failed to read GitHub event payload: ${error.message}` };
  }
}

function githubRequest(path) {
  const token = process.env.GITHUB_TOKEN || process.env.GH_TOKEN || "";
  const repo = process.env.GITHUB_REPOSITORY || "";
  const apiUrl = process.env.GITHUB_API_URL || "https://api.github.com";
  const url = buildGitHubApiUrl(path, apiUrl);
  assertSafeGitHubApiUrl(url);
  const client = url.protocol === "http:" ? http : https;

  return new Promise((resolve) => {
    const req = client.request(url, {
      headers: {
        "Accept": "application/vnd.github+json",
        "User-Agent": "APort-Policy-Verify-Action/1.0",
        ...(token ? { "Authorization": `Bearer ${token}` } : {}),
        ...(repo ? { "X-GitHub-Api-Version": "2022-11-28" } : {}),
      },
    }, (res) => {
      const headers = res.headers || {};
      let body = "";
      res.setEncoding("utf8");
      res.on("data", (chunk) => {
        body += chunk;
      });
      res.on("end", () => {
        if (res.statusCode < 200 || res.statusCode >= 300) {
          resolve({ ok: false, status: res.statusCode, headers, data: [], error: body.slice(0, 500) });
          return;
        }
        try {
          resolve({ ok: true, status: res.statusCode, headers, data: JSON.parse(body) });
        } catch (error) {
          resolve({ ok: false, status: res.statusCode, headers, data: [], error: error.message });
        }
      });
    });

    req.on("error", (error) => {
      resolve({ ok: false, status: 0, data: [], error: error.message });
    });
    req.setTimeout(10000, () => {
      req.destroy(new Error("GitHub API request timed out"));
    });
    req.end();
  });
}

async function readBasePolicy(event, request = githubRequest) {
  if (!hasTrustedBaseFileRef(event)) {
    return { policy: null, warnings: [] };
  }

  const warnings = [];
  for (const policyPath of [".aport/policy.yaml", ".aport/policy.yml"]) {
    const result = await readBaseFile(event, policyPath, request);
    warnings.push(...result.warnings);
    if (result.file) {
      return {
        policy: {
          path: policyPath,
          ref: result.file.ref,
          source: result.file.source,
          text: result.file.text,
        },
        warnings,
      };
    }
  }

  return { policy: null, warnings };
}

function hasTrustedBaseFileRef(event) {
  const repository = process.env.GITHUB_REPOSITORY || "";
  return Boolean(repository && resolveTrustedFileRef(event));
}

async function readBaseFile(event, filePath, request = githubRequest) {
  const resolved = resolveBaseFileRequest(event, filePath);
  if (!resolved.ok) {
    return { file: null, warnings: [resolved.warning] };
  }

  const result = await request(resolved.path);
  if (!result.ok) {
    if (result.status === 404) {
      return { file: null, warnings: [] };
    }
    return {
      file: null,
      warnings: [
        `Could not read base file ${filePath} from GitHub API (${result.status}): ${result.error || "unknown error"}`,
      ],
    };
  }

  const content = decodeGitHubContent(result.data);
  if (!content) {
    return {
      file: null,
      warnings: [`Base file ${filePath} was found but could not be decoded.`],
    };
  }

  return {
    file: {
      path: filePath,
      ref: resolved.ref,
      source: `${filePath}@${String(resolved.ref).slice(0, 12)}`,
      text: content,
    },
    warnings: [],
  };
}

function resolveBaseFileRequest(event, filePath) {
  const repository = process.env.GITHUB_REPOSITORY || "";
  const ref = resolveTrustedFileRef(event);
  if (!repository || !ref) {
    return { ok: false, warning: "Could not resolve trusted base branch ref." };
  }

  const normalizedPath = normalizeRepositoryPath(filePath);
  if (!normalizedPath) {
    return { ok: false, warning: `Refusing to read unsafe repository path: ${filePath}` };
  }

  const [owner, repo] = repository.split("/");
  if (!owner || !repo) {
    return { ok: false, warning: "Could not resolve trusted base branch ref." };
  }

  const encodedPath = normalizedPath
    .split("/")
    .map((segment) => encodeURIComponent(segment))
    .join("/");
  return {
    ok: true,
    ref,
    path: `/repos/${owner}/${repo}/contents/${encodedPath}?ref=${encodeURIComponent(ref)}`,
  };
}

function resolveTrustedFileRef(event) {
  const pr = event.pull_request || (event.number && event.head && event.base ? event : null);
  if (pr?.base) {
    return pr.base.sha || pr.base.ref || process.env.GITHUB_BASE_REF || "";
  }

  const mergeGroup = event.merge_group;
  if (isMergeGroupEvent(event) && mergeGroup) {
    return mergeGroup.base_sha || mergeGroup.base_ref || "";
  }

  if (isPushEvent(event)) {
    const before = String(event.before || "");
    return isSha(before) && !isZeroSha(before) ? before : "";
  }

  return "";
}

function isPushEvent(event) {
  return (
    process.env.GITHUB_EVENT_NAME === "push" ||
    typeof event.before === "string" ||
    typeof event.after === "string"
  );
}

function isMergeGroupEvent(event) {
  return (
    process.env.GITHUB_EVENT_NAME === "merge_group" ||
    Boolean(event?.merge_group)
  );
}

function normalizeRepositoryPath(filePath) {
  const normalized = String(filePath || "").trim().replace(/^\.\/+/, "");
  if (
    !normalized ||
    normalized.startsWith("/") ||
    normalized.includes("\0") ||
    normalized.split("/").some((segment) => segment === "..")
  ) {
    return "";
  }
  return normalized;
}

function decodeGitHubContent(data) {
  if (typeof data?.content !== "string") return "";
  const encoding = String(data.encoding || "base64").toLowerCase();
  if (encoding !== "base64") return "";
  return Buffer.from(data.content.replace(/\s/g, ""), "base64").toString("utf8");
}

async function getPullRequestData(event, request = githubRequest, options = {}) {
  const repository = process.env.GITHUB_REPOSITORY || "";
  const pr = event.pull_request || (event.number && event.head && event.base ? event : null);
  if (!pr?.number && isMergeGroupEvent(event)) {
    return getMergeGroupData(event, request);
  }
  if (!pr?.number && (process.env.GITHUB_EVENT_NAME === "push" || event.before || event.after)) {
    return getPushData(event, request, options.pushLookup);
  }

  if (!repository || !pr?.number) {
    return {
      files: [],
      commits: [],
      evidenceTruncated: { files: true, commits: true, maxPages: 0 },
      warnings: ["This Action currently summarizes pull_request and push events; repository evidence is incomplete."],
    };
  }

  const [owner, repo] = repository.split("/");
  const filesPath = `/repos/${owner}/${repo}/pulls/${pr.number}/files?per_page=100`;
  const commitsPath = `/repos/${owner}/${repo}/pulls/${pr.number}/commits?per_page=100`;
  const [filesResult, commitsResult] = await Promise.all([
    githubRequestAllPages(filesPath, request),
    githubRequestAllPages(commitsPath, request),
  ]);

  const warnings = [];
  if (!filesResult.ok) warnings.push(`Could not fetch PR files from GitHub API (${filesResult.status}): ${filesResult.error || "unknown error"}`);
  if (!commitsResult.ok) warnings.push(`Could not fetch PR commits from GitHub API (${commitsResult.status}): ${commitsResult.error || "unknown error"}`);
  if (filesResult.truncated) warnings.push(`PR files exceeded the ${filesResult.maxPages * 100} item safety limit; evidence was truncated.`);
  if (commitsResult.truncated) warnings.push(`PR commits exceeded the ${commitsResult.maxPages * 100} item safety limit; evidence was truncated.`);
  const filesIncomplete = !filesResult.ok || Boolean(filesResult.truncated);
  const commitsIncomplete = !commitsResult.ok || Boolean(commitsResult.truncated);

  return {
    files: Array.isArray(filesResult.data) ? filesResult.data : [],
    commits: Array.isArray(commitsResult.data) ? commitsResult.data : [],
    evidenceTruncated: {
      files: filesIncomplete,
      commits: commitsIncomplete,
      maxPages: Math.max(filesResult.maxPages || 0, commitsResult.maxPages || 0),
    },
    warnings,
  };
}

async function getMergeGroupData(event, request = githubRequest) {
  const repository = process.env.GITHUB_REPOSITORY || "";
  const [owner, repo] = repository.split("/");
  const mergeGroup = event.merge_group || {};
  const baseSha = String(mergeGroup.base_sha || "");
  const headSha = String(mergeGroup.head_sha || process.env.GITHUB_SHA || "");
  const warnings = [];

  if (!owner || !repo || !isSha(baseSha) || !isSha(headSha)) {
    const fallback = mergeGroupPayloadEvidence(event);
    warnings.push(
      "Could not resolve a complete merge-group compare range; using merge-group payload and marking evidence incomplete.",
    );
    return {
      ...fallback,
      evidenceTruncated: {
        files: true,
        commits: true,
        maxPages: 0,
      },
      warnings,
    };
  }

  const comparePath = `/repos/${owner}/${repo}/compare/${encodeURIComponent(baseSha)}...${encodeURIComponent(headSha)}`;
  const result = await request(comparePath);
  if (!result.ok) {
    const fallback = mergeGroupPayloadEvidence(event);
    warnings.push(`Could not fetch merge-group compare data from GitHub API (${result.status}): ${result.error || "unknown error"}`);
    warnings.push("Using merge-group payload and marking evidence incomplete.");
    return {
      ...fallback,
      evidenceTruncated: {
        files: true,
        commits: true,
        maxPages: 0,
      },
      warnings,
    };
  }

  const data = result.data || {};
  const files = Array.isArray(data.files) ? data.files : [];
  const commits = Array.isArray(data.commits) ? data.commits : [];
  const filesIncomplete = files.length === 0 || files.length >= 300;
  const commitsIncomplete =
    commits.length === 0 ||
    (Number.isFinite(Number(data.total_commits)) && Number(data.total_commits) > commits.length);

  if (filesIncomplete) {
    warnings.push("Merge-group file evidence is empty or may be capped by GitHub compare API; marking file evidence incomplete.");
  }
  if (commitsIncomplete) {
    warnings.push("Merge-group commit evidence is empty or incomplete; marking commit evidence incomplete.");
  }

  return {
    files,
    commits,
    evidenceTruncated: {
      files: filesIncomplete,
      commits: commitsIncomplete,
      maxPages: 0,
    },
    warnings,
  };
}

async function getPushData(event, request = githubRequest, lookupOptions = {}) {
  const repository = process.env.GITHUB_REPOSITORY || "";
  const [owner, repo] = repository.split("/");
  const before = String(event.before || "");
  const after = String(event.after || process.env.GITHUB_SHA || "");
  const ref = String(event.ref || process.env.GITHUB_REF || "");
  const branch = branchFromGitRef(ref);
  const warnings = [];
  const canCompare =
    Boolean(owner && repo) &&
    isSha(before) &&
    isSha(after) &&
    !isZeroSha(before) &&
    !isZeroSha(after);

  const comparePath = `/repos/${owner}/${repo}/compare/${encodeURIComponent(before)}...${encodeURIComponent(after)}`;
  const [lookup, compareResult] = await Promise.all([
    classifyPushAction(
      {
        owner,
        repo,
        before,
        after,
        branch,
        ref,
        forced: event.forced === true,
        created: event.created === true,
        deleted: event.deleted === true,
      },
      request,
      lookupOptions,
    ),
    // Deferred so a request that throws (a refused API URL, say) rejects
    // inside Promise.all instead of leaving the lookup promise unhandled.
    canCompare ? Promise.resolve().then(() => request(comparePath)) : Promise.resolve(null),
  ]);
  warnings.push(...lookup.warnings);

  const compare = summarizeCompare(compareResult);
  const classification = await reconcileMergedPullRequest(
    { owner, repo, after, lookup, compare },
    request,
  );
  warnings.push(...classification.warnings);

  if (!canCompare || !compareResult.ok) {
    const fallback = pushPayloadEvidence(event);
    if (!canCompare) {
      warnings.push(
        "Could not resolve a complete push compare range; using push event payload and marking evidence incomplete.",
      );
    } else {
      warnings.push(`Could not fetch push compare data from GitHub API (${compareResult.status}): ${compareResult.error || "unknown error"}`);
      warnings.push("Using push event payload and marking evidence incomplete.");
    }
    return {
      ...fallback,
      repositoryAction: classification.action,
      pushClassification: classification.evidence,
      evidenceTruncated: {
        files: true,
        commits: true,
        maxPages: 0,
      },
      warnings,
    };
  }

  if (compare.filesIncomplete) {
    warnings.push("Push file evidence is empty or may be capped by GitHub compare API; marking file evidence incomplete.");
  }
  if (compare.commitsIncomplete) {
    warnings.push("Push commit evidence is empty or incomplete; marking commit evidence incomplete.");
  }

  return {
    files: compare.files,
    commits: compare.commits,
    repositoryAction: classification.action,
    pushClassification: classification.evidence,
    evidenceTruncated: {
      files: compare.filesIncomplete,
      commits: compare.commitsIncomplete,
      maxPages: 0,
    },
    warnings,
  };
}

/**
 * The parts of a compare response the push path cares about. `ok` is false
 * when the compare was skipped or failed; `commitsTruncated` when GitHub
 * capped the commit list (the compare API returns at most 250 commits).
 */
function summarizeCompare(result) {
  if (!result || !result.ok) {
    return { ok: false, files: [], commits: [], totalCommits: 0, commitsTruncated: true, filesIncomplete: true, commitsIncomplete: true };
  }
  const data = result.data || {};
  const files = Array.isArray(data.files) ? data.files : [];
  const commits = Array.isArray(data.commits) ? data.commits : [];
  const totalCommits = Number.isFinite(Number(data.total_commits))
    ? Number(data.total_commits)
    : commits.length;
  const commitsTruncated = totalCommits > commits.length;
  return {
    ok: true,
    files,
    commits,
    totalCommits,
    commitsTruncated,
    filesIncomplete: files.length === 0 || files.length >= 300,
    commitsIncomplete: commits.length === 0 || commitsTruncated,
  };
}

const PUSH_LOOKUP_ATTEMPTS = 3;
const PUSH_LOOKUP_DELAY_MS = 10000;

// Pages of GET /commits/{sha}/pulls to read before giving up. A commit can be
// associated with more than one pull request, and the merge commit this guard
// is looking for is not guaranteed to be on the first page: the API orders the
// list by pull request number, so a long-lived branch reopened many times can
// push the merge that actually targets this branch off any single page. At 100
// per page, 5 pages is 500 associations, plus one sentinel request to prove
// whether a sixth page exists. That is far past anything a real merge commit
// carries and still bounds the request count.
const PUSH_LOOKUP_MAX_PAGES = 5;

function defaultSleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function hasGitHubRateLimitEvidence(result = {}) {
  const headers = result.headers || {};
  const remaining = String(headers["x-ratelimit-remaining"] ?? "").trim();
  if (remaining === "0") return true;
  if (headers["retry-after"] !== undefined) return true;
  return /rate limit|secondary rate limit|abuse detection/i.test(String(result.error || ""));
}

function isRetryableLookupFailure(result = {}) {
  const code = Number(result.status);
  return (
    code === 0 ||
    code === 429 ||
    (code === 403 && hasGitHubRateLimitEvidence(result)) ||
    (code >= 500 && code <= 599)
  );
}

function pushEvidence(classification, extra = {}) {
  return {
    action: "repo.push",
    evidence: {
      push_classification: classification,
      push_forced: false,
      ...extra,
    },
    warnings: [],
  };
}

function findMergedPullRequestForPush(data, branch, after) {
  if (!Array.isArray(data)) return null;
  return data.find((pullRequest) => (
    Number.isFinite(Number(pullRequest?.number)) &&
    pullRequest?.state === "closed" &&
    typeof pullRequest?.merged_at === "string" &&
    pullRequest.merged_at.length > 0 &&
    pullRequest?.base?.ref === branch &&
    pullRequest?.merge_commit_sha === after
  )) || null;
}

function mergedPullRequestPushResult(mergedPullRequest, after, branch) {
  return {
    action: "pr.merge",
    evidence: {
      push_classification: "merged_pull_request",
      push_forced: false,
      pull_request_number: Number(mergedPullRequest.number),
      pull_request_merged: true,
      merge_commit_sha: after,
      merge_base_branch: branch,
    },
    pullRequest: mergedPullRequest,
    warnings: [],
  };
}

/**
 * Classify a push as `not_push`, `forced`, `created`, `merged_pull_request`,
 * `direct`, or `unknown`.
 *
 * `not_push` comes first and covers a ref that is not a branch: a tag push, a
 * `refs/pull/...` ref, anything under `refs/` that is not `refs/heads/`.
 * Branch protection has no opinion on those, which is the treatment
 * fatalRequiresProtectedPush already gives them, so they are reported the same
 * way an event that is not a push is.
 *
 * `forced` and `created` come straight from the push payload and never consult
 * the API. A force push that happens to land on an old merge commit still
 * rewrote the branch, and a push that creates the branch (`before` is the zero
 * SHA, which is also what a re-push of a deleted branch looks like) has no
 * pull request to be the merge of. A branch deletion (`after` is the zero SHA)
 * is not looked up either.
 *
 * The other three come from GET /repos/{owner}/{repo}/commits/{sha}/pulls,
 * read in full at 100 per page up to PUSH_LOOKUP_MAX_PAGES, then probed
 * once more to distinguish exactly-full from truncated lists. A single page
 * is not enough: a commit can carry more associations than one page holds,
 * and the merge that targets this branch is not guaranteed to be among the
 * first of them, so a one-page lookup can miss a legitimate merge and report
 * `direct`. If the sentinel shows the list is longer than the page budget the
 * result is `unknown` with `associated_pr_list_truncated`, never `direct`. A
 * list we did not finish reading is not evidence that no merge exists.
 *
 * That lookup is retried, ten seconds apart by default, only on network
 * errors, 429, 403 responses that carry GitHub rate-limit evidence, and 5xx,
 * because the commit/pulls index can lag a merge by a few seconds. A 401,
 * ordinary permission-denied 403, 404, 422, or an unparseable body is final and yields
 * `unknown` with `associated_pr_lookup_failed`. An empty result is retried
 * only when `retryOnNoMatch` is set, which callers turn on for a push to the
 * default branch so a legitimate merge is not called direct because the index
 * was slow. A confirmed empty result is a real answer: a later error does not
 * turn it into `unknown`. Callers that enforce treat `unknown` as direct.
 *
 * A `merged_pull_request` result here is a candidate. It only says the pushed
 * tip is the merge commit of a merged pull request into this branch; see
 * reconcileMergedPullRequest for the check that the push contains nothing
 * beyond that merge.
 */
async function classifyPushAction(
  { owner, repo, before = "", after, branch, ref = "", forced = false, created = false, deleted = false },
  request = githubRequest,
  {
    attempts = PUSH_LOOKUP_ATTEMPTS,
    delayMs = PUSH_LOOKUP_DELAY_MS,
    sleep = defaultSleep,
    retryOnNoMatch = false,
  } = {},
) {
  // A non-branch ref is settled before anything else, including `forced` and
  // `created`. A new tag push carries `created: true` and a zero `before` SHA
  // exactly like a new branch, so a `created` check placed first classifies
  // `refs/tags/v1` as `created` with reason `branch_created`, and an updated
  // tag falls through to `direct` because `branch` is empty. Neither is a
  // branch event and neither is what fatalRequiresProtectedPush already does
  // with a non-branch ref, which is exempt it. `not_push` says that.
  if (isNonBranchRef(ref)) {
    return pushEvidence("not_push", { push_classification_reason: "non_branch_ref" });
  }
  if (forced === true) {
    return pushEvidence("forced", { push_forced: true });
  }
  if (created === true || isZeroSha(before)) {
    return pushEvidence("created", { push_classification_reason: "branch_created" });
  }
  if (deleted === true || isZeroSha(after)) {
    return pushEvidence("direct", { push_classification_reason: "branch_deleted" });
  }
  if (!owner || !repo || !isSha(after) || !branch) {
    return pushEvidence("direct");
  }

  const pullsPath = `/repos/${owner}/${repo}/commits/${encodeURIComponent(after)}/pulls?per_page=100`;
  const maxAttempts = Math.max(1, Math.floor(Number(attempts)) || 1);
  let lastFailure = null;
  let failures = 0;
  let confirmedEmpty = false;
  let truncated = false;

  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    const result = await githubRequestAllPages(pullsPath, request, PUSH_LOOKUP_MAX_PAGES);
    const invalidBody = result.ok && !Array.isArray(result.data);
    const mergedPullRequest = findMergedPullRequestForPush(result.data, branch, after);
    if (mergedPullRequest) {
      return mergedPullRequestPushResult(mergedPullRequest, after, branch);
    }

    if (!result.ok || invalidBody) {
      failures += 1;
      lastFailure = invalidBody
        ? { status: result.status, error: "GitHub API returned a non-array response" }
        : result;
      if (!isRetryableLookupFailure(result) || invalidBody) break;
      if (attempt < maxAttempts) await sleep(delayMs);
      continue;
    }

    // A capped list is not evidence of anything. The merge that targets this
    // branch may be on a page that was never read, so "no match in what we
    // read" cannot become `direct` here; it fails closed to `unknown`, which
    // enforcing callers treat as direct but which the evidence names as a
    // lookup that did not complete.
    truncated = Boolean(result.truncated);

    confirmedEmpty = !truncated;
    if (!retryOnNoMatch) break;
    if (attempt < maxAttempts) await sleep(delayMs);
  }

  if (truncated) {
    return {
      ...pushEvidence("unknown", {
        push_classification_reason: "associated_pr_list_truncated",
      }),
      warnings: [
        `Commit ${after} has more than ${PUSH_LOOKUP_MAX_PAGES * 100} associated pull requests, so the merge commit for ${branch} could not be ruled in or out; treating push as unresolved.`,
      ],
    };
  }

  if (confirmedEmpty || !lastFailure) {
    return pushEvidence("direct");
  }

  return {
    ...pushEvidence("unknown", { push_classification_reason: "associated_pr_lookup_failed" }),
    warnings: [
      `Could not resolve pushed commit PR association from GitHub API after ${failures} failed attempt${failures === 1 ? "" : "s"} (${lastFailure.status}): ${lastFailure.error || "unknown error"}; treating push as direct.`,
    ],
  };
}

/**
 * Confirm that a push whose tip is a merged pull request's merge commit
 * contains nothing but that merge.
 *
 * GitHub marks a pull request merged as soon as its head becomes reachable
 * from the base branch, so `git push origin feature:main`, or a local merge
 * pushed together with an extra commit, both produce a "merged" pull request
 * whose merge_commit_sha is the pushed tip. The compare range from `before`
 * to `after` shows what really landed:
 *
 * - The tip may not be the pull request head itself. A merge, squash, or
 *   rebase performed by GitHub always creates a new commit.
 * - When the pull request head is among the pushed commits (a merge commit
 *   merge), the tip must be a merge commit with the head as a parent and every
 *   other pushed commit must be a pull request commit.
 * - The push may never carry more commits than the pull request plus one.
 *
 * Squash and rebase merges land only new commits GitHub created, so nothing
 * in the push matches the pull request; the count rule still bounds them.
 *
 * Anything that cannot be verified (compare failed, was capped, or came back
 * with no commit list at all, pull request commits or files could not be fetched)
 * is `unknown`, which enforcing callers treat as direct.
 */
function patchDeltaSignature(patch, status = "") {
  if (typeof patch !== "string" || patch.trim().length === 0) return null;
  const changed = [];
  let hasHunk = false;

  for (const line of patch.split(/\r?\n/)) {
    if (line.startsWith("@@")) {
      hasHunk = true;
      continue;
    }
    if (line.startsWith("\\ No newline at end of file")) continue;
    if (!hasHunk && (line.startsWith("+++") || line.startsWith("---"))) {
      continue;
    }
    if (line.startsWith("+") || line.startsWith("-")) {
      changed.push(line);
    }
  }

  const statusAllowsNoContext = status === "added" || status === "removed";
  return hasHunk && (changed.length > 0 || statusAllowsNoContext)
    ? changed.join("\n")
    : null;
}

function patchLocationSignature(patch, status = "") {
  if (typeof patch !== "string" || patch.trim().length === 0) return null;
  const normalized = [];
  let hasHunk = false;
  let hasChangedLine = false;
  let hasContextLine = false;

  for (const line of patch.split(/\r?\n/)) {
    if (line.startsWith("@@")) {
      hasHunk = true;
      normalized.push("@@");
      continue;
    }
    if (line.startsWith("\\ No newline at end of file")) continue;
    if (!hasHunk && (line.startsWith("+++") || line.startsWith("---"))) {
      continue;
    }
    if (line.startsWith("+") || line.startsWith("-")) hasChangedLine = true;
    if (line.startsWith(" ")) hasContextLine = true;
    normalized.push(line);
  }

  const statusAllowsNoContext = status === "added" || status === "removed";
  return hasHunk && hasChangedLine && (hasContextLine || statusAllowsNoContext)
    ? normalized.join("\n")
    : null;
}

function normalizeChangedFile(file) {
  const numberOrNull = (value) => {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : null;
  };
  const status = String(file?.status || "");
  const sha = String(file?.sha || "").toLowerCase();
  return {
    sha: isSha(sha) ? sha : "",
    filename: String(file?.filename || ""),
    previous_filename: String(file?.previous_filename || ""),
    status,
    additions: numberOrNull(file?.additions),
    deletions: numberOrNull(file?.deletions),
    changes: numberOrNull(file?.changes),
    patch_delta_signature: patchDeltaSignature(file?.patch, status),
    patch_location_signature: patchLocationSignature(file?.patch, status),
  };
}

function comparableChangedFile(file, evidenceKind) {
  const baseEvidence = {
    filename: file.filename,
    previous_filename: file.previous_filename,
    status: file.status,
    additions: file.additions,
    deletions: file.deletions,
    changes: file.changes,
  };
  if (evidenceKind === "patch_delta") {
    return { ...baseEvidence, patch_delta_signature: file.patch_delta_signature };
  }
  if (evidenceKind === "patch_location") {
    return {
      ...baseEvidence,
      patch_delta_signature: file.patch_delta_signature,
      patch_location_signature: file.patch_location_signature,
    };
  }
  return { ...baseEvidence, sha: file.sha };
}

function changedFileKey(file) {
  const normalized = normalizeChangedFile(file);
  return normalized.previous_filename + "\0" + normalized.filename;
}

function comparePullRequestFileEvidence(pushFiles, pullRequestFiles) {
  if (!Array.isArray(pushFiles) || pushFiles.length === 0) {
    return { ok: false, reason: "push_files_unavailable" };
  }
  if (!Array.isArray(pullRequestFiles) || pullRequestFiles.length === 0) {
    return { ok: false, reason: "pull_request_files_unavailable" };
  }

  const pushByPath = new Map(
    pushFiles.map((file) => [changedFileKey(file), normalizeChangedFile(file)]),
  );
  const prByPath = new Map(
    pullRequestFiles.map((file) => [
      changedFileKey(file),
      normalizeChangedFile(file),
    ]),
  );
  if (pushByPath.size !== prByPath.size) {
    return { ok: false, reason: "pull_request_file_evidence_mismatch" };
  }

  for (const [key, pushedFile] of pushByPath.entries()) {
    const prFile = prByPath.get(key);
    if (!prFile) {
      return { ok: false, reason: "pull_request_file_evidence_mismatch" };
    }
    const hasPatchDeltaEvidence =
      pushedFile.patch_delta_signature !== null &&
      prFile.patch_delta_signature !== null;
    const hasBlobShaEvidence = Boolean(pushedFile.sha && prFile.sha);
    if (!hasPatchDeltaEvidence && !hasBlobShaEvidence) {
      return { ok: false, reason: "pull_request_file_patch_unavailable" };
    }
    if (hasPatchDeltaEvidence) {
      if (
        JSON.stringify(comparableChangedFile(pushedFile, "patch_delta")) !==
        JSON.stringify(comparableChangedFile(prFile, "patch_delta"))
      ) {
        return { ok: false, reason: "pull_request_file_evidence_mismatch" };
      }
      if (
        !pushedFile.patch_location_signature ||
        !prFile.patch_location_signature
      ) {
        return { ok: false, reason: "pull_request_file_location_ambiguous" };
      }
      if (
        JSON.stringify(comparableChangedFile(pushedFile, "patch_location")) !==
        JSON.stringify(comparableChangedFile(prFile, "patch_location"))
      ) {
        return { ok: false, reason: "pull_request_file_location_ambiguous" };
      }
      if (hasBlobShaEvidence && pushedFile.sha !== prFile.sha) {
        // PR-file and compare-file patches are relative to different bases.
        // Matching coordinates cannot safely override blob drift.
        return { ok: false, reason: "pull_request_file_location_ambiguous" };
      }
      continue;
    }
    if (
      JSON.stringify(comparableChangedFile(pushedFile, "sha")) !==
      JSON.stringify(comparableChangedFile(prFile, "sha"))
    ) {
      return { ok: false, reason: "pull_request_file_evidence_mismatch" };
    }
  }

  return { ok: true };
}

async function reconcileMergedPullRequest(
  { owner, repo, after, lookup, compare },
  request = githubRequest,
) {
  if (lookup.evidence.push_classification !== "merged_pull_request") {
    return { ...lookup, warnings: [] };
  }
  const { pullRequest } = lookup;
  const number = Number(pullRequest?.number);
  const direct = (reason, warning) => ({
    ...pushEvidence("direct", {
      push_classification_reason: reason,
      pull_request_number: number,
    }),
    warnings: warning ? [warning] : [],
  });
  const unknown = (reason, warning) => ({
    ...pushEvidence("unknown", {
      push_classification_reason: reason,
      pull_request_number: number,
    }),
    warnings: warning ? [warning] : [],
  });

  const headSha = String(pullRequest?.head?.sha || "").toLowerCase();
  const tip = after.toLowerCase();
  if (headSha && tip === headSha) {
    return direct(
      "pull_request_head_pushed_directly",
      `The pushed tip is the head of pull request #${number} itself, not a merge commit GitHub created; the branch was pushed directly.`,
    );
  }

  if (!compare.ok) {
    return unknown(
      "push_compare_unavailable",
      `The push compare range could not be read, so the merge of pull request #${number} could not be checked against the pushed commits; treating push as direct.`,
    );
  }

  // A 200 compare that carries no commit list is not evidence of a clean
  // merge, it is the absence of evidence. `commits.length === 0` reaches here
  // when GitHub omits the field, returns a non-array, or returns `[]`, and
  // none of the checks below can run without commits: the count rule compares
  // against `total_commits`, which is 0 in the same response, and the parent
  // rule has nothing to walk. Classifying `merged_pull_request` on that would
  // let a locally pushed merge carrying extra commits through
  // protect-default-branch with no commit evidence at all, so it is `unknown`
  // for the same reason a failed or truncated compare is.
  if (compare.commits.length === 0) {
    return unknown(
      "push_commits_unavailable",
      `The push compare returned no commits, so the merge of pull request #${number} could not be checked against the pushed commits; treating push as direct.`,
    );
  }

  const prCommitsResult = await githubRequestAllPages(
    `/repos/${owner}/${repo}/pulls/${number}/commits?per_page=100`,
    request,
  );
  if (!prCommitsResult.ok || prCommitsResult.truncated) {
    return unknown(
      "pull_request_commits_unavailable",
      `Could not fetch the commits of pull request #${number} from GitHub API (${prCommitsResult.truncated ? "truncated" : prCommitsResult.status}): ${prCommitsResult.error || "unknown error"}; treating push as direct.`,
    );
  }

  const prShas = new Set(
    prCommitsResult.data
      .map((commit) => String(commit?.sha || "").toLowerCase())
      .filter(Boolean),
  );
  const pushed = compare.commits.map((commit) => ({
    sha: String(commit?.sha || "").toLowerCase(),
    parents: Array.isArray(commit?.parents)
      ? commit.parents.map((parent) => String(parent?.sha || "").toLowerCase())
      : [],
  }));

  if (compare.totalCommits > prShas.size + 1) {
    return direct(
      "commits_outside_pull_request",
      `The push to the default branch carries ${compare.totalCommits} commits but pull request #${number} has ${prShas.size}; the push contains commits that are not part of the merged pull request.`,
    );
  }
  if (compare.commitsTruncated) {
    return unknown(
      "push_commits_truncated",
      `GitHub returned ${pushed.length} of ${compare.totalCommits} pushed commits, so the merge of pull request #${number} could not be fully checked; treating push as direct.`,
    );
  }

  const headPushed = Boolean(headSha) && pushed.some((commit) => commit.sha === headSha);
  if (headPushed) {
    const tipCommit = pushed.find((commit) => commit.sha === tip);
    if (!tipCommit || tipCommit.parents.length < 2 || !tipCommit.parents.includes(headSha)) {
      return direct(
        "pull_request_head_pushed_directly",
        `The pushed tip ${after.slice(0, 12)} is not a merge commit of pull request #${number}'s head; the branch was pushed directly.`,
      );
    }
    const outside = pushed.filter((commit) => commit.sha !== tip && !prShas.has(commit.sha));
    if (outside.length > 0) {
      return direct(
        "commits_outside_pull_request",
        `The push contains ${outside.length} commit${outside.length === 1 ? "" : "s"} that ${outside.length === 1 ? "is" : "are"} not part of pull request #${number} (${outside.map((commit) => commit.sha.slice(0, 12)).join(", ")}).`,
      );
    }
  }

  if (compare.filesIncomplete) {
    return unknown(
      "push_files_unavailable",
      `The push compare returned no file evidence or capped file evidence, so the merge of pull request #${number} could not be checked against the pushed files; treating push as direct.`,
    );
  }

  const prFilesResult = await githubRequestAllPages(
    `/repos/${owner}/${repo}/pulls/${number}/files?per_page=100`,
    request,
  );
  if (!prFilesResult.ok || prFilesResult.truncated) {
    return unknown(
      "pull_request_files_unavailable",
      `Could not fetch the files of pull request #${number} from GitHub API (${prFilesResult.truncated ? "truncated" : prFilesResult.status}): ${prFilesResult.error || "unknown error"}; treating push as direct.`,
    );
  }

  const fileEvidence = comparePullRequestFileEvidence(
    compare.files,
    prFilesResult.data,
  );
  if (!fileEvidence.ok) {
    if (
      fileEvidence.reason === "push_files_unavailable" ||
      fileEvidence.reason === "pull_request_files_unavailable" ||
      fileEvidence.reason === "pull_request_file_patch_unavailable" ||
      fileEvidence.reason === "pull_request_file_location_ambiguous"
    ) {
      return unknown(
        fileEvidence.reason,
        `The file evidence for pull request #${number} was empty, missing patch hunks, or ambiguous about the changed location, so it could not be checked against the pushed files; treating push as direct.`,
      );
    }
    return direct(
      fileEvidence.reason,
      `The files that landed in the push do not match the file evidence for pull request #${number}; treating the push as direct.`,
    );
  }

  const { pullRequest: _omit, ...confirmed } = lookup;
  return { ...confirmed, warnings: [] };
}

async function getRepositoryDefaultBranch(request = githubRequest) {
  const repository = process.env.GITHUB_REPOSITORY || "";
  const [owner, repo] = repository.split("/");
  if (!owner || !repo) {
    return { defaultBranch: "", error: "GITHUB_REPOSITORY is not set" };
  }
  const result = await request(`/repos/${owner}/${repo}`);
  if (!result.ok) {
    return { defaultBranch: "", error: `${result.status}: ${result.error || "unknown error"}` };
  }
  const defaultBranch = String(result.data?.default_branch || "").trim();
  if (!defaultBranch) {
    return { defaultBranch: "", error: "repository response has no default_branch" };
  }
  return { defaultBranch, error: "" };
}

function mergeGroupPayloadEvidence(event) {
  const mergeGroup = event.merge_group || {};
  const headCommit = mergeGroup.head_commit;
  return {
    files: [],
    commits: headCommit ? [headCommit] : [],
  };
}

function pushPayloadEvidence(event) {
  const commits = Array.isArray(event.commits) ? event.commits : [];
  const filesByName = new Map();

  for (const commit of commits) {
    for (const filename of [
      ...(Array.isArray(commit.added) ? commit.added : []),
      ...(Array.isArray(commit.modified) ? commit.modified : []),
      ...(Array.isArray(commit.removed) ? commit.removed : []),
    ]) {
      if (!filesByName.has(filename)) {
        filesByName.set(filename, {
          filename,
          additions: 0,
          deletions: 0,
        });
      }
    }
  }

  return {
    files: Array.from(filesByName.values()),
    commits,
  };
}

function isSha(value) {
  return /^[a-f0-9]{40}$/i.test(value);
}

async function githubRequestAllPages(path, request = githubRequest, maxPages = 20) {
  const data = [];
  let lastResult = null;
  const pagePath = (page) => {
    const separator = path.includes("?") ? "&" : "?";
    return path + separator + "page=" + page;
  };

  for (let page = 1; page <= maxPages; page += 1) {
    const result = await request(pagePath(page));
    lastResult = result;
    if (!result.ok) {
      return {
        ...result,
        data,
        maxPages,
      };
    }
    if (!Array.isArray(result.data)) {
      return {
        ok: false,
        status: result.status,
        data,
        error: "GitHub API returned a non-array response",
        maxPages,
      };
    }
    data.push(...result.data);
    if (result.data.length < 100) {
      return { ok: true, status: result.status, data, maxPages };
    }
  }

  const sentinel = await request(pagePath(maxPages + 1));
  if (!sentinel.ok) {
    return {
      ...sentinel,
      data,
      maxPages,
    };
  }
  if (!Array.isArray(sentinel.data)) {
    return {
      ok: false,
      status: sentinel.status,
      data,
      error: "GitHub API returned a non-array response",
      maxPages,
    };
  }

  return {
    ok: true,
    status: sentinel.status || lastResult?.status || 200,
    data,
    truncated: sentinel.data.length > 0,
    maxPages,
  };
}

function buildGitHubApiUrl(path, apiUrl = "https://api.github.com") {
  const base = apiUrl.endsWith("/") ? apiUrl : `${apiUrl}/`;
  const relativePath = String(path || "").replace(/^\/+/, "");
  return new URL(relativePath, base);
}

module.exports = {
  assertSafeGitHubApiUrl,
  buildGitHubApiUrl,
  decodeGitHubContent,
  getRepositoryDefaultBranch,
  isSha,
  isZeroSha,
  reconcileMergedPullRequest,
  readEventPayload,
  getPullRequestData,
  readBasePolicy,
  readBaseFile,
  githubRequestAllPages,
  getMergeGroupData,
  getPushData,
  classifyPushAction,
};

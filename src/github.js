const fs = require("fs");
const https = require("https");

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

  return new Promise((resolve) => {
    const req = https.request(url, {
      headers: {
        "Accept": "application/vnd.github+json",
        "User-Agent": "APort-Policy-Verify-Action/1.0",
        ...(token ? { "Authorization": `Bearer ${token}` } : {}),
        ...(repo ? { "X-GitHub-Api-Version": "2022-11-28" } : {}),
      },
    }, (res) => {
      let body = "";
      res.setEncoding("utf8");
      res.on("data", (chunk) => {
        body += chunk;
      });
      res.on("end", () => {
        if (res.statusCode < 200 || res.statusCode >= 300) {
          resolve({ ok: false, status: res.statusCode, data: [], error: body.slice(0, 500) });
          return;
        }
        try {
          resolve({ ok: true, status: res.statusCode, data: JSON.parse(body) });
        } catch (error) {
          resolve({ ok: false, status: res.statusCode, data: [], error: error.message });
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

async function getPullRequestData(event, request = githubRequest) {
  const repository = process.env.GITHUB_REPOSITORY || "";
  const pr = event.pull_request || (event.number && event.head && event.base ? event : null);
  if (!pr?.number && isMergeGroupEvent(event)) {
    return getMergeGroupData(event, request);
  }
  if (!pr?.number && (process.env.GITHUB_EVENT_NAME === "push" || event.before || event.after)) {
    return getPushData(event, request);
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

async function getPushData(event, request = githubRequest) {
  const repository = process.env.GITHUB_REPOSITORY || "";
  const [owner, repo] = repository.split("/");
  const before = String(event.before || "");
  const after = String(event.after || process.env.GITHUB_SHA || "");
  const branch = branchFromGitRef(event.ref || process.env.GITHUB_REF || "");
  const warnings = [];
  const classification = await classifyPushAction(
    { owner, repo, after, branch },
    request,
  );
  warnings.push(...classification.warnings);

  if (!owner || !repo || !isSha(before) || !isSha(after) || isZeroSha(before)) {
    const fallback = pushPayloadEvidence(event);
    warnings.push(
      "Could not resolve a complete push compare range; using push event payload and marking evidence incomplete.",
    );
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

  const comparePath = `/repos/${owner}/${repo}/compare/${encodeURIComponent(before)}...${encodeURIComponent(after)}`;
  const result = await request(comparePath);
  if (!result.ok) {
    const fallback = pushPayloadEvidence(event);
    warnings.push(`Could not fetch push compare data from GitHub API (${result.status}): ${result.error || "unknown error"}`);
    warnings.push("Using push event payload and marking evidence incomplete.");
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

  const data = result.data || {};
  const files = Array.isArray(data.files) ? data.files : [];
  const commits = Array.isArray(data.commits) ? data.commits : [];
  const filesIncomplete = files.length === 0 || files.length >= 300;
  const commitsIncomplete =
    commits.length === 0 ||
    (Number.isFinite(Number(data.total_commits)) && Number(data.total_commits) > commits.length);

  if (filesIncomplete) {
    warnings.push("Push file evidence is empty or may be capped by GitHub compare API; marking file evidence incomplete.");
  }
  if (commitsIncomplete) {
    warnings.push("Push commit evidence is empty or incomplete; marking commit evidence incomplete.");
  }

  return {
    files,
    commits,
    repositoryAction: classification.action,
    pushClassification: classification.evidence,
    evidenceTruncated: {
      files: filesIncomplete,
      commits: commitsIncomplete,
      maxPages: 0,
    },
    warnings,
  };
}

async function classifyPushAction({ owner, repo, after, branch }, request = githubRequest) {
  const directPush = {
    action: "repo.push",
    evidence: {
      push_classification: "direct",
    },
    warnings: [],
  };

  if (!owner || !repo || !isSha(after) || !branch) {
    return directPush;
  }

  const pullsPath = `/repos/${owner}/${repo}/commits/${encodeURIComponent(after)}/pulls?per_page=10`;
  const result = await request(pullsPath);
  if (!result.ok) {
    return {
      action: "repo.push",
      evidence: {
        push_classification: "unknown",
        push_classification_reason: "associated_pr_lookup_failed",
      },
      warnings: [
        `Could not resolve pushed commit PR association from GitHub API (${result.status}): ${result.error || "unknown error"}; treating push as direct.`,
      ],
    };
  }

  const pulls = Array.isArray(result.data) ? result.data : [];
  const mergedPullRequest = pulls.find((pullRequest) => (
    Number.isFinite(Number(pullRequest?.number)) &&
    pullRequest?.state === "closed" &&
    typeof pullRequest?.merged_at === "string" &&
    pullRequest.merged_at.length > 0 &&
    pullRequest?.base?.ref === branch &&
    pullRequest?.merge_commit_sha === after
  ));

  if (!mergedPullRequest) {
    return directPush;
  }

  return {
    action: "pr.merge",
    evidence: {
      push_classification: "merged_pull_request",
      pull_request_number: Number(mergedPullRequest.number),
      pull_request_merged: true,
      merge_commit_sha: after,
      merge_base_branch: branch,
    },
    warnings: [],
  };
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

function isZeroSha(value) {
  return /^0{40}$/.test(value);
}

function branchFromGitRef(ref) {
  const value = String(ref || "");
  if (value.startsWith("refs/heads/")) return value.slice("refs/heads/".length);
  return value;
}

async function githubRequestAllPages(path, request = githubRequest, maxPages = 20) {
  const data = [];
  for (let page = 1; page <= maxPages; page += 1) {
    const separator = path.includes("?") ? "&" : "?";
    const result = await request(`${path}${separator}page=${page}`);
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

  return {
    ok: true,
    status: 200,
    data,
    truncated: true,
    maxPages,
  };
}

function buildGitHubApiUrl(path, apiUrl = "https://api.github.com") {
  const base = apiUrl.endsWith("/") ? apiUrl : `${apiUrl}/`;
  const relativePath = String(path || "").replace(/^\/+/, "");
  return new URL(relativePath, base);
}

module.exports = {
  buildGitHubApiUrl,
  decodeGitHubContent,
  readEventPayload,
  getPullRequestData,
  readBasePolicy,
  readBaseFile,
  githubRequestAllPages,
  getMergeGroupData,
  getPushData,
  classifyPushAction,
};

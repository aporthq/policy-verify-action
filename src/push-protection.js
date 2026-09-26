/**
 * Default-branch push protection.
 *
 * The guard classifies every push (see classifyPushAction in github.js) but in
 * report-only mode that classification is evidence, not a verdict. An external
 * audit pointed out that a downstream tool therefore cannot rely on the check
 * to go red on a direct or forced push to the default branch. The
 * `protect-default-branch` input closes that: when it is on and a `push` lands
 * on the repository default branch, a forced push or a push whose tip is not
 * the merge commit of a merged pull request fails the step.
 *
 * Everything here is deliberately narrow. It never touches pull request
 * events, never touches pushes to other branches, and it is the only path that
 * turns a push into a failure in `auto` mode.
 */

const { branchFromGitRef } = require("./git-ref");

const PUSH_CLASSIFICATIONS = [
  "direct",
  "merged_pull_request",
  "forced",
  "created",
  "unknown",
  // A push event whose ref is not a branch (a tag, `refs/pull/...`). The
  // classifier emits it so a tag push is not reported as `created` or
  // `direct`; see classifyPushAction in github.js.
  "not_push",
];

function defaultBranchFromEvent(event = {}) {
  return String(event?.repository?.default_branch || "").trim();
}

/**
 * The branch a push event landed on. Only a `refs/heads/` ref counts; a tag
 * push has no branch. GITHUB_REF_NAME is the last resort and only when the
 * runner says the ref is a branch.
 */
function pushedBranch(event = {}, env = process.env) {
  const fromRef = branchFromGitRef(event?.ref) || branchFromGitRef(env.GITHUB_REF);
  if (fromRef) return fromRef;
  return env.GITHUB_REF_TYPE === "branch" ? String(env.GITHUB_REF_NAME || "") : "";
}

/**
 * Where the default branch name comes from, in order: the push payload's
 * `repository.default_branch`, the `default-branch` input, then
 * GET /repos/{owner}/{repo}. The lookup only runs for a branch push and only
 * when the first two are empty. When all three come up empty the result is an
 * empty string; evaluateDefaultBranchProtection fails closed on that.
 */
async function resolveDefaultBranch({
  event = {},
  eventName = "",
  env = process.env,
  input = "",
  lookup = null,
} = {}) {
  const fromEvent = defaultBranchFromEvent(event);
  if (fromEvent) return { defaultBranch: fromEvent, source: "payload", warnings: [] };

  const fromInput = String(input || "").trim();
  if (fromInput) return { defaultBranch: fromInput, source: "input", warnings: [] };

  if (eventName !== "push" || !pushedBranch(event, env) || typeof lookup !== "function") {
    return { defaultBranch: "", source: "", warnings: [] };
  }

  const result = await lookup();
  if (result?.defaultBranch) {
    return { defaultBranch: String(result.defaultBranch), source: "api", warnings: [] };
  }
  return {
    defaultBranch: "",
    source: "",
    warnings: [
      `The push payload does not name the repository default branch and it could not be read from the GitHub API (${result?.error || "unknown error"}). Set the default-branch input to name it.`,
    ],
  };
}

function isDefaultBranchPush({
  event = {},
  eventName = "",
  env = process.env,
  defaultBranch = defaultBranchFromEvent(event),
} = {}) {
  if (eventName !== "push") return false;
  const name = String(defaultBranch || "").trim();
  if (!name) return false;
  return pushedBranch(event, env) === name;
}

/**
 * The `push-classification` step output.
 *
 * `not_push` for anything that is not a push event, and for a push event on a
 * ref that is not a branch, which the classifier reports as `not_push` for the
 * same reason. Otherwise the classifier's verdict. A push event with no
 * classification at all should not happen, but if it does the honest answer is
 * `unknown`, not `direct`.
 */
function resolvePushClassificationOutput({ eventName = "", pushClassification } = {}) {
  if (eventName !== "push") return "not_push";
  const value = String(pushClassification?.push_classification || "");
  return PUSH_CLASSIFICATIONS.includes(value) ? value : "unknown";
}

function shortSha(value) {
  return String(value || "").slice(0, 12);
}

function evaluateDefaultBranchProtection({
  enabled = false,
  eventName = "",
  event = {},
  pushClassification,
  env = process.env,
  defaultBranch = defaultBranchFromEvent(event),
} = {}) {
  const classification = resolvePushClassificationOutput({
    eventName,
    pushClassification,
  });
  const resolvedDefaultBranch = String(defaultBranch || "").trim();
  const branch = pushedBranch(event, env);
  const applies = isDefaultBranchPush({
    event,
    eventName,
    env,
    defaultBranch: resolvedDefaultBranch,
  });
  const result = {
    enabled: Boolean(enabled),
    applies,
    classification,
    defaultBranch: resolvedDefaultBranch,
    branch,
    findings: [],
    warnings: [],
    blocked: false,
    reason: "",
  };
  const sha = String(event.after || env.GITHUB_SHA || "");

  if (classification === "created") {
    return result;
  }

  // Protection on, a branch push, and no way to tell whether it is the default
  // branch: fail closed, the same way an unresolved pull request lookup does.
  if (enabled && eventName === "push" && branch && !resolvedDefaultBranch) {
    result.reason = "default_branch_unknown";
    result.findings.push({
      code: "OAP.REPO.DIRECT_PUSH_DEFAULT_BRANCH",
      severity: "high",
      message: `protect-default-branch is enabled but the repository default branch could not be determined from the push payload, the default-branch input, or the GitHub API, so the push to ${branch} (${shortSha(sha)}) is treated as a direct push to the default branch.`,
      details: {
        branch,
        sha,
        push_classification: classification,
        push_classification_reason: "default_branch_unknown",
        protect_default_branch: true,
      },
    });
    result.blocked = true;
    return result;
  }

  if (!applies) return result;

  const details = {
    branch: resolvedDefaultBranch,
    sha,
    push_classification: classification,
    protect_default_branch: Boolean(enabled),
  };

  if (classification === "forced") {
    result.reason = "forced";
    result.findings.push({
      code: "OAP.REPO.FORCE_PUSH",
      // Reported as a warning when protection is off so report-only runs still
      // show it; only the input escalates it to a blocking finding.
      severity: enabled ? "high" : "warning",
      message: `Force push to the default branch ${resolvedDefaultBranch} (${shortSha(sha)}) rewrote branch history.`,
      details,
    });
  } else if (
    enabled &&
    classification !== "merged_pull_request" &&
    classification !== "created"
  ) {
    const lookupFailed = classification === "unknown";
    result.reason = lookupFailed ? "lookup_failed" : "direct";
    result.findings.push({
      code: "OAP.REPO.DIRECT_PUSH_DEFAULT_BRANCH",
      severity: "high",
      message: lookupFailed
        ? `The pull request association for ${shortSha(sha)} on the default branch ${resolvedDefaultBranch} could not be resolved from the GitHub API, so the push is treated as direct.`
        : `Direct push to the default branch ${resolvedDefaultBranch} (${shortSha(sha)}) is not the merge commit of a merged pull request. Open a pull request instead.`,
      details: {
        ...details,
        ...(pushClassification?.push_classification_reason
          ? {
              push_classification_reason: String(
                pushClassification.push_classification_reason,
              ),
            }
          : {}),
      },
    });
  }

  result.blocked =
    Boolean(enabled) &&
    result.findings.some((finding) =>
      ["high", "error"].includes(String(finding.severity || "").toLowerCase()),
    );

  return result;
}

/**
 * One sentence explaining why the step failed, for the summary and the
 * workflow annotation. Empty when the protection did not block.
 */
function describeBlockReason(protection) {
  if (!protection?.blocked) return "";
  const branch = protection.defaultBranch || "the default branch";
  if (protection.reason === "forced") {
    return `protect-default-branch is enabled and the push to ${branch} was forced.`;
  }
  if (protection.reason === "lookup_failed") {
    return `protect-default-branch is enabled and the pull request association for the push to ${branch} could not be resolved, so it was treated as a direct push.`;
  }
  if (protection.reason === "default_branch_unknown") {
    return `protect-default-branch is enabled and the repository default branch could not be determined, so the push to ${protection.branch || "the branch"} was treated as a direct push to the default branch.`;
  }
  return `protect-default-branch is enabled and the push to ${branch} is not the merge commit of a merged pull request.`;
}

/**
 * The "Default branch protection" line shared by the run log and the job
 * summary: "disabled" when the input is off; when it is on, whether the push
 * landed on the default branch.
 */
function describeProtectionState(pushProtection = {}) {
  if (!pushProtection?.enabled) return "disabled";
  if (pushProtection.classification === "created") {
    return "enabled (branch created)";
  }
  if (pushProtection.reason === "default_branch_unknown") {
    return "enabled (default branch unresolved; fail closed)";
  }
  return pushProtection.applies ? "enabled" : "enabled (not the default branch)";
}

module.exports = {
  PUSH_CLASSIFICATIONS,
  defaultBranchFromEvent,
  describeBlockReason,
  describeProtectionState,
  evaluateDefaultBranchProtection,
  isDefaultBranchPush,
  pushedBranch,
  resolveDefaultBranch,
  resolvePushClassificationOutput,
};

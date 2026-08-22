const { collectChangedFileEvidence } = require("./path-evidence");

function buildVerifyContext({
  event,
  files,
  attribution,
  structuralFindings = [],
  repositoryPolicy,
  evidenceTruncated = {},
}) {
  const pr = event.pull_request || (event.number && event.head && event.base ? event : {});
  const mergeGroup = event.merge_group || {};
  const action = normalizeEventAction(event);
  const eventName = process.env.GITHUB_EVENT_NAME || "";
  const eventAction = String(event.action || "");
  const repository = process.env.GITHUB_REPOSITORY || "";
  const isMergeGroup = eventName === "merge_group" || Boolean(event.merge_group);
  const sha = process.env.GITHUB_SHA || mergeGroup.head_sha || pr.head?.sha || "";
  const headSha = pr.head?.sha || "";
  const fileEvidence = collectChangedFileEvidence(files);
  const effectiveStructuralFindings = fileEvidence.capped
    ? [
        ...structuralFindings,
        {
          code: "OAP.REPO.FILE_EVIDENCE_CAPPED",
          severity: "high",
          message:
            "GitHub PR file path evidence exceeded the hosted verifier request budget, so repository path analysis is incomplete.",
          details: {
            total_paths: fileEvidence.total,
            included_paths: fileEvidence.paths.length,
            omitted_paths: fileEvidence.omitted,
            max_evidence_bytes: fileEvidence.maxBytes,
            max_evidence_count: fileEvidence.maxCount,
          },
        },
      ]
    : structuralFindings;
  const filesChanged = fileEvidence.paths;
  const linesAdded = files.reduce((sum, file) => sum + Number(file.additions || 0), 0);
  const linesRemoved = files.reduce((sum, file) => sum + Number(file.deletions || 0), 0);

  return {
    agent_id: process.env.APORT_AGENT_ID || undefined,
    idempotency_key: makeIdempotencyKey({
      repository,
      action,
      prNumber: pr.number,
      sha,
      runId: process.env.GITHUB_RUN_ID || "",
    }),
    authorization: {
      provider: "github_actions_oidc",
      require_oidc: true,
      action,
    },
    evidence: {
      source: "github_action_runner",
      evidence_format: "aport.github.pr.v1",
      event_name: eventName,
      event_action: eventAction,
      pull_request_number: pr.number || undefined,
      pull_request_merged: Boolean(pr.merged),
      files_analyzed: !Boolean(evidenceTruncated.files),
      commits_analyzed: !Boolean(evidenceTruncated.commits),
      files_changed: filesChanged,
      lines_added: linesAdded,
      lines_removed: linesRemoved,
      actor_class: attribution.class,
      confidence: attribution.confidence,
      structural_findings: effectiveStructuralFindings,
      ...(headSha ? { pull_request_head_sha: headSha } : {}),
      ...(isMergeGroup && mergeGroup.head_sha ? { merge_group_head_sha: mergeGroup.head_sha } : {}),
      ...(isMergeGroup && mergeGroup.base_sha ? { merge_group_base_sha: mergeGroup.base_sha } : {}),
      ...(isMergeGroup && mergeGroup.head_ref ? { merge_group_head_ref: mergeGroup.head_ref } : {}),
      ...(isMergeGroup && mergeGroup.base_ref ? { merge_group_base_ref: mergeGroup.base_ref } : {}),
      ...(repositoryPolicy ? { repository_policy: repositoryPolicy } : {}),
    },
    repository,
    action,
    branch: pr.head?.ref || refNameFromGitRef(mergeGroup.head_ref) || process.env.GITHUB_HEAD_REF || process.env.GITHUB_REF_NAME || "",
    base_branch: pr.base?.ref || refNameFromGitRef(mergeGroup.base_ref) || process.env.GITHUB_BASE_REF || undefined,
    head_branch: pr.head?.ref || refNameFromGitRef(mergeGroup.head_ref) || process.env.GITHUB_HEAD_REF || undefined,
    sha,
    ...(headSha ? { head_sha: headSha } : {}),
    files_changed: filesChanged,
    lines_added: linesAdded,
    lines_removed: linesRemoved,
    github_actor: process.env.GITHUB_ACTOR || event.sender?.login || "",
  };
}

function normalizeEventAction(event) {
  const eventName = process.env.GITHUB_EVENT_NAME || "";
  const eventAction = event.action || "";

  if (eventName === "push") return "repo.push";
  if (eventName === "merge_group") return "pr.update";
  if (eventAction === "opened") return "pr.create";
  if (eventAction === "closed" && event.pull_request?.merged) return "pr.merge";
  return "pr.update";
}

function refNameFromGitRef(ref) {
  const value = String(ref || "");
  if (value.startsWith("refs/heads/")) return value.slice("refs/heads/".length);
  return value;
}

function makeIdempotencyKey({ repository, action, prNumber, sha, runId }) {
  return [
    "github",
    repository,
    prNumber || runId || "run",
    action,
    sha || "unknown",
  ]
    .join("-")
    .replace(/[^a-zA-Z0-9._-]+/g, "-")
    .slice(0, 200);
}

module.exports = { buildVerifyContext, normalizeEventAction, makeIdempotencyKey };

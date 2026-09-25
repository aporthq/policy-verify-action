const { describeBlockReason, describeProtectionState } = require("./push-protection");

function row(label, value) {
  return `| ${escapeTableCell(label)} | ${escapeTableCell(value || "-")} |`;
}

function signalRows(signals) {
  if (!signals?.length) return "_No attribution signals checked._";
  return [
    "| Signal | Result | Detail |",
    "|---|---:|---|",
    ...signals.map(
      (signal) =>
        `| ${inlineCode(signal.name)} | ${signal.hit ? "hit" : "miss"} | ${escapeTableCell(signal.detail || "")} |`,
    ),
  ].join("\n");
}

function findingsList(findings) {
  if (!findings.length) {
    return "- No protected-path or workflow privilege findings in this report-only slice.";
  }
  return findings
    .map((finding) => {
      const paths = finding.paths?.length
        ? ` (${finding.paths.map((path) => inlineCode(path)).join(", ")})`
        : "";
      const severity = escapeMarkdownText(
        String(finding.severity || "").toUpperCase(),
      );
      return `- **${severity}** ${inlineCode(finding.code)}: ${escapeMarkdownText(finding.message)}${paths}`;
    })
    .join("\n");
}

function hasHighStructuralFinding(findings = []) {
  return findings.some((finding) =>
    ["high", "error"].includes(String(finding?.severity || "").toLowerCase()),
  );
}

function summaryStatus({
  hostedEnforcement,
  willFail,
  verification,
  structuralFindings = [],
  pushProtection = null,
}) {
  if (willFail && pushProtection?.blocked) {
    return {
      label: "Blocked",
      tone: `APort stopped this workflow: ${describeBlockReason(pushProtection)}`,
    };
  }

  if (willFail) {
    return {
      label: "Blocked",
      tone: "APort stopped this workflow because hosted enforcement returned a deny, hosted verification failed, or a high/error repository finding was present.",
    };
  }

  if (hasHighStructuralFinding(structuralFindings)) {
    return {
      label: "Needs review",
      tone: hostedEnforcement
        ? "High-severity evidence was present, but this run was not marked as blocking by the configured enforcement mode."
        : "High-severity evidence was detected in report-only mode. Enable hosted enforcement after reviewing expected false-deny behavior.",
    };
  }

  if (verification?.decision?.allow === false) {
    return {
      label: "Needs review",
      tone: hostedEnforcement
        ? "APort returned a deny decision. Review the policy reasons before rerunning this workflow."
        : "APort returned a deny decision in non-blocking mode. Review the policy reasons before treating this run as safe.",
    };
  }

  if (verification?.decision?.allow === true) {
    return {
      label: "Verified",
      tone: "APort returned an allow decision and no blocking repository findings were detected.",
    };
  }

  if (hostedEnforcement) {
    return {
      label: "Enforced",
      tone: "Hosted enforcement is enabled. APort will fail this workflow on deny decisions, failed hosted verification, or high/error repository findings.",
    };
  }

  return {
    label: "Report ready",
    tone: "APort generated repository provenance and structural evidence without blocking this workflow.",
  };
}

function safeGitHubRepository(value) {
  const repository = String(value || "").trim();
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository)) return "";
  return repository;
}

function workflowFileFromRef(workflowRef) {
  const ref = String(workflowRef || "");
  const marker = "/.github/workflows/";
  const start = ref.indexOf(marker);
  if (start === -1) return "";

  const afterMarker = ref.slice(start + marker.length);
  const refMarker = afterMarker.indexOf("@refs/");
  const workflowFile = (
    refMarker === -1 ? afterMarker : afterMarker.slice(0, refMarker)
  ).trim();
  if (
    !workflowFile ||
    workflowFile.includes("/") ||
    workflowFile.includes("\\") ||
    /[\u0000-\u001F\u007F-\u009F]/.test(workflowFile)
  ) {
    return "";
  }
  return workflowFile;
}

function buildWorkflowBadgeMarkdown({ repository, workflowRef }) {
  const safeRepository = safeGitHubRepository(repository);
  if (!safeRepository) return "";

  const workflowFile = workflowFileFromRef(workflowRef) || "aport-guard.yml";
  const [owner, repo] = safeRepository.split("/");
  const encodedRepository = `${encodeURIComponent(owner)}/${encodeURIComponent(repo)}`;
  const encodedWorkflow = encodeURIComponent(workflowFile);
  return `[![APort Repository Guard](https://github.com/${encodedRepository}/actions/workflows/${encodedWorkflow}/badge.svg)](https://github.com/${encodedRepository}/actions/workflows/${encodedWorkflow})`;
}

function inlineCode(value) {
  const text = escapeInlineCode(value);
  const maxBacktickRun = Math.max(
    0,
    ...(text.match(/`+/g) || []).map((match) => match.length),
  );
  const fence = "`".repeat(maxBacktickRun + 1);
  const padded = text.startsWith("`") || text.endsWith("`")
    ? ` ${text} `
    : text;
  return `${fence}${padded}${fence}`;
}

function escapeInlineCode(value) {
  return String(value ?? "-").replace(/\r?\n/g, " ");
}

function escapeTableCell(value) {
  return escapeMarkdownText(value).replace(/\|/g, "\\|");
}

function escapeMarkdownText(value) {
  return String(value ?? "-")
    .replace(/\r?\n/g, " ")
    .replace(/`/g, "\\`")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\[/g, "\\[")
    .replace(/\]/g, "\\]");
}

/**
 * The application origin that goes with a configured API url.
 *
 * The claim link was hard-coded to aport.io. When `api-url` points at staging
 * or a self-hosted deployment, the passport is issued THERE — so that link sent
 * maintainers to production, where the agent id does not exist and the claim
 * returns not_found. The app and the API share a host in the default
 * deployment (aport.io/api/… and aport.io/claim) and `api.` is stripped for the
 * split-host form, so the origin follows the configuration rather than a
 * constant.
 */
function appBaseFromApiUrl(apiUrl) {
  try {
    const url = new URL(apiUrl);
    // `host`, not `hostname`. hostname drops the port, so a self-hosted
    // `api-url` of http://gh.internal:8787 produced http://gh.internal and sent
    // maintainers to whatever answers on port 80 — which for a self-hosted
    // deployment is usually nothing.
    const host = url.host.replace(/^api\./, "");
    // A deployment served under a path prefix keeps it. `api-url` names the
    // API, so a trailing /api or /api/v1 belongs to the API rather than to the
    // application and comes off; anything before it is the application's base.
    const path = url.pathname.replace(/\/+$/, "").replace(/\/api(\/v\d+)?$/, "");
    return `${url.protocol}//${host}${path}`;
  } catch {
    return "https://aport.io";
  }
}

/**
 * The passport call to action.
 *
 * A hosted-mode run issues a passport for this repository from its OIDC token,
 * and it starts unclaimed because we cannot know who to email. Claiming it is
 * how the repository's maintainers reach their own audit logs, so the link
 * belongs where they already are: in the comment the run just posted.
 *
 * DELIBERATELY NEUTRAL ABOUT WHETHER IT IS CLAIMED. Hosted issuance reuses the
 * same passport on every run, and this summary has no claim-state signal to
 * read — the verification result carries a decision, not a passport. Asserting
 * "this passport is unclaimed" on every run would keep saying it long after
 * someone claimed it, and send their colleagues through OAuth to be told
 * `already_claimed`. So the copy works either way: the link is worth following
 * whether you are claiming it or opening the one you already own.
 */
function buildClaimMarkdown({ agentId, oidcRepositoryPassport, apiUrl }) {
  // Gated on whether THIS run actually issued or refreshed a repository
  // passport from the OIDC token, not on hosted enforcement.
  //
  // Those are not the same: a run configured with a managed agent-id and API
  // key is hosted, skips OIDC issuance, and its passport is not a repository
  // guard at all. Offering a repository claim link there sends someone through
  // OAuth to be told not_a_repository_passport.
  if (!agentId || !oidcRepositoryPassport) return "";
  const claimUrl = `${appBaseFromApiUrl(apiUrl)}/claim?agent_id=${encodeURIComponent(agentId)}`;
  return `## This Repository's Passport

${inlineCode(agentId)} guards this repository. Open it to see this repository's decision history and audit trail — and to claim it, if nobody has yet.

[Open ${inlineCode(agentId)}](${claimUrl}) — claiming signs you in with GitHub and checks that your account has **admin** or **maintain** on this repository.

`;
}

function renderSummary({
  repository,
  prNumber,
  actor,
  attribution,
  structuralFindings,
  repositoryPolicy,
  verification,
  configuredMode,
  eventName,
  workflowRef,
  warnings,
  willFail,
  apiUrl,
  pushProtection = null,
}) {
  const decision = verification?.decision;
  const provenance = verification?.provenance || "unattributed";
  const outcome =
    decision?.outcome || (decision ? (decision.allow ? "allow" : "deny") : "");
  const decisionLine = decision?.decision_id
    ? `\`${decision.decision_id}\``
    : verification?.mode === "evidence-only" ||
        verification?.mode === "auto-fallback"
      ? "not created"
      : "-";
  const policySource = repositoryPolicy?.source || "built-in default";
  const enforcementMode = String(
    configuredMode ||
      verification?.configuredMode ||
      verification?.mode ||
      "auto",
  )
    .trim()
    .toLowerCase();
  const hostedEnforcement =
    enforcementMode === "hosted" || verification?.requiresHosted === true;
  const status = summaryStatus({
    hostedEnforcement,
    willFail,
    verification,
    structuralFindings,
    pushProtection,
  });
  const badgeMarkdown = buildWorkflowBadgeMarkdown({
    repository,
    workflowRef,
  });
  const protectionEnabled = Boolean(pushProtection?.enabled);
  const isPushEvent = eventName === "push";
  const meaning = hostedEnforcement
    ? `Hosted enforcement is enabled. A deny decision or high/error structural finding fails this workflow.${protectionEnabled ? " `protect-default-branch` is also enabled, so a forced or direct push to the default branch fails it." : ""}`
    : protectionEnabled
      ? "This check is report-only for pull requests. `protect-default-branch` is enabled, so a forced push or a direct push to the default branch fails this workflow."
      : "This check is report-only and always exits 0 unless you explicitly enable hosted enforcement.";
  const pushRows = isPushEvent
    ? [
        row("Push classification", pushProtection?.classification || ""),
        row("Default branch protection", describeProtectionState(pushProtection)),
      ]
    : [];

  return `<img src="https://aport.io/porter-repository-guard.svg" alt="Porter, the APort Repository Guard mascot" width="72" align="right" />

# APort Repository Guard

**${escapeMarkdownText(status.label)}.** ${escapeMarkdownText(status.tone)}

${hostedEnforcement ? "Hosted enforcement" : "Report-only agent attribution"} and repository provenance summary.

${[
  "| Field | Value |",
  "|---|---|",
  row("Repository", repository),
  row("Pull request", prNumber ? `#${prNumber}` : ""),
  row("Event", eventName || ""),
  ...pushRows,
  row("Actor", actor),
  row("Actor class", attribution.class),
  row("Confidence", attribution.confidence),
  row("Provenance", provenance),
  row("Mode", configuredMode || verification?.mode || "auto"),
  row("Verification", verification?.mode || "auto"),
  row("Policy", "code.repository.merge.v1"),
  row("Outcome", outcome || "-"),
  row("Decision", decisionLine),
  row("Policy source", policySource),
].join("\n")}

## What This Means

${meaning}

Hosted mode uses GitHub OIDC to create or reuse an OAP passport for this repository, then records a \`ci_time\` policy decision through APort Verify. To upgrade \`ci_time\` to \`pre_action\`, install APort agent guardrails for the coding agent so tool calls create signed decisions before files, shell commands, or GitHub actions happen.

${badgeMarkdown ? `## Shareable Badge\n\nAdd this to your README after enabling the workflow as a required check:\n\n\`\`\`md\n${badgeMarkdown}\n\`\`\`\n` : ""}

## Attribution Signals

${signalRows(attribution.signals)}

## Structural Findings

${findingsList(structuralFindings)}

${warnings?.length ? `## Warnings\n\n${warnings.map((warning) => `- ${escapeMarkdownText(warning)}`).join("\n")}\n` : ""}
${buildClaimMarkdown({ agentId: decision?.agent_id, oidcRepositoryPassport: verification?.oidcRepositoryPassport, apiUrl })}
## Next Move

- Make this a required check in GitHub branch protection or rulesets for merge-time enforcement.
- Install APort agent guardrails for Claude Code, Cursor, OpenClaw, LangChain, CrewAI, DeerFlow, or n8n to add pre-action decisions before code reaches GitHub.
- Learn more at https://aport.io/github and https://aport.io/quickstart/#github.
`;
}

module.exports = {
  buildWorkflowBadgeMarkdown,
  escapeInlineCode,
  escapeMarkdownText,
  escapeTableCell,
  workflowFileFromRef,
  inlineCode,
  renderSummary,
};

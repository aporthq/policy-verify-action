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
}) {
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
  const hostedEnforcement = enforcementMode === "hosted";
  const status = summaryStatus({
    hostedEnforcement,
    willFail,
    verification,
    structuralFindings,
  });
  const badgeMarkdown = buildWorkflowBadgeMarkdown({
    repository,
    workflowRef,
  });
  const meaning = hostedEnforcement
    ? "Hosted enforcement is enabled. A deny decision or high/error structural finding fails this workflow."
    : "This check is report-only and always exits 0 unless you explicitly enable hosted enforcement.";

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

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
  warnings,
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
  const meaning = hostedEnforcement
    ? "Hosted enforcement is enabled. A deny decision or high/error structural finding fails this workflow."
    : "This check is report-only and always exits 0 unless you explicitly enable hosted enforcement.";

  return `# APort / OAP code.repository.merge.v1

${hostedEnforcement ? "Hosted enforcement" : "Report-only agent attribution"} and repository provenance summary.

${[
  "| Field | Value |",
  "|---|---|",
  row("Repository", repository),
  row("Pull request", prNumber ? `#${prNumber}` : ""),
  row("Actor", actor),
  row("Actor class", attribution.class),
  row("Confidence", attribution.confidence),
  row("Provenance", provenance),
  row("Mode", configuredMode || verification?.mode || "auto"),
  row("Verification", verification?.mode || "auto"),
  row("Outcome", outcome || "-"),
  row("Decision", decisionLine),
  row("Policy source", policySource),
].join("\n")}

## What This Means

${meaning}

Hosted mode uses GitHub OIDC to create or reuse an OAP passport for this repository/workflow, then records a \`ci_time\` policy decision through APort Verify. To upgrade \`ci_time\` to \`pre_action\`, install APort agent guardrails for the coding agent so tool calls create signed decisions before files, shell commands, or GitHub actions happen.

## Attribution Signals

${signalRows(attribution.signals)}

## Structural Findings

${findingsList(structuralFindings)}

${warnings?.length ? `## Warnings\n\n${warnings.map((warning) => `- ${escapeMarkdownText(warning)}`).join("\n")}\n` : ""}
`;
}

module.exports = {
  escapeInlineCode,
  escapeMarkdownText,
  escapeTableCell,
  inlineCode,
  renderSummary,
};

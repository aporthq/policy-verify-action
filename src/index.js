const fs = require("fs");
const { classify } = require("./attribution");
const { normalizeMode, runAportVerification } = require("./aport");
const { buildVerifyContext } = require("./context");
const {
  getPullRequestData,
  readBaseFile,
  readBasePolicy,
  readEventPayload,
} = require("./github");
const {
  buildPolicyEvidence,
  parseRepositoryPolicy,
  repositoryPolicyFindings,
  resolveProtectedPaths,
} = require("./policy");
const { emitRunLog } = require("./logging");
const { renderSummary } = require("./summary");
const { detectStructuralFindings } = require("./structural");

function parseList(value) {
  return String(value || "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function writeOutput(name, value) {
  const outputPath = process.env.GITHUB_OUTPUT;
  if (!outputPath) return;
  fs.appendFileSync(outputPath, `${name}=${value}\n`);
}

function writeSummary(summary) {
  const summaryPath = process.env.GITHUB_STEP_SUMMARY;
  if (summaryPath) {
    fs.appendFileSync(summaryPath, `${summary}\n`);
    return;
  }
  process.stdout.write(`${summary}\n`);
}

async function main() {
  const event = readEventPayload();
  const pr =
    event.pull_request || (event.number && event.head && event.base ? event : {});
  const configuredMode = process.env.APORT_MODE || "auto";
  const warnings = [];
  if (event.__error) warnings.push(event.__error);

  const {
    files,
    commits,
    evidenceTruncated,
    warnings: dataWarnings,
  } = await getPullRequestData(event);
  warnings.push(...dataWarnings);

  const { policy: basePolicy, warnings: policyWarnings } =
    await readBasePolicy(event);
  warnings.push(...policyWarnings);
  const parsedPolicy = basePolicy?.text
    ? parseRepositoryPolicy(basePolicy.text)
    : null;
  const repositoryPolicy = buildPolicyEvidence(basePolicy);
  const attributionInput = buildAttributionInput({
    event,
    pr,
    commits,
  });

  const attribution = classify({
    ...attributionInput,
    commits,
    workflowRef: process.env.GITHUB_WORKFLOW_REF || "",
  });

  const protectedPaths = resolveProtectedPaths({
    inputPaths: parseList(process.env.APORT_PROTECTED_PATHS),
    policy: parsedPolicy,
  });
  const policyBranch = resolvePolicyBranch(event, pr);
  const structuralFindings = [
    ...detectStructuralFindings({
      files,
      evidenceTruncated,
      ...(protectedPaths?.length ? { protectedPaths } : {}),
      requirePinnedActions: Boolean(
        parsedPolicy?.github?.require_pinned_actions,
      ),
    }),
    ...repositoryPolicyFindings({
      policy: parsedPolicy,
      baseBranch: policyBranch,
    }),
    ...basePolicyReadFindings(basePolicy, policyWarnings),
  ];
  const verifyContext = buildVerifyContext({
    event,
    files,
    attribution,
    structuralFindings,
    repositoryPolicy,
    evidenceTruncated,
  });
  const readTrustedPassport = async (passportPath) => {
    const result = await readBaseFile(event, passportPath);
    warnings.push(...result.warnings);
    if (!result.file) {
      throw new Error(
        `Trusted passport ${passportPath} was not found in the trusted workflow ref.`,
      );
    }
    return result.file.text;
  };
  const verification = await runAportVerification({
    mode: configuredMode,
    apiUrl: process.env.APORT_API_URL || "https://api.aport.io",
    oidcAudience: process.env.APORT_OIDC_AUDIENCE || "aport.io",
    passportPath: process.env.APORT_PASSPORT_PATH || ".aport/passport.json",
    fallbackMode: process.env.APORT_FALLBACK_MODE || "evidence-only",
    verifyContext,
    readTrustedPassport,
  });
  if (verification.warning) warnings.push(verification.warning);

  const willFail = shouldFailWorkflow(
    configuredMode,
    verification,
    structuralFindings,
  );
  const summary = renderSummary({
    repository: process.env.GITHUB_REPOSITORY || "",
    prNumber: pr.number || "",
    actor: attributionInput.actor,
    attribution,
    structuralFindings,
    repositoryPolicy,
    verification,
    configuredMode,
    eventName: process.env.GITHUB_EVENT_NAME || "",
    workflowRef: process.env.GITHUB_WORKFLOW_REF || "",
    warnings,
    willFail,
  });

  writeSummary(summary);
  writeOutput("actor-class", attribution.class);
  writeOutput("confidence", attribution.confidence);
  writeOutput("provenance", verification.provenance || "unattributed");
  writeOutput("decision-id", verification.decision?.decision_id || "");
  writeOutput("outcome", verification.decision?.outcome || "");
  writeOutput("structural-findings", JSON.stringify(structuralFindings));

  emitRunLog({
    repository: process.env.GITHUB_REPOSITORY || "",
    prNumber: pr.number || "",
    configuredMode,
    verification,
    structuralFindings,
    warnings,
    willFail,
  });

  if (willFail) {
    process.exitCode = 1;
  }
}

function shouldFailWorkflow(mode, verification, structuralFindings = []) {
  return (
    normalizeMode(mode) === "hosted" &&
    (!verification?.success ||
      verification?.decision?.allow === false ||
      hasBlockingStructuralFindings(structuralFindings))
  );
}

function buildAttributionInput({ event = {}, pr = {}, commits = [] } = {}) {
  return {
    actor: pr.user?.login || process.env.GITHUB_ACTOR || event.sender?.login || "",
    actorType: pr.user?.type || event.sender?.type || "",
    appSlug: event.installation?.app_slug || event.app?.slug || "",
    headRef: pr.head?.ref || process.env.GITHUB_HEAD_REF || "",
    commits,
  };
}

function hasBlockingStructuralFindings(findings = []) {
  return findings.some((finding) =>
    ["high", "error"].includes(String(finding?.severity || "").toLowerCase()),
  );
}

function basePolicyReadFindings(basePolicy, warnings = []) {
  if (basePolicy) return [];

  const unavailable = warnings.find((warning) =>
    isBasePolicyReadFailure(warning),
  );
  if (!unavailable) return [];

  return [
    {
      code: "OAP.REPO.BASE_POLICY_UNAVAILABLE",
      severity: "high",
      message:
        "Trusted base repository policy could not be read, so repository policy analysis is incomplete.",
      details: { warning: unavailable },
    },
  ];
}

function resolvePolicyBranch(event, pr = {}) {
  const prBase = pr.base?.ref || process.env.GITHUB_BASE_REF || "";
  if (prBase) return prBase;

  const eventName = process.env.GITHUB_EVENT_NAME || "";
  if (eventName !== "push") return "";

  return (
    branchFromGitRef(event.ref) ||
    branchFromGitRef(process.env.GITHUB_REF) ||
    (process.env.GITHUB_REF_TYPE === "branch"
      ? process.env.GITHUB_REF_NAME || ""
      : "")
  );
}

function branchFromGitRef(ref) {
  const value = String(ref || "");
  if (value.startsWith("refs/heads/")) return value.slice("refs/heads/".length);
  if (!value.startsWith("refs/")) return value;
  return "";
}

function isBasePolicyReadFailure(warning) {
  const value = String(warning || "");
  return (
    /^Could not read base file \.aport\/policy\.ya?ml from GitHub API \((?!404\b)/.test(
      value,
    ) ||
    /^Base file \.aport\/policy\.ya?ml was found but could not be decoded\./.test(
      value,
    )
  );
}

function handleFatalError(error) {
  const mode = normalizeMode(process.env.APORT_MODE || "auto");
  const hosted = mode === "hosted";
  writeSummary(`# APort / OAP code.repository.merge.v1

${hosted ? "Hosted verification could not complete." : "Report-only mode could not complete."}

- Error: ${error.message}
- Outcome: ${hosted ? "workflow failed because hosted mode was explicitly required." : "workflow remains allowed because this mode is report-only."}
`);
  if (hosted) {
    process.exitCode = 1;
  }
}

if (require.main === module) {
  main().catch(handleFatalError);
}

module.exports = {
  basePolicyReadFindings,
  buildAttributionInput,
  parseList,
  resolvePolicyBranch,
  shouldFailWorkflow,
};

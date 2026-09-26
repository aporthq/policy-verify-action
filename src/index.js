const fs = require("fs");
const { classify } = require("./attribution");
const { normalizeMode, runAportVerification } = require("./aport");
const { buildVerifyContext } = require("./context");
const {
  getPullRequestData,
  getRepositoryDefaultBranch,
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
const { branchFromGitRef, isNonBranchRef, isZeroSha } = require("./git-ref");
const { emitRunLog } = require("./logging");
const {
  defaultBranchFromEvent,
  evaluateDefaultBranchProtection,
  isDefaultBranchPush,
  pushedBranch,
  resolveDefaultBranch,
} = require("./push-protection");
const { renderSummary } = require("./summary");
const { detectStructuralFindings } = require("./structural");

function parseList(value) {
  return String(value || "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function parseBoolean(value) {
  return /^(1|true|yes|on)$/i.test(String(value || "").trim());
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

function addMask(value) {
  const secret = String(value || "");
  if (!secret) return;
  process.stdout.write(`::add-mask::${escapeWorkflowCommandValue(secret)}\n`);
}

function escapeWorkflowCommandValue(value) {
  return String(value)
    .replace(/%/g, "%25")
    .replace(/\r/g, "%0D")
    .replace(/\n/g, "%0A");
}

async function main() {
  const event = readEventPayload();
  const pr =
    event.pull_request || (event.number && event.head && event.base ? event : {});
  const configuredMode = process.env.APORT_MODE || "auto";
  const {
    agentId: configuredManagedAgentId,
    apiKey: configuredApiKey,
  } = readManagedCredentials(process.env);
  addMask(configuredApiKey);
  const warnings = [];
  if (event.__error) warnings.push(event.__error);
  const useManagedCredentials = shouldUseManagedCredentials({
    event,
    pr,
    repository: process.env.GITHUB_REPOSITORY || "",
    actor: process.env.GITHUB_ACTOR || "",
  });
  if (!useManagedCredentials && (configuredManagedAgentId || configuredApiKey)) {
    warnings.push(
      "Managed hosted credentials were ignored for a no-secret pull request; using the no-secret GitHub OIDC hosted path.",
    );
  }
  const managedAgentId = useManagedCredentials ? configuredManagedAgentId : "";
  const apiKey = useManagedCredentials ? configuredApiKey : "";
  const eventName = process.env.GITHUB_EVENT_NAME || "";
  const protectDefaultBranch = parseBoolean(
    process.env.APORT_PROTECT_DEFAULT_BRANCH,
  );
  const { defaultBranch, warnings: defaultBranchWarnings } =
    await resolveDefaultBranch({
      event,
      eventName,
      input: process.env.APORT_DEFAULT_BRANCH,
      lookup: getRepositoryDefaultBranch,
    });
  warnings.push(...defaultBranchWarnings);
  const defaultBranchPush = isDefaultBranchPush({
    event,
    eventName,
    defaultBranch,
  });

  const {
    files,
    commits,
    evidenceTruncated,
    repositoryAction,
    pushClassification,
    warnings: dataWarnings,
  } = await getPullRequestData(event, undefined, {
    pushLookup: {
      // Every push to the default branch waits out an empty pulls index,
      // whether or not the input is on, so the push-classification output
      // does not depend on the input and a lagging merge is not reported
      // as direct. The wait is bounded: three attempts, ten seconds apart.
      retryOnNoMatch: defaultBranchPush,
      ...pushLookupOverrides(process.env),
    },
  });
  warnings.push(...dataWarnings);

  const pushProtection = evaluateDefaultBranchProtection({
    enabled: protectDefaultBranch,
    eventName,
    event,
    pushClassification,
    defaultBranch,
  });
  warnings.push(...pushProtection.warnings);
  const verifyPushClassification =
    pushClassification && eventName === "push" && pushProtection.defaultBranch
      ? {
          ...pushClassification,
          push_to_default_branch: pushProtection.applies,
          default_branch: pushProtection.defaultBranch,
        }
      : pushClassification;

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
  const blockProtectedPaths = parseBoolean(
    process.env.APORT_BLOCK_PROTECTED_PATHS,
  );
  const policyBranch = resolvePolicyBranch(event, pr);
  const repositoryFindings = [
    ...detectStructuralFindings({
      files,
      evidenceTruncated,
      ...(protectedPaths?.length ? { protectedPaths } : {}),
      blockProtectedPaths,
      requirePinnedActions: Boolean(
        parsedPolicy?.github?.require_pinned_actions,
      ),
      // The first-install carve-out is for the installing pull request only.
      // A direct push to a protected branch must stay fail-closed.
      eventName: process.env.GITHUB_EVENT_NAME || "",
    }),
    ...repositoryPolicyFindings({
      policy: parsedPolicy,
      baseBranch: policyBranch,
    }),
    ...basePolicyReadFindings(basePolicy, policyWarnings),
  ];
  // The push protection findings stay Action-side (summary, annotations, exit
  // code). They are not sent as structural findings, so a commit index that
  // lags a legitimate merge cannot persist a hosted deny for it. The hosted
  // verifier still gets the push facts as plain evidence fields.
  const structuralFindings = [...repositoryFindings, ...pushProtection.findings];
  const verifyContext = buildVerifyContext({
    event,
    files,
    attribution,
    structuralFindings: hostedStructuralFindings(structuralFindings, pushProtection),
    repositoryPolicy,
    evidenceTruncated,
    repositoryAction,
    pushClassification: verifyPushClassification,
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
    agentId: managedAgentId,
    apiKey,
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
    pushProtection,
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
    eventName,
    workflowRef: process.env.GITHUB_WORKFLOW_REF || "",
    warnings,
    willFail,
    pushProtection,
    // So the claim link points at the deployment that issued the passport,
    // not at production regardless of configuration.
    apiUrl: process.env.APORT_API_URL || "https://api.aport.io",
  });

  writeSummary(summary);
  writeOutput("actor-class", attribution.class);
  writeOutput("confidence", attribution.confidence);
  writeOutput("provenance", verification.provenance || "unattributed");
  writeOutput("decision-id", verification.decision?.decision_id || "");
  writeOutput("outcome", verification.decision?.outcome || "");
  writeOutput("structural-findings", JSON.stringify(structuralFindings));
  writeOutput("push-classification", pushProtection.classification);

  emitRunLog({
    repository: process.env.GITHUB_REPOSITORY || "",
    prNumber: pr.number || "",
    configuredMode,
    verification,
    structuralFindings,
    warnings,
    willFail,
    pushProtection,
  });

  if (willFail) {
    process.exitCode = 1;
  }
}

/**
 * Hosted enforcement decides the outcome for every mode that requires it.
 * Default-branch protection is the one addition that can fail a report-only
 * run, and it only ever fires for a push to the default branch with
 * `protect-default-branch` on.
 */
function shouldFailWorkflow(
  mode,
  verification,
  structuralFindings = [],
  pushProtection = null,
) {
  if (pushProtection?.blocked === true) return true;
  const requiresHosted =
    normalizeMode(mode) === "hosted" || verification?.requiresHosted === true;
  return (
    requiresHosted &&
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

function shouldUseManagedCredentials({
  event = {},
  pr = {},
  repository = "",
  actor = process.env.GITHUB_ACTOR || "",
} = {}) {
  const headRepository =
    pr.head?.repo?.full_name || event.pull_request?.head?.repo?.full_name || "";
  const baseRepository = repository || event.repository?.full_name || "";
  if (isDependabotPullRequest({ event, pr, actor })) return false;
  // GitHub withholds secrets for every pull-request-derived event from an
  // external fork, including pull_request_review. Treat any event carrying a
  // PR head repository as a no-secret run when its repository differs.
  if (!headRepository || !baseRepository) return true;
  return headRepository === baseRepository;
}

/**
 * Test and self-host knob for the pull request lookup retry delay. The
 * production default (ten seconds between attempts) lives in github.js; this
 * only exists so an end-to-end run against a local API stand-in does not wait
 * twenty seconds per direct push.
 */
function pushLookupOverrides(env = process.env) {
  const raw = String(env.APORT_PUSH_LOOKUP_DELAY_MS ?? "").trim();
  if (!/^\d+$/.test(raw)) return {};
  return { delayMs: Number(raw) };
}

function readManagedCredentials(env = process.env) {
  return {
    agentId: env.APORT_INPUT_AGENT_ID || "",
    apiKey: env.APORT_INPUT_API_KEY || "",
  };
}

function isDependabotPullRequest({ event = {}, pr = {}, actor = "" } = {}) {
  if (!pr.number && !event.pull_request) return false;
  return [
    pr.user?.login,
    event.pull_request?.user?.login,
    event.sender?.login,
    actor || process.env.GITHUB_ACTOR,
  ].some((login) => String(login || "").toLowerCase() === "dependabot[bot]");
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

/**
 * The structural findings sent to the hosted verifier: everything except the
 * default-branch push findings, which are enforced Action-side only.
 */
function hostedStructuralFindings(structuralFindings = [], pushProtection = null) {
  const actionSide = new Set(pushProtection?.findings || []);
  return structuralFindings.filter((finding) => !actionSide.has(finding));
}

function handleFatalError(error) {
  const event = readEventPayload();
  const hosted = fatalRequiresHosted(process.env, event);
  const protectedPush = fatalRequiresProtectedPush(process.env, event);
  const failed = hosted || protectedPush;
  const outcome = hosted
    ? "workflow failed because hosted mode was explicitly required."
    : protectedPush
      ? "workflow failed because protect-default-branch is enabled and the push could not be classified."
      : "workflow remains allowed because this mode is report-only.";
  writeSummary(`# APort / OAP code.repository.merge.v1

${hosted ? "Hosted verification could not complete." : protectedPush ? "Default branch protection could not complete." : "Report-only mode could not complete."}

- Error: ${error.message}
- Outcome: ${outcome}
`);
  // A push that never got classified is reported as unknown, never as a
  // missing output a later step could mistake for a pass. Created branches and
  // non-branch refs can still be classified from the trusted event payload.
  writeOutput("push-classification", fatalPushClassification(process.env, event));
  if (failed) {
    process.stdout.write(
      `::error title=APort Repository Guard could not complete::${escapeWorkflowCommandValue(error.message)}\n`,
    );
    process.exitCode = 1;
  }
}

/**
 * With protect-default-branch on, a push to the default branch that dies
 * before API-backed classification must still fail closed unless the trusted
 * push payload is enough to classify it as exempt. Tag pushes are not branch
 * pushes, and a newly created branch is explicitly allowed by
 * evaluateDefaultBranchProtection; a forced push remains protected even if the
 * payload also carries a zero before SHA. When branch/default evidence is
 * missing, the push is treated as protected. The API lookup is not attempted
 * here; the run is already failing.
 */
function fatalPushClassification(env = process.env, event = {}) {
  if (env.GITHUB_EVENT_NAME !== "push") return "not_push";
  if (isNonBranchRef(String(event?.ref || env.GITHUB_REF || ""))) return "not_push";
  if (event?.forced !== true && (event?.created === true || isZeroSha(event?.before))) {
    return "created";
  }
  return "unknown";
}

function fatalRequiresProtectedPush(env = process.env, event = {}) {
  if (
    env.GITHUB_EVENT_NAME !== "push" ||
    !parseBoolean(env.APORT_PROTECT_DEFAULT_BRANCH)
  ) {
    return false;
  }
  const fatalClassification = fatalPushClassification(env, event);
  if (fatalClassification === "not_push" || fatalClassification === "created") {
    return false;
  }
  const branch = pushedBranch(event, env);
  const defaultBranch =
    defaultBranchFromEvent(event) || String(env.APORT_DEFAULT_BRANCH || "").trim();
  if (!branch || !defaultBranch) return true;
  return branch === defaultBranch;
}

function fatalRequiresHosted(env = process.env, event = {}) {
  const mode = normalizeMode(env.APORT_MODE || "auto");
  if (mode === "hosted") return true;
  if (mode !== "auto") return false;

  const { agentId, apiKey } = readManagedCredentials(env);
  if (!agentId && !apiKey) return false;

  const pr =
    event.pull_request || (event.number && event.head && event.base ? event : {});
  return shouldUseManagedCredentials({
    event,
    pr,
    repository: env.GITHUB_REPOSITORY || "",
    actor: env.GITHUB_ACTOR || "",
  });
}

if (require.main === module) {
  main().catch(handleFatalError);
}

module.exports = {
  basePolicyReadFindings,
  buildAttributionInput,
  fatalPushClassification,
  fatalRequiresHosted,
  fatalRequiresProtectedPush,
  handleFatalError,
  hostedStructuralFindings,
  parseBoolean,
  parseList,
  pushLookupOverrides,
  readManagedCredentials,
  resolvePolicyBranch,
  shouldFailWorkflow,
  shouldUseManagedCredentials,
};

const { matchesAny } = require("./glob");
const {
  filePathCandidates,
  primaryFilePath,
  uniquePaths,
} = require("./path-evidence");

const DEFAULT_PROTECTED_PATHS = [
  ".github/workflows/**",
  ".github/workflow-templates/**",
  ".github/workflows-templates/**",
  ".github/actions/**",
  "**/package.json",
  "**/pnpm-lock.yaml",
  "**/package-lock.json",
  "**/yarn.lock",
  "**/next.config.*",
  "**/tailwind.config.*",
  ".aport/policy.yaml",
  ".aport/policy.yml",
  "functions/api/verify/**",
  "functions/utils/policy/**",
  "policies/**",
];

// These paths can alter the guard's trust boundary or the policy it enforces.
// They remain fail-closed even where a repository opts to report other
// protected-path changes without blocking the workflow.
const DEFAULT_CONTROL_PLANE_PATHS = [
  ".github/workflows/**",
  ".github/workflow-templates/**",
  ".github/workflows-templates/**",
  ".github/actions/**",
  ".aport/policy.yaml",
  ".aport/policy.yml",
];

const DEFAULT_SUSPICIOUS_CONTENT_PATHS = [
  ".github/workflows/**",
  ".github/workflow-templates/**",
  ".github/workflows-templates/**",
  ".github/actions/**",
  "**/next.config.*",
  "**/tailwind.config.*",
  "**/postcss.config.*",
  "**/vite.config.*",
  "**/webpack.config.*",
  "**/rollup.config.*",
  "**/package.json",
  "**/pnpm-lock.yaml",
  "**/package-lock.json",
  "**/yarn.lock",
  "integrations/github/actions/**",
  "scripts/**",
  "functions/api/verify/**",
  "functions/utils/policy/**",
  "policies/**",
];
const DOCUMENTATION_EXTENSIONS = new Set([".md", ".mdx", ".txt"]);
const SUSPICIOUS_CONTENT_EVIDENCE_OPTIONAL_PATHS = [
  "**/pnpm-lock.yaml",
  "**/package-lock.json",
  "**/yarn.lock",
];

const WRITE_ALL_RE = /^\s*["']?permissions["']?\s*:\s*["']?write-all["']?\s*(?:#.*)?$/im;
const PERMISSIONS_BLOCK_RE = /^(\s*)["']?permissions["']?\s*:\s*$/i;
const REPOSITORY_WRITE_PERMISSION_SCOPE = String.raw`(?:actions|attestations|checks|contents|deployments|discussions|issues|models|packages|pages|pull-requests|repository-projects|security-events|statuses)`;
const WRITE_PERMISSION_ENTRY_RE = new RegExp(
  String.raw`^\s*["']?${REPOSITORY_WRITE_PERMISSION_SCOPE}["']?\s*:\s*["']?write["']?\s*$`,
  "i",
);
const OIDC_WRITE_PERMISSION_ENTRY_RE = new RegExp(
  String.raw`^\s*["']?id-token["']?\s*:\s*["']?write["']?\s*$`,
  "i",
);
const GITHUB_PERMISSION_SCOPE = String.raw`(?:${REPOSITORY_WRITE_PERMISSION_SCOPE}|id-token)`;
const PERMISSION_ENTRY_RE = new RegExp(
  String.raw`^\s*["']?${GITHUB_PERMISSION_SCOPE}["']?\s*:\s*["']?(?:read|write|none)["']?\s*$`,
  "i",
);
const PULL_REQUEST_TARGET_RE =
  /^\s*-\s*['"]?pull_request_target['"]?\s*$|^\s*['"]?pull_request_target['"]?\s*:|^\s*['"]?on['"]?\s*:\s*['"]?pull_request_target['"]?\s*(?:#.*)?$|^\s*['"]?on['"]?\s*:\s*\[[^\]]*\b['"]?pull_request_target['"]?\b[^\]]*\]|^\s*['"]?on['"]?\s*:\s*\{.*\b['"]?pull_request_target['"]?\b.*\}\s*$/im;
const USES_ACTION_RE = /^\s*(?:-\s*)?["']?uses["']?\s*:\s*['"]?([^'"\s#]+)['"]?(?:\s+#.*)?$/gim;
// The guard's own identity. Used only to recognise the pull request that
// installs this action, and matched against the repository slug so a fork or
// lookalike name (`evil/policy-verify-action`) does not qualify.
const APORT_ACTION_REPOSITORY = "aporthq/policy-verify-action";
const SHA_PIN_RE = /^[a-f0-9]{40}$/i;
const SUSPICIOUS_PATTERNS = [
  {
    code: "observed-global-o-marker",
    regex: /global\s*\.\s*o\s*=\s*['"]5-3-132-du['"]/i,
  },
  {
    code: "eval-base64-decoder",
    regex: /\beval\s*\([\s\S]{0,4096}\b(?:atob|Buffer\s*\.\s*from)\s*\(/i,
  },
  {
    code: "function-base64-decoder",
    regex: /\b(?:new\s+Function|Function|setTimeout|setInterval)\s*\(\s*(?:atob|Buffer\s*\.\s*from)\s*\(/i,
  },
  {
    code: "remote-shell-pipe",
    regex: /\b(?:curl|wget)\b[\s\S]{0,2048}\bhttps?:\/\/[^\r\n|]{0,2048}\|\s*(?:sudo\s+)?(?:bash|sh|zsh)\b/i,
  },
  {
    code: "child-process-remote-exec",
    regex: /\b(?:exec|execSync|spawn|spawnSync)\s*\(\s*["'`][^"'`\r\n]{0,2048}\bhttps?:\/\//i,
  },
  {
    code: "dense-encoded-exec",
    regex: /\b(?:eval|Function|exec|execSync|spawn|spawnSync)\b[\s\S]{0,4096}[A-Za-z0-9+/]{120,}={0,2}/i,
  },
];

function isWorkflow(path) {
  return matchesAny(
    [
      ".github/workflows/**",
      ".github/workflow-templates/**",
      ".github/workflows-templates/**",
    ],
    path,
  );
}

function isSuspiciousContentPath(path, additionalPaths = []) {
  if (isDocumentationPath(path)) return false;
  return (
    matchesAny(DEFAULT_SUSPICIOUS_CONTENT_PATHS, path) ||
    matchesAny(additionalPaths, path)
  );
}

function isDocumentationPath(path) {
  const normalized = String(path || "").toLowerCase();
  const filename = normalized.split("/").pop() || normalized;
  const extension = filename.includes(".")
    ? `.${filename.split(".").pop()}`
    : "";
  return DOCUMENTATION_EXTENSIONS.has(extension);
}

/**
 * A first-install ("bootstrap") pull request: the one that adds the guard and
 * would otherwise fail on the very file it is installing.
 *
 * Control-plane paths are fail-closed because a change there can weaken the
 * guard. Adding the guard is the one case where that reasoning does not hold:
 * there is no prior policy to weaken, and blocking it means every new adopter's
 * first PR goes red, which teaches them to ignore or remove the check.
 *
 * Deliberately narrow, so it cannot be used to slip a change past the guard:
 *   - every control-plane file in the PR is ADDED, never modified or removed
 *     (a modification could weaken an existing workflow)
 *   - EVERY added control-plane file installs THIS action, proven by a `uses:`
 *     step naming the guard's own repository. Without that evidence, adding any
 *     unrelated workflow or a brand-new .aport policy would read as a first
 *     install and quietly lose the control-plane severity. Checking every file
 *     rather than just one matters: an install that also adds an unrelated
 *     `deploy.yml` would otherwise downgrade that file too.
 *   - no existing .aport policy file is touched
 *
 * The marker is content an author controls, so a guard step alone cannot be the
 * test: a workflow that carries a real guard step AND a `run:` that posts
 * GITHUB_TOKEN to an attacker satisfies it while raising no blocking finding of
 * its own (the id-token/contents pair is read as OIDC and is only a warning).
 * The added workflow must therefore look like an install as a WHOLE file:
 * no `run:` steps at all, and no `uses:` other than the guard and a short
 * allowlist of steps a real install legitimately needs.
 *
 * A PR that both installs the guard and changes something else in the control
 * plane is NOT a bootstrap and stays fail-closed.
 */
function isBootstrapInstall(files = [], controlPlaneTouched = [], fileContents = {}) {
  if (!controlPlaneTouched.length) return false;

  const controlPlaneFiles = files.filter((file) =>
    filePathCandidates(file).some((path) =>
      matchesAny(DEFAULT_CONTROL_PLANE_PATHS, path),
    ),
  );
  if (!controlPlaneFiles.length) return false;

  // Every control-plane file must be newly added. "added" is GitHub's status
  // for a file that did not exist on the base branch.
  const allAdded = controlPlaneFiles.every(
    (file) => String(file?.status || "").toLowerCase() === "added",
  );
  if (!allAdded) return false;

  // Policy files are never bootstrapped silently: if one is present it must
  // also be an addition, which the check above already required, but a policy
  // change alongside a workflow addition is not a plain install.
  const policyTouched = controlPlaneFiles.some((file) =>
    filePathCandidates(file).some((path) =>
      matchesAny([".aport/policy.yaml", ".aport/policy.yml"], path),
    ),
  );
  if (policyTouched && controlPlaneFiles.length > 1) return false;

  // `every`, not `some`: a PR that installs the guard AND adds an unrelated
  // control-plane file is not a plain install, and downgrading it would hand
  // the unrelated file the carve-out too.
  return controlPlaneFiles.every((file) =>
    installsAportGuard(file, fileContents),
  );
}

function workflowAddedSource(file, fullContent) {
  // An added file may arrive as a patch or as full content; either represents
  // the whole new file, matching how the workflow scan below reads them.
  if (!file?.patch) return String(fullContent || "");
  return file.patch
    .split(/\r?\n/)
    .filter((line) => line.startsWith("+") && !line.startsWith("+++"))
    .map((line) => line.slice(1))
    .join("\n");
}

/**
 * Positive evidence that an added workflow installs this guard: a `uses:` step
 * naming the action's own repository. Read from the added lines only, so a
 * pre-existing mention elsewhere in the file cannot be replayed as evidence.
 *
 * The line must be a real workflow step, not merely text that looks like one.
 * A `run: |` block can contain anything, including `uses: aporthq/...` inside a
 * heredoc, and matching raw text would let an unrelated or hostile workflow
 * claim the install carve-out.
 */
function installsAportGuard(file, fileContents = {}) {
  const paths = filePathCandidates(file);
  if (!paths.some(isWorkflow)) return false;

  const source = workflowAddedSource(
    file,
    fileContentForPaths(paths, fileContents),
  );

  const refs = workflowExecutableUses(source);
  if (!refs.some((ref) => isAportGuardActionRef(ref))) return false;

  // Every other action step must be one an install actually needs. Anything
  // else is a workflow doing more than installing the guard.
  if (!refs.every((ref) => isAportGuardActionRef(ref) || isInstallSupportActionRef(ref))) {
    return false;
  }

  // A `run:` step executes arbitrary code with the workflow's token. The
  // shipped guard workflow has none, so its presence means this file is not
  // just an install.
  if (hasRunStep(source)) return false;

  return true;
}

/**
 * Steps a genuine install may carry besides the guard itself. Deliberately
 * tiny: every entry widens what can claim the carve-out.
 */
const INSTALL_SUPPORT_ACTIONS = ["actions/checkout"];

function isInstallSupportActionRef(ref) {
  const slug = String(ref || "").split("@")[0].toLowerCase();
  return INSTALL_SUPPORT_ACTIONS.includes(slug);
}

/**
 * Whether the added source declares a `run:` step, ignoring text inside a block
 * scalar (where `run:` is data, not a key).
 */
function hasRunStep(source) {
  return scanWorkflowExecution(source).hasRunStep;
}

/**
 * The reference must be the guard's own repository, optionally at a version.
 * Compared on the slug so `notaporthq/policy-verify-action` and
 * `aporthq/policy-verify-action-evil` do not qualify.
 */
function isAportGuardActionRef(ref) {
  const slug = String(ref || "").split("@")[0];
  return slug.toLowerCase() === APORT_ACTION_REPOSITORY;
}

/**
 * The `uses` value of a flow-style step mapping (`{ uses: a/b@v1, with: {...} }`),
 * or null. Only the mapping's OWN key counts: a nested `with: { uses: ... }` is
 * an input value, never a step that runs, and matching every `uses:` in the line
 * let a workflow park the guard reference inside inputs and claim the install.
 */
function flowMappingUses(text) {
  return flowMappingKeyValue(text, "uses");
}

function flowMappingHasRun(text) {
  return flowMappingHasKey(text, "run");
}

function flowMappingHasKey(text, wantedKey) {
  return flowMappingKeyValue(text, wantedKey, { returnBoolean: true }) === true;
}

function normalizeYamlNodePrefix(text) {
  let value = String(text || "").trim();
  let changed = true;
  while (changed) {
    changed = false;
    const anchor = value.match(/^&[A-Za-z0-9_.-]+(?:\s+|$)(.*)$/);
    if (anchor) {
      value = anchor[1].trimStart();
      changed = true;
      continue;
    }
    const tag = value.match(/^![^\s]+(?:\s+|$)(.*)$/);
    if (tag) {
      value = tag[1].trimStart();
      changed = true;
    }
  }
  return value;
}

function flowMappingKeyValue(text, wantedKey, { returnBoolean = false } = {}) {
  const body = String(text || "");
  let depth = 0;
  let quote = null;
  let keyStart = -1;
  for (let i = 0; i < body.length; i += 1) {
    const char = body[i];
    if (quote) {
      if (quote === '"' && char === "\\") {
        i += 1;
        continue;
      }
      if (char === quote) quote = null;
      continue;
    }
    if (char === '"' || char === "'") {
      quote = char;
      continue;
    }
    if (char === "{" || char === "[") {
      depth += 1;
      // Entering the outer mapping starts its first key; anything deeper is a
      // nested value whose keys must be skipped.
      if (depth === 1) keyStart = i + 1;
      continue;
    }
    if (char === "}" || char === "]") {
      depth -= 1;
      if (depth === 1) keyStart = -1;
      continue;
    }
    // A comma at depth 1 ends one entry of the outer mapping and starts the next.
    if (char === "," && depth === 1) {
      keyStart = i + 1;
      continue;
    }
    if (char === ":" && depth === 1 && keyStart >= 0) {
      const key = body.slice(keyStart, i).trim().replace(/^["']|["']$/g, "");
      keyStart = -1;
      if (key.toLowerCase() !== String(wantedKey || "").toLowerCase()) continue;
      if (returnBoolean) return true;
      return readFlowScalarValue(body, i + 1);
    }
  }
  return returnBoolean ? false : null;
}

function readFlowScalarValue(text, start) {
  const body = String(text || "");
  let i = start;
  while (i < body.length && /\s/.test(body[i])) i += 1;
  const quote = body[i] === '"' || body[i] === "'" ? body[i] : null;
  if (quote) {
    let value = "";
    for (i += 1; i < body.length; i += 1) {
      const char = body[i];
      if (quote === '"' && char === "\\") {
        if (i + 1 < body.length) value += body[i + 1];
        i += 1;
        continue;
      }
      if (char === quote) return value;
      value += char;
    }
    return value || null;
  }
  const value = body.slice(i).match(/^([^,}\]\s]+)/);
  return value ? value[1] : null;
}

/**
 * Every top-level `uses` of a flow sequence: `[{uses: a/b@v1}, {uses: c/d@v2}]`.
 * Splits on the sequence's own commas so each mapping is read on its own terms.
 */
function flowSequenceUses(text) {
  return flowSequenceMappings(text)
    .map(flowMappingUses)
    .filter(Boolean);
}

function flowSequenceHasRun(text) {
  return flowSequenceMappings(text).some(flowMappingHasRun);
}

function flowSequenceMappings(text) {
  const body = String(text || "");
  const mappings = [];
  let depth = 0;
  let quote = null;
  let itemStart = -1;
  for (let i = 0; i < body.length; i += 1) {
    const char = body[i];
    if (quote) {
      if (quote === '"' && char === "\\") {
        i += 1;
        continue;
      }
      if (char === quote) quote = null;
      continue;
    }
    if (char === '"' || char === "'") {
      quote = char;
      continue;
    }
    if (char === "{" || char === "[") {
      depth += 1;
      if (depth === 2 && char === "{") itemStart = i;
      continue;
    }
    if (char === "}" || char === "]") {
      if (depth === 2 && char === "}" && itemStart >= 0) {
        mappings.push(body.slice(itemStart, i + 1));
        itemStart = -1;
      }
      depth -= 1;
    }
  }
  return mappings;
}

function isFlowSequenceComplete(text) {
  const body = String(text || "");
  let depth = 0;
  let quote = null;
  let sawSequence = false;
  for (let i = 0; i < body.length; i += 1) {
    const char = body[i];
    if (quote) {
      if (quote === '"' && char === "\\") {
        i += 1;
        continue;
      }
      if (char === quote) quote = null;
      continue;
    }
    if (char === '"' || char === "'") {
      quote = char;
      continue;
    }
    if (char === "[") {
      sawSequence = true;
      depth += 1;
      continue;
    }
    if (char === "]") {
      depth -= 1;
      if (sawSequence && depth <= 0) return true;
    }
  }
  return false;
}

function isFlowMappingComplete(text) {
  const body = String(text || "");
  let depth = 0;
  let quote = null;
  let sawMapping = false;
  for (let i = 0; i < body.length; i += 1) {
    const char = body[i];
    if (quote) {
      if (quote === '"' && char === "\\") {
        i += 1;
        continue;
      }
      if (char === quote) quote = null;
      continue;
    }
    if (char === '"' || char === "'") {
      quote = char;
      continue;
    }
    if (char === "{") {
      sawMapping = true;
      depth += 1;
      continue;
    }
    if (char === "}") {
      depth -= 1;
      if (sawMapping && depth <= 0) return true;
    }
  }
  return false;
}

/**
 * Action references that appear as executable workflow entries.
 *
 * YAML without a parser, so this is a structural approximation rather than a
 * full load. Three forms count as executable references:
 *
 *   1. It is not inside a block scalar. `key: |` or `key: >` makes every
 *      following line indented deeper than that key literal text, so anything
 *      matched there is content, not structure.
 *   2. It sits at a plausible step position: a `- uses:` sequence item, or a
 *      `uses:` key in a mapping opened by a `- ` sequence item at the same
 *      indent. A workflow nests jobs > <job> > steps > - step, so a step key is
 *      always indented; a top-level `uses:` is not a workflow step.
 *   3. It is a job-level reusable workflow reference (`jobs.<id>.uses`).
 *
 * Including job-level `uses` matters because a bootstrap install is only safe
 * when the whole workflow is just the guard. A reusable workflow is executable
 * code too, so it must be surfaced to the allowlist instead of ignored.
 */
function scanWorkflowExecution(source) {
  const refs = [];
  let hasRunStepValue = false;
  const lines = String(source || "").split(/\r?\n/);
  // Indent of the key that opened the current block scalar, or null.
  let blockScalarIndent = null;
  // Indent of the most recent `- ` sequence item, so `uses:` written as a later
  // key of that same step mapping is still recognised.
  let sequenceItemIndent = null;
  // Indent of the `steps:` key whose sequence we are inside, or null. Only a
  // `uses:` under a steps sequence actually runs. Accepting any indented
  // `uses:` let a workflow park the guard reference in inert data such as an
  // `env:` mapping while running something else entirely.
  let stepsIndent = null;
  let stepsSequenceIndent = null;
  // Indent of a `jobs.<id>.uses:` reusable-workflow call, which is executable
  // but is not a step.
  let jobIdIndent = null;
  // Indent the active job's own keys sit at. Derived from the first key seen
  // inside the job rather than assumed to be jobIdIndent + 2: a workflow
  // indented four spaces per level put its `jobs.<id>.uses` reusable-workflow
  // call outside the assumed column, so a hostile call was never returned and
  // the file still read as a plain guard install.
  let jobKeyIndent = null;
  // Indent of the `jobs:` key itself, so its direct children can be identified.
  let jobsIndent = null;
  let flowStepsBuffer = null;
  let flowStepMappingBuffer = null;
  let explicitJobKeyIndent = null;
  let explicitStepsKeyIndent = null;

  function processStepsInlineValue(inline) {
    const value = normalizeYamlNodePrefix(inline);
    if (!value) return;
    if (value.startsWith("[")) {
      if (isFlowSequenceComplete(value)) {
        refs.push(...flowSequenceUses(value));
        hasRunStepValue = hasRunStepValue || flowSequenceHasRun(value);
      } else {
        flowStepsBuffer = value;
      }
      return;
    }
    // An aliased step list may resolve to executable YAML anchored elsewhere.
    // This lightweight scanner does not resolve anchors, so fail closed for the
    // bootstrap decision instead of treating the sequence as empty.
    if (/^\*[A-Za-z0-9_.-]+$/.test(value)) {
      hasRunStepValue = true;
    }
  }

  for (const rawLine of lines) {
    if (!rawLine.trim()) continue;

    const indent = leadingWhitespaceLength(rawLine);
    if (blockScalarIndent !== null) {
      // Still deeper than the introducing key, so this is literal text.
      if (indent > blockScalarIndent) continue;
      blockScalarIndent = null;
    }

    const line = stripYamlComment(rawLine);
    if (!line.trim()) continue;

    if (flowStepsBuffer !== null) {
      flowStepsBuffer += `\n${line.trim()}`;
      if (isFlowSequenceComplete(flowStepsBuffer)) {
        refs.push(...flowSequenceUses(flowStepsBuffer));
        hasRunStepValue = hasRunStepValue || flowSequenceHasRun(flowStepsBuffer);
        flowStepsBuffer = null;
      }
      continue;
    }

    if (flowStepMappingBuffer !== null) {
      flowStepMappingBuffer += `\n${line.trim()}`;
      if (isFlowMappingComplete(flowStepMappingBuffer)) {
        const flowRef = flowMappingUses(flowStepMappingBuffer);
        if (flowRef) refs.push(flowRef);
        hasRunStepValue =
          hasRunStepValue || flowMappingHasRun(flowStepMappingBuffer);
        flowStepMappingBuffer = null;
      }
      continue;
    }

    if (explicitJobKeyIndent !== null) {
      if (/^\s*:\s*(?:&[A-Za-z0-9_.-]+)?\s*$/.test(line)) {
        jobKeyIndent = null;
        jobIdIndent = explicitJobKeyIndent;
        explicitJobKeyIndent = null;
        continue;
      }
      explicitJobKeyIndent = null;
    }

    if (explicitStepsKeyIndent !== null) {
      const explicitStepsValue = line.match(
        /^\s*:\s*(?:&[A-Za-z0-9_.-]+)?\s*(.*)$/i,
      );
      if (explicitStepsValue) {
        stepsIndent = explicitStepsKeyIndent;
        stepsSequenceIndent = null;
        sequenceItemIndent = null;
        explicitStepsKeyIndent = null;
        processStepsInlineValue(explicitStepsValue[1]);
        continue;
      }
      explicitStepsKeyIndent = null;
    }

    // Leaving the steps sequence: any key at or above the `steps:` indent.
    if (stepsIndent !== null && indent <= stepsIndent && !/^\s*-(?:\s+|\s*$)/.test(line)) {
      stepsIndent = null;
      stepsSequenceIndent = null;
      sequenceItemIndent = null;
    }
    // `jobs:` opens the job map; its direct children are job ids.
    const jobsMatch = line.match(/^(\s*)["']?jobs["']?\s*:\s*$/i);
    if (jobsMatch) {
      jobsIndent = indent;
      jobIdIndent = null;
      jobKeyIndent = null;
      explicitJobKeyIndent = null;
      explicitStepsKeyIndent = null;
      continue;
    }
    if (jobsIndent !== null && indent <= jobsIndent && !/^\s*-(?:\s+|\s*$)/.test(line)) {
      jobsIndent = null;
      jobIdIndent = null;
      jobKeyIndent = null;
      explicitJobKeyIndent = null;
      explicitStepsKeyIndent = null;
    }
    const isDirectJobEntry =
      jobsIndent !== null &&
      indent > jobsIndent &&
      (jobIdIndent === null || indent <= jobIdIndent);
    if (
      jobIdIndent !== null &&
      indent > jobIdIndent &&
      (jobKeyIndent === null || indent <= jobKeyIndent) &&
      /^\s*\?\s+["']?steps["']?\s*$/.test(line)
    ) {
      jobKeyIndent = indent;
      explicitStepsKeyIndent = indent;
      continue;
    }
    if (
      isDirectJobEntry &&
      /^\s*\?\s+[A-Za-z0-9_-]+\s*$/.test(line)
    ) {
      explicitJobKeyIndent = indent;
      continue;
    }
    if (
      jobsIndent !== null &&
      indent > jobsIndent &&
      /^\s*["']?[A-Za-z0-9_-]+["']?\s*:\s*(?:&[A-Za-z0-9_.-]+)?\s*$/.test(line)
    ) {
      // A job id, if it is the first level under `jobs:`.
      if (jobIdIndent === null || indent <= jobIdIndent) {
        // A new job id ends the previous job, so its key column is unknown again.
        jobKeyIndent = null;
        jobIdIndent = indent;
        explicitStepsKeyIndent = null;
      }
    }
    // The shallowest key strictly inside the job id is the job's own key column,
    // whatever the file's indent step happens to be.
    if (
      jobIdIndent !== null &&
      indent > jobIdIndent &&
      !/^\s*-(?:\s+|\s*$)/.test(line) &&
      /^\s*["']?[A-Za-z0-9_.-]+["']?\s*:/.test(line) &&
      (jobKeyIndent === null || indent < jobKeyIndent)
    ) {
      jobKeyIndent = indent;
    }

    const jobFlowMatch = line.match(
      /^\s*["']?[A-Za-z0-9_-]+["']?\s*:\s*(\{.*)$/i,
    );
    if (isDirectJobEntry && jobFlowMatch) {
      const ref = flowMappingUses(jobFlowMatch[1]);
      if (ref) refs.push(ref);
      jobKeyIndent = null;
      jobIdIndent = indent;
      continue;
    }

    const stepsMatch = line.match(/^\s*["']?steps["']?\s*:\s*(.*)$/i);
    const isJobKeyContext =
      jobIdIndent !== null && jobKeyIndent !== null && indent === jobKeyIndent;
    if (stepsMatch && isJobKeyContext) {
      stepsIndent = indent;
      stepsSequenceIndent = null;
      sequenceItemIndent = null;
      processStepsInlineValue(stepsMatch[1]);
      continue;
    }

    const sequenceMatch = line.match(/^(\s*)-(\s*)(.*)$/);
    const isStepSequenceItem =
      Boolean(sequenceMatch) &&
      stepsIndent !== null &&
      (stepsSequenceIndent === null
        ? indent >= stepsIndent
        : indent === stepsSequenceIndent);
    if (sequenceMatch) {
      if (isStepSequenceItem) {
        if (stepsSequenceIndent === null) stepsSequenceIndent = indent;
        // The step mapping's keys line up with the text after the dash. A bare
        // `-` has no text after it; YAML still treats the following indented
        // mapping as the step body, so use the conventional child column.
        const itemText = sequenceMatch[3] || "";
        sequenceItemIndent = itemText.trim()
          ? sequenceMatch[1].length + 1 + sequenceMatch[2].length
          : sequenceMatch[1].length + 2;
        // A flow-style step item: `- { uses: a/b@v1, with: ... }`.
        const flow = normalizeYamlNodePrefix(itemText);
        if (flow.startsWith("{")) {
          if (isFlowMappingComplete(flow)) {
            const flowRef = flowMappingUses(flow);
            if (flowRef) refs.push(flowRef);
            hasRunStepValue = hasRunStepValue || flowMappingHasRun(flow);
          } else {
            flowStepMappingBuffer = flow;
          }
          continue;
        }
        if (/^\*[A-Za-z0-9_.-]+$/.test(flow)) {
          hasRunStepValue = true;
          continue;
        }
        const inlineUsesMatch = flow.match(
          /^["']?uses["']?\s*:\s*['"]?([^'"\s#]+)['"]?\s*$/i,
        );
        if (inlineUsesMatch) {
          refs.push(inlineUsesMatch[1]);
          continue;
        }
        if (/^["']?run["']?\s*:/i.test(flow)) {
          hasRunStepValue = true;
          continue;
        }
      }
    } else if (sequenceItemIndent !== null && indent < sequenceItemIndent) {
      // Dedented out of the sequence entirely.
      sequenceItemIndent = null;
    }

    const usesMatch = line.match(
      /^\s*(?:-\s*)?["']?uses["']?\s*:\s*['"]?([^'"\s#]+)['"]?\s*$/i,
    );
    if (usesMatch) {
      const isSequenceItem = isStepSequenceItem;
      const isStepKey =
        sequenceItemIndent !== null && indent === sequenceItemIndent;
      // Inside a steps sequence, a `uses:` is either the item itself or a key
      // of the item's mapping. Outside one, the only executable `uses:` is a
      // job calling a reusable workflow: `jobs.<id>.uses`, which sits exactly
      // one level inside the job id, is not itself a sequence item, and is the
      // job's own key. Everything else -- env:, with:, inputs:, outputs:, a
      // strategy matrix -- is data and must not count, however deeply nested.
      // A sequence item may sit at the SAME column as the `steps:` key that
      // owns it -- valid YAML, and common in hand-written workflows. Requiring
      // a deeper indent hid the guard step of such a file, so a clean first
      // install was blocked at high severity.
      const inSteps =
        stepsIndent !== null &&
        (indent > stepsIndent || (isSequenceItem && indent === stepsIndent));
      const isReusableJobCall =
        !inSteps &&
        jobIdIndent !== null &&
        jobKeyIndent !== null &&
        indent === jobKeyIndent &&
        !isSequenceItem;
      if (inSteps ? isSequenceItem || isStepKey : isReusableJobCall) {
        refs.push(usesMatch[1]);
      }
      continue;
    }

    const runMatch = line.match(/^\s*(?:-\s*)?["']?run["']?\s*:/i);
    if (runMatch) {
      const isStepKey =
        sequenceItemIndent !== null && indent === sequenceItemIndent;
      if (isStepSequenceItem || isStepKey) {
        hasRunStepValue = true;
      }
      continue;
    }

    // `key: |`, `key: >` and their indicators (`|-`, `>+`, `|2`) open a block
    // scalar whose body is everything indented deeper than this key.
    if (/^\s*(?:-\s+)?[^:\r\n]+:\s*[|>][0-9+-]*\s*$/.test(line)) {
      blockScalarIndent = indent;
    }
  }

  return {
    usesRefs: refs,
    hasRunStep: hasRunStepValue,
  };
}

function workflowExecutableUses(source) {
  return scanWorkflowExecution(source).usesRefs;
}

/**
 * Does this PR introduce an action that is not pinned to a full commit SHA?
 *
 * Only asked when the trusted base policy sets require_pinned_actions. Such a
 * repository has explicitly demanded pinning, and OAP.REPO.UNPINNED_ACTION is
 * warning-level, so a bootstrap downgrade would leave the install PR with no
 * blocking finding at all and the required check would never fail. The install
 * carve-out therefore does not apply to installs that are themselves unpinned:
 * fix the pins and the PR passes.
 */
function introducesUnpinnedActions({
  files = [],
  fileContents = {},
  requirePinnedActions = false,
} = {}) {
  if (!requirePinnedActions) return false;

  return files.some((file) => {
    const paths = filePathCandidates(file);
    if (!paths.some(isWorkflow)) return false;
    const source = workflowAddedSource(file, fileContentForPaths(paths, fileContents));
    return findUnpinnedActions(source).length > 0;
  });
}

/**
 * The carve-out exists for the pull request that installs the guard, so it only
 * applies to pull-request style validation (`pull_request`, review events on
 * that same PR, and the merge queue re-validation of the same change).
 *
 * The push trigger exists to catch changes made directly on a protected branch,
 * which is exactly the case the control-plane rule is fail-closed for. A direct
 * push that adds a workflow naming this action must therefore stay high.
 *
 * Unknown or absent event names are treated as NOT a pull request: callers that
 * do not pass an event get the fail-closed answer rather than a silent
 * downgrade on push.
 */
function isInstallPullRequestEvent(eventName) {
  // pull_request_target is deliberately NOT here. It runs with the base
  // repository's secrets against head content the fork author controls, so it
  // is the one event where downgrading a control-plane finding is worst, and
  // README.md and CHANGELOG.md both already say the carve-out covers PR-style
  // validation only. A guard workflow does not need pull_request_target.
  return ["pull_request", "pull_request_review", "merge_group"].includes(
    String(eventName || "").toLowerCase(),
  );
}

function detectStructuralFindings({
  files = [],
  fileContents = {},
  protectedPaths = DEFAULT_PROTECTED_PATHS,
  blockProtectedPaths = false,
  requirePinnedActions = false,
  evidenceTruncated = {},
  eventName = "",
} = {}) {
  const findings = [];

  if (evidenceTruncated.files || evidenceTruncated.commits) {
    const truncated = [
      evidenceTruncated.files ? "files" : "",
      evidenceTruncated.commits ? "commits" : "",
    ].filter(Boolean);
    findings.push({
      code: "OAP.REPO.EVIDENCE_TRUNCATED",
      severity: "high",
      message: `GitHub repository ${truncated.join(" and ")} evidence is incomplete, so repository analysis is incomplete.`,
      details: {
        files_truncated: Boolean(evidenceTruncated.files),
        commits_truncated: Boolean(evidenceTruncated.commits),
        max_pages: evidenceTruncated.maxPages,
      },
    });
  }

  const protectedTouched = uniquePaths(
    files.flatMap((file) =>
      filePathCandidates(file).filter((path) => matchesAny(protectedPaths, path)),
    ),
  );
  const controlPlaneTouched = uniquePaths(
    files.flatMap((file) =>
      filePathCandidates(file).filter((path) =>
        matchesAny(DEFAULT_CONTROL_PLANE_PATHS, path),
      ),
    ),
  );
  const protectedOrControlPlaneTouched = uniquePaths([
    ...protectedTouched,
    ...controlPlaneTouched,
  ]);
  // A bootstrap install only downgrades THIS finding. Escalation and
  // pull_request_target findings are raised separately below and are not
  // affected, so an install PR that also does something dangerous still fails
  // on that specific finding rather than on the mere fact that it touched the
  // control plane. Unpinned actions are the exception: that finding is only
  // warning-level, so an unpinned install is excluded from the carve-out
  // outright rather than left with nothing blocking.
  const bootstrap =
    isInstallPullRequestEvent(eventName) &&
    !blockProtectedPaths &&
    isBootstrapInstall(files, controlPlaneTouched, fileContents) &&
    !introducesUnpinnedActions({ files, fileContents, requirePinnedActions });

  if (protectedOrControlPlaneTouched.length) {
    const blocking =
      (controlPlaneTouched.length && !bootstrap) || blockProtectedPaths;
    findings.push({
      code: "OAP.REPO.PROTECTED_PATH_TOUCHED",
      severity: blocking ? "high" : "warning",
      message: bootstrap
        ? "Guard control-plane paths added by a first-install pull request. "
          + "Reported rather than blocked: every control-plane file here is new, "
          + "so there is no existing guard configuration to weaken. Review the "
          + "added files before merging."
        : controlPlaneTouched.length
          ? "Guard control-plane paths changed."
          : "Protected repository paths changed.",
      paths: protectedOrControlPlaneTouched,
      details: bootstrap ? { bootstrap_install: true } : undefined,
    });
  }

  const suspiciousFindings = detectSuspiciousContentFindings(
    files,
    fileContents,
    protectedPaths,
  );
  findings.push(...suspiciousFindings);

  const policyTouched = uniquePaths(
    files.flatMap((file) =>
      filePathCandidates(file).filter((path) =>
        matchesAny([".aport/policy.yaml", ".aport/policy.yml"], path),
      ),
    ),
  );
  if (policyTouched.length) {
    findings.push({
      code: "OAP.GH.POLICY_HEAD_UNTRUSTED",
      severity: "warning",
      message: "Repository policy changed in this PR. APort ignores PR-head policy and evaluates using the trusted base-branch policy.",
      paths: policyTouched,
    });
  }

  for (const file of files) {
    const filename = primaryFilePath(file);
    if (!isWorkflow(filename)) continue;

    const fullContent = fileContents[filename];
    if (!file.patch && !fullContent) {
      findings.push({
        code: "OAP.REPO.WORKFLOW_DIFF_UNAVAILABLE",
        severity: "high",
        message:
          "GitHub did not provide a workflow patch, so workflow security analysis is incomplete.",
        paths: [filename],
      });
      continue;
    }

    const addedLines = file.patch
      ? file.patch
          .split(/\r?\n/)
          .filter((line) => line.startsWith("+") && !line.startsWith("+++"))
          .map((line) => line.slice(1))
          .join("\n")
      : String(fullContent || "");
    const permissionFindings = file.patch
      ? detectPatchPermissionFindings(file.patch)
      : detectSourcePermissionFindings(addedLines);

    if (PULL_REQUEST_TARGET_RE.test(addedLines)) {
      findings.push({
        code: "OAP.REPO.PULL_REQUEST_TARGET_INTRODUCED",
        severity: "high",
        message: "`pull_request_target` was introduced in a workflow.",
        paths: [filename],
      });
    }

    if (permissionFindings.repositoryWrite) {
      findings.push({
        code: "OAP.REPO.WORKFLOW_PERMISSION_ESCALATION",
        severity: "high",
        message: "Workflow write permissions were introduced or expanded.",
        paths: [filename],
      });
    }

    if (permissionFindings.oidcWrite) {
      findings.push({
        code: "OAP.REPO.OIDC_TOKEN_PERMISSION_ADDED",
        severity: "warning",
        message:
          "Workflow requests GitHub OIDC token permission. This is required for hosted APort OIDC, but should be reviewed against cloud trust policies.",
        paths: [filename],
      });
    }

    if (requirePinnedActions) {
      const unpinnedActions = findUnpinnedActions(addedLines);
      if (unpinnedActions.length) {
        findings.push({
          code: "OAP.REPO.UNPINNED_ACTION",
          severity: "warning",
          message: "Workflow introduced actions that are not pinned to a full commit SHA.",
          paths: [filename],
          actions: unpinnedActions,
        });
      }
    }
  }

  return findings;
}

function introducesWritePermissions(source) {
  return detectSourcePermissionFindings(source).repositoryWrite;
}

function introducesOidcWritePermission(source) {
  return detectSourcePermissionFindings(source).oidcWrite;
}

function patchIntroducesWritePermissions(patch) {
  return detectPatchPermissionFindings(patch).repositoryWrite;
}

function patchIntroducesOidcWritePermission(patch) {
  return detectPatchPermissionFindings(patch).oidcWrite;
}

function detectSourcePermissionFindings(source) {
  const result = { repositoryWrite: false, oidcWrite: false };
  if (WRITE_ALL_RE.test(source)) result.repositoryWrite = true;
  mergePermissionFindings(result, inlinePermissionFindings(source));
  mergePermissionFindings(result, permissionsBlockFindings(source));
  return result;
}

function detectPatchPermissionFindings(patch) {
  const result = { repositoryWrite: false, oidcWrite: false };
  const lines = workflowPatchLines(patch);
  let permissionsIndent = null;
  let inferredPermissionEntryIndent = null;

  for (const { added, text, hunk } of lines) {
    if (hunk) {
      permissionsIndent = null;
      inferredPermissionEntryIndent = null;
      continue;
    }

    const line = stripYamlComment(text);
    if (!line.trim()) continue;

    if (added && WRITE_ALL_RE.test(line)) {
      result.repositoryWrite = true;
    }

    if (added) {
      mergePermissionFindings(result, inlinePermissionFindings(line));
    }

    if (permissionsIndent !== null) {
      const indent = leadingWhitespaceLength(line);
      if (indent <= permissionsIndent) {
        permissionsIndent = null;
      } else if (added) {
        recordPermissionEntry(result, line);
      }
    }

    const permissionEntryIndent = permissionEntryIndentFor(line);
    if (permissionEntryIndent !== null) {
      if (
        added &&
        permissionEntryIndent === inferredPermissionEntryIndent &&
        isPermissionWriteEntry(line)
      ) {
        recordPermissionEntry(result, line);
      }
      if (!added && inferredPermissionEntryIndent === null) {
        inferredPermissionEntryIndent = permissionEntryIndent;
      }
    }

    const blockMatch = line.match(PERMISSIONS_BLOCK_RE);
    if (blockMatch) {
      permissionsIndent = blockMatch[1].length;
      inferredPermissionEntryIndent = null;
    }
  }

  return result;
}

function mergePermissionFindings(target, source) {
  target.repositoryWrite = target.repositoryWrite || source.repositoryWrite;
  target.oidcWrite = target.oidcWrite || source.oidcWrite;
}

function recordPermissionEntry(result, line) {
  if (WRITE_PERMISSION_ENTRY_RE.test(line)) {
    result.repositoryWrite = true;
  }
  if (OIDC_WRITE_PERMISSION_ENTRY_RE.test(line)) {
    result.oidcWrite = true;
  }
}

function isPermissionWriteEntry(line) {
  return (
    WRITE_PERMISSION_ENTRY_RE.test(line) ||
    OIDC_WRITE_PERMISSION_ENTRY_RE.test(line)
  );
}

function permissionEntryIndentFor(line) {
  if (!PERMISSION_ENTRY_RE.test(line)) return null;
  return leadingWhitespaceLength(line);
}

function workflowPatchLines(patch) {
  return String(patch || "")
    .split(/\r?\n/)
    .filter(
      (line) =>
        line.startsWith("@@") ||
        ((line.startsWith("+") || line.startsWith(" ")) &&
          !line.startsWith("+++")),
    )
    .map((line) =>
      line.startsWith("@@")
        ? { added: false, text: "", hunk: true }
        : {
            added: line.startsWith("+"),
            text: line.slice(1),
            hunk: false,
          },
    );
}

function inlinePermissionFindings(source) {
  const result = { repositoryWrite: false, oidcWrite: false };
  const lines = String(source || "").split(/\r?\n/);
  for (const rawLine of lines) {
    const line = stripYamlComment(rawLine);
    const match = line.match(
      /^\s*["']?permissions["']?\s*:\s*\{([^}\n]*)\}\s*$/i,
    );
    if (!match) continue;

    const entries = match[1].split(",");
    for (const entry of entries) recordPermissionEntry(result, entry);
  }
  return result;
}

function permissionsBlockFindings(source) {
  const result = { repositoryWrite: false, oidcWrite: false };
  const lines = String(source || "").split(/\r?\n/);
  let permissionsIndent = null;

  for (const rawLine of lines) {
    const line = stripYamlComment(rawLine);
    if (!line.trim()) continue;

    if (permissionsIndent !== null) {
      const indent = leadingWhitespaceLength(line);
      if (indent <= permissionsIndent) {
        permissionsIndent = null;
      } else {
        recordPermissionEntry(result, line);
      }
    }

    const blockMatch = line.match(PERMISSIONS_BLOCK_RE);
    if (blockMatch) {
      permissionsIndent = blockMatch[1].length;
    }
  }

  return result;
}

function detectSuspiciousContentFindings(
  files = [],
  fileContents = {},
  additionalSuspiciousPaths = [],
) {
  const findings = [];

  for (const file of files) {
    const paths = filePathCandidates(file);
    const suspiciousPaths = paths.filter((path) =>
      isSuspiciousContentPath(path, additionalSuspiciousPaths),
    );
    if (!suspiciousPaths.length) continue;

    const sourceEvidence = suspiciousSourceEvidenceForFile(
      file,
      fileContentForPaths(paths, fileContents),
    );
    if (!sourceEvidence.available) {
      const missingRequiredEvidencePaths = suspiciousPaths.filter(
        requiresSuspiciousContentEvidence,
      );
      if (missingRequiredEvidencePaths.length) {
        findings.push({
          code: "OAP.REPO.SUSPICIOUS_CONTENT_DIFF_UNAVAILABLE",
          severity: "high",
          message:
            "GitHub did not provide patch or content evidence for a sensitive execution/config surface, so suspicious-content analysis is incomplete.",
          paths: missingRequiredEvidencePaths,
        });
      }
      continue;
    }

    const patternCodes = findSuspiciousContentMatches(sourceEvidence.source).map(
      (match) => match.code,
    );
    if (!patternCodes.length) continue;

    findings.push({
      code: "OAP.REPO.SUSPICIOUS_OBFUSCATION",
      severity: "high",
      message:
        "Suspicious obfuscated or remote-execution code was introduced in a protected repository surface.",
      paths: suspiciousPaths,
      patterns: patternCodes,
    });
  }

  return findings;
}

function requiresSuspiciousContentEvidence(path) {
  return !matchesAny(SUSPICIOUS_CONTENT_EVIDENCE_OPTIONAL_PATHS, path);
}

function fileContentForPaths(paths, fileContents = {}) {
  for (const path of paths) {
    if (fileContents[path] !== undefined && fileContents[path] !== null) {
      return fileContents[path];
    }
  }
  return undefined;
}

function suspiciousSourceEvidenceForFile(file, fullContent) {
  if (typeof file?.patch === "string") {
    return {
      available: true,
      source: file.patch
        .split(/\r?\n/)
        .filter((line) => line.startsWith("+") && !line.startsWith("+++"))
        .map((line) => line.slice(1))
        .join("\n"),
    };
  }
  if (fullContent !== undefined && fullContent !== null) {
    return {
      available: true,
      source: String(fullContent),
    };
  }
  return {
    available: false,
    source: "",
  };
}

function findSuspiciousContentMatches(source) {
  const content = String(source || "");
  const matches = [];

  for (const pattern of SUSPICIOUS_PATTERNS) {
    pattern.regex.lastIndex = 0;
    const match = pattern.regex.exec(content);
    if (match) {
      matches.push({
        code: pattern.code,
        index: match.index,
      });
    }
  }

  return matches;
}

function stripYamlComment(line) {
  const text = String(line || "");
  let quote = null;
  for (let i = 0; i < text.length; i += 1) {
    const char = text[i];
    if (quote) {
      if (quote === '"' && char === "\\") {
        i += 1;
        continue;
      }
      if (char === quote) quote = null;
      continue;
    }
    if (char === '"' || char === "'") {
      quote = char;
      continue;
    }
    if (char === "#" && (i === 0 || /\s/.test(text[i - 1]))) {
      return text.slice(0, i).replace(/\s+$/, "");
    }
  }
  return text;
}

function leadingWhitespaceLength(line) {
  const match = line.match(/^\s*/);
  return match ? match[0].length : 0;
}

function findUnpinnedActions(source) {
  const unpinned = [];
  const actionRefs = new Set(workflowExecutableUses(source));
  if (!hasWorkflowExecutionScope(source) || actionRefs.size === 0) {
    USES_ACTION_RE.lastIndex = 0;
    let match;
    while ((match = USES_ACTION_RE.exec(source))) {
      actionRefs.add(match[1]);
    }
    for (const ref of flowStyleActionRefs(source)) {
      actionRefs.add(ref);
    }
  }
  for (const actionRef of actionRefs) {
    if (actionRef.startsWith("./") || actionRef.startsWith("../")) continue;
    if (actionRef.startsWith("docker://")) continue;
    const atIndex = actionRef.lastIndexOf("@");
    if (atIndex < 0) {
      unpinned.push(actionRef);
      continue;
    }
    const ref = actionRef.slice(atIndex + 1);
    if (!SHA_PIN_RE.test(ref)) unpinned.push(actionRef);
  }
  return unpinned;
}

function hasWorkflowExecutionScope(source) {
  return /^\s*["']?(?:jobs|steps)["']?\s*:/im.test(String(source || "")) ||
    /^\s*\?\s+["']?steps["']?\s*$/im.test(String(source || ""));
}

function flowStyleActionRefs(source) {
  const refs = [];
  const text = String(source || "");
  const lines = text.split(/\r?\n/);
  let flowBuffer = null;

  for (const rawLine of lines) {
    const line = stripYamlComment(rawLine);
    if (!line.trim()) continue;

    if (flowBuffer !== null) {
      flowBuffer += `\n${line.trim()}`;
      if (isFlowMappingComplete(flowBuffer)) {
        const ref = flowMappingUses(flowBuffer);
        if (ref) refs.push(ref);
        flowBuffer = null;
      }
      continue;
    }

    const sequenceMatch = line.match(/^\s*-\s*(.*)$/);
    if (!sequenceMatch) continue;
    const item = normalizeYamlNodePrefix(sequenceMatch[1]);
    if (!item.startsWith("{")) continue;
    if (isFlowMappingComplete(item)) {
      const ref = flowMappingUses(item);
      if (ref) refs.push(ref);
    } else {
      flowBuffer = item;
    }
  }

  return refs;
}

module.exports = {
  // Exported for tests: the executable-position scan is the security boundary.
  workflowExecutableUses,
  DEFAULT_CONTROL_PLANE_PATHS,
  DEFAULT_PROTECTED_PATHS,
  DEFAULT_SUSPICIOUS_CONTENT_PATHS,
  detectSuspiciousContentFindings,
  detectStructuralFindings,
  findSuspiciousContentMatches,
  findUnpinnedActions,
  introducesOidcWritePermission,
  introducesWritePermissions,
  patchIntroducesOidcWritePermission,
  patchIntroducesWritePermissions,
};

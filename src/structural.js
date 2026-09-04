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

const CONTROL_PLANE_MUTATION_PATHS = [
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
const USES_ACTION_RE = /^\s*(?:-\s*)?uses\s*:\s*['"]?([^'"\s#]+)['"]?(?:\s+#.*)?$/gim;
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

function isControlPlaneMutationPath(path) {
  return matchesAny(CONTROL_PLANE_MUTATION_PATHS, path);
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

function detectStructuralFindings({
  files = [],
  fileContents = {},
  protectedPaths = DEFAULT_PROTECTED_PATHS,
  blockProtectedPaths = false,
  requirePinnedActions = false,
  evidenceTruncated = {},
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
  if (protectedTouched.length) {
    const touchesControlPlane = protectedTouched.some(isControlPlaneMutationPath);
    findings.push({
      code: "OAP.REPO.PROTECTED_PATH_TOUCHED",
      severity: blockProtectedPaths || touchesControlPlane ? "high" : "warning",
      message: "Protected repository paths changed.",
      paths: protectedTouched,
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
  return String(line || "").replace(/\s+#.*$/, "");
}

function leadingWhitespaceLength(line) {
  const match = line.match(/^\s*/);
  return match ? match[0].length : 0;
}

function findUnpinnedActions(source) {
  const unpinned = [];
  let match;
  while ((match = USES_ACTION_RE.exec(source))) {
    const actionRef = match[1];
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

module.exports = {
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

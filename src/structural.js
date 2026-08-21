const { matchesAny } = require("./glob");
const {
  filePathCandidates,
  primaryFilePath,
  uniquePaths,
} = require("./path-evidence");

const DEFAULT_PROTECTED_PATHS = [
  ".github/workflows/**",
  ".github/actions/**",
  "package.json",
  "pnpm-lock.yaml",
  "package-lock.json",
  "yarn.lock",
  "next.config.*",
  "tailwind.config.*",
  ".aport/policy.yaml",
  ".aport/policy.yml",
  "functions/api/verify/**",
  "functions/utils/policy/**",
  "policies/**",
];

const WRITE_ALL_RE = /^\s*["']?permissions["']?\s*:\s*["']?write-all["']?\s*(?:#.*)?$/im;
const PERMISSIONS_BLOCK_RE = /^(\s*)["']?permissions["']?\s*:\s*$/i;
const GITHUB_PERMISSION_SCOPE = String.raw`(?:actions|attestations|checks|contents|deployments|discussions|id-token|issues|models|packages|pages|pull-requests|repository-projects|security-events|statuses)`;
const WRITE_PERMISSION_ENTRY_RE = new RegExp(
  String.raw`^\s*["']?${GITHUB_PERMISSION_SCOPE}["']?\s*:\s*["']?write["']?\s*$`,
  "i",
);
const PERMISSION_ENTRY_RE = new RegExp(
  String.raw`^\s*["']?${GITHUB_PERMISSION_SCOPE}["']?\s*:\s*["']?(?:read|write|none)["']?\s*$`,
  "i",
);
const PULL_REQUEST_TARGET_RE =
  /^\s*-\s*['"]?pull_request_target['"]?\s*$|^\s*['"]?pull_request_target['"]?\s*:|^\s*['"]?on['"]?\s*:\s*['"]?pull_request_target['"]?\s*(?:#.*)?$|^\s*['"]?on['"]?\s*:\s*\[[^\]]*\b['"]?pull_request_target['"]?\b[^\]]*\]|^\s*['"]?on['"]?\s*:\s*\{.*\b['"]?pull_request_target['"]?\b.*\}\s*$/im;
const USES_ACTION_RE = /^\s*(?:-\s*)?uses\s*:\s*['"]?([^'"\s#]+)['"]?(?:\s+#.*)?$/gim;
const SHA_PIN_RE = /^[a-f0-9]{40}$/i;

function isWorkflow(path) {
  return matchesAny([".github/workflows/**"], path);
}

function detectStructuralFindings({
  files = [],
  fileContents = {},
  protectedPaths = DEFAULT_PROTECTED_PATHS,
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
    findings.push({
      code: "OAP.REPO.PROTECTED_PATH_TOUCHED",
      severity: "warning",
      message: "Protected repository paths changed.",
      paths: protectedTouched,
    });
  }

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
    const permissionsExpanded = file.patch
      ? patchIntroducesWritePermissions(file.patch)
      : introducesWritePermissions(addedLines);

    if (PULL_REQUEST_TARGET_RE.test(addedLines)) {
      findings.push({
        code: "OAP.REPO.PULL_REQUEST_TARGET_INTRODUCED",
        severity: "high",
        message: "`pull_request_target` was introduced in a workflow.",
        paths: [filename],
      });
    }

    if (permissionsExpanded) {
      findings.push({
        code: "OAP.REPO.WORKFLOW_PERMISSION_ESCALATION",
        severity: "high",
        message: "Workflow write permissions were introduced or expanded.",
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
  return (
    WRITE_ALL_RE.test(source) ||
    inlinePermissionsIntroduceWrite(source) ||
    permissionsBlockIntroducesWrite(source)
  );
}

function patchIntroducesWritePermissions(patch) {
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

    if (
      added &&
      (WRITE_ALL_RE.test(line) || inlinePermissionsIntroduceWrite(line))
    ) {
      return true;
    }

    if (permissionsIndent !== null) {
      const indent = leadingWhitespaceLength(line);
      if (indent <= permissionsIndent) {
        permissionsIndent = null;
      } else if (added && WRITE_PERMISSION_ENTRY_RE.test(line)) {
        return true;
      }
    }

    const permissionEntryIndent = permissionEntryIndentFor(line);
    if (permissionEntryIndent !== null) {
      if (
        added &&
        permissionEntryIndent === inferredPermissionEntryIndent &&
        WRITE_PERMISSION_ENTRY_RE.test(line)
      ) {
        return true;
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

  return false;
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

function inlinePermissionsIntroduceWrite(source) {
  const lines = String(source || "").split(/\r?\n/);
  for (const rawLine of lines) {
    const line = stripYamlComment(rawLine);
    const match = line.match(
      /^\s*["']?permissions["']?\s*:\s*\{([^}\n]*)\}\s*$/i,
    );
    if (!match) continue;

    const entries = match[1].split(",");
    if (
      entries.some((entry) => WRITE_PERMISSION_ENTRY_RE.test(entry))
    ) {
      return true;
    }
  }
  return false;
}

function permissionsBlockIntroducesWrite(source) {
  const lines = String(source || "").split(/\r?\n/);
  let permissionsIndent = null;

  for (const rawLine of lines) {
    const line = stripYamlComment(rawLine);
    if (!line.trim()) continue;

    if (permissionsIndent !== null) {
      const indent = leadingWhitespaceLength(line);
      if (indent <= permissionsIndent) {
        permissionsIndent = null;
      } else if (WRITE_PERMISSION_ENTRY_RE.test(line)) {
        return true;
      }
    }

    const blockMatch = line.match(PERMISSIONS_BLOCK_RE);
    if (blockMatch) {
      permissionsIndent = blockMatch[1].length;
    }
  }

  return false;
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
  detectStructuralFindings,
  findUnpinnedActions,
  introducesWritePermissions,
};

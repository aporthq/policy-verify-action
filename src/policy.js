const { createHash } = require("crypto");
const { matchesAny } = require("./glob");
const { DEFAULT_PROTECTED_PATHS } = require("./structural");

const POLICY_PATHS = [".aport/policy.yaml", ".aport/policy.yml"];

function parseRepositoryPolicy(source) {
  const protectedPaths = readYamlList(source, ["repository", "protected_paths"]);
  const allowedBaseBranches = readYamlList(source, [
    "repository",
    "allowed_base_branches",
  ]);
  const requirePinnedActions = readYamlBoolean(source, [
    "github",
    "require_pinned_actions",
  ]);

  return {
    repository: {
      ...(protectedPaths.length ? { protected_paths: protectedPaths } : {}),
      ...(allowedBaseBranches.length
        ? { allowed_base_branches: allowedBaseBranches }
        : {}),
    },
    github: {
      ...(requirePinnedActions !== undefined
        ? { require_pinned_actions: requirePinnedActions }
        : {}),
    },
  };
}

function resolveProtectedPaths({ inputPaths = [], policy } = {}) {
  const policyPaths = policy?.repository?.protected_paths || [];
  return uniquePolicyPaths([
    ...DEFAULT_PROTECTED_PATHS,
    ...(Array.isArray(policyPaths) ? policyPaths : []),
    ...inputPaths,
  ]);
}

function uniquePolicyPaths(paths) {
  const seen = new Set();
  const result = [];
  for (const path of paths) {
    const value = String(path || "").trim();
    if (!value || seen.has(value)) continue;
    seen.add(value);
    result.push(value);
  }
  return result;
}

function buildPolicyEvidence(basePolicy) {
  if (!basePolicy?.text) return undefined;
  const parsed = parseRepositoryPolicy(basePolicy.text);
  return {
    source: basePolicy.source,
    path: basePolicy.path,
    ref: basePolicy.ref,
    hash: hashPolicy(basePolicy.text),
    protected_paths: parsed.repository.protected_paths || [],
    allowed_base_branches: parsed.repository.allowed_base_branches || [],
    require_pinned_actions: Boolean(parsed.github.require_pinned_actions),
  };
}

function repositoryPolicyFindings({ policy, baseBranch } = {}) {
  const allowedBaseBranches = policy?.repository?.allowed_base_branches;
  if (
    !baseBranch ||
    !Array.isArray(allowedBaseBranches) ||
    allowedBaseBranches.length === 0 ||
    matchesAny(
      normalizeLegacyWildcardAllowlist(allowedBaseBranches),
      baseBranch,
    )
  ) {
    return [];
  }

  return [
    {
      code: "OAP.REPO.BASE_BRANCH_FORBIDDEN",
      severity: "high",
      message: `Base branch ${baseBranch} is not allowed by trusted repository policy.`,
    },
  ];
}

function normalizeLegacyWildcardAllowlist(patterns) {
  return (patterns || [])
    .map((pattern) => String(pattern || "").trim())
    .filter(Boolean)
    .map((pattern) => (pattern === "*" ? "**" : pattern));
}

function hashPolicy(source) {
  return `sha256:${createHash("sha256").update(source).digest("hex")}`;
}

function readYamlList(source, path) {
  const lines = String(source || "").split(/\r?\n/);
  const keyInfo = findYamlPath(lines, path);
  if (!keyInfo) {
    const inlineValue = readInlineObjectPathValue(lines, path);
    return inlineValue === undefined ? [] : parseYamlListValue(inlineValue);
  }

  const inline = parseYamlListValue(keyInfo.value);
  if (inline.length) return inline;

  const values = [];
  for (let i = keyInfo.index + 1; i < lines.length; i += 1) {
    const line = stripComment(lines[i]);
    if (!line.trim()) continue;
    const indent = countIndent(line);
    if (indent <= keyInfo.indent) break;
    const item = line.trim().match(/^-\s+(.+)$/);
    if (item) values.push(cleanYamlScalar(item[1]));
  }
  return values.filter(Boolean);
}

function readYamlBoolean(source, path) {
  const lines = String(source || "").split(/\r?\n/);
  const keyInfo = findYamlPath(lines, path);
  const rawValue =
    keyInfo?.value || readInlineObjectPathValue(lines, path) || "";
  if (!rawValue) return undefined;
  const value = cleanYamlScalar(rawValue).toLowerCase();
  if (value === "true") return true;
  if (value === "false") return false;
  return undefined;
}

function findYamlPath(lines, path) {
  let startIndex = 0;
  let parentIndent = -1;

  for (const segment of path) {
    let found = null;
    for (let i = startIndex; i < lines.length; i += 1) {
      const line = stripComment(lines[i]);
      if (!line.trim()) continue;
      const indent = countIndent(line);
      if (parentIndent >= 0 && indent <= parentIndent) break;
      const match = line
        .trim()
        .match(/^["']?([A-Za-z0-9_-]+)["']?\s*:\s*(.*)$/);
      if (match && match[1] === segment) {
        found = { index: i, indent, value: match[2].trim() };
        break;
      }
    }
    if (!found) return null;
    startIndex = found.index + 1;
    parentIndent = found.indent;
    if (segment === path[path.length - 1]) return found;
  }

  return null;
}

function readInlineObjectPathValue(lines, path) {
  if (!Array.isArray(path) || path.length < 2) return undefined;
  const parent = findYamlPath(lines, path.slice(0, -1));
  if (!parent?.value) return undefined;
  return readInlineObjectValue(parent.value, path[path.length - 1]);
}

function readInlineObjectValue(value, key) {
  const match = String(value || "").trim().match(/^\{(.*)\}$/);
  if (!match) return undefined;

  for (const entry of splitInlineYaml(match[1])) {
    const separator = entry.indexOf(":");
    if (separator < 0) continue;
    const entryKey = cleanYamlScalar(entry.slice(0, separator));
    if (entryKey === key) return entry.slice(separator + 1).trim();
  }

  return undefined;
}

function parseYamlListValue(value) {
  const inline = String(value || "").trim().match(/^\[(.*)\]$/);
  if (!inline) return [];
  return splitInlineYaml(inline[1]).map(cleanYamlScalar).filter(Boolean);
}

function splitInlineYaml(value) {
  const entries = [];
  let current = "";
  let quote = "";
  let depth = 0;

  for (const char of String(value || "")) {
    if ((char === "\"" || char === "'") && !quote) {
      quote = char;
    } else if (char === quote) {
      quote = "";
    } else if (!quote && (char === "[" || char === "{")) {
      depth += 1;
    } else if (!quote && (char === "]" || char === "}")) {
      depth = Math.max(0, depth - 1);
    }

    if (char === "," && !quote && depth === 0) {
      entries.push(current.trim());
      current = "";
    } else {
      current += char;
    }
  }

  if (current.trim()) entries.push(current.trim());
  return entries;
}

function stripComment(line) {
  const value = String(line || "");
  let quoted = false;
  let quote = "";
  for (let i = 0; i < value.length; i += 1) {
    const char = value[i];
    if ((char === "\"" || char === "'") && value[i - 1] !== "\\") {
      if (!quoted) {
        quoted = true;
        quote = char;
      } else if (quote === char) {
        quoted = false;
        quote = "";
      }
    }
    if (char === "#" && !quoted) return value.slice(0, i);
  }
  return value;
}

function countIndent(line) {
  return String(line || "").match(/^\s*/)[0].length;
}

function cleanYamlScalar(value) {
  return String(value || "")
    .trim()
    .replace(/^["']|["']$/g, "")
    .trim();
}

module.exports = {
  POLICY_PATHS,
  buildPolicyEvidence,
  parseRepositoryPolicy,
  repositoryPolicyFindings,
  resolveProtectedPaths,
};

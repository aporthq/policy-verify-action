function normalizePath(value) {
  return normalizePatternPath(value);
}

function normalizePatternPath(value) {
  return String(value || "")
    .replace(/\\/g, "/")
    .replace(/^\/+/, "")
    .split("/")
    .filter((part) => part && part !== ".")
    .join("/");
}

function normalizeRepositoryPath(value) {
  const raw = String(value || "").trim().replace(/^\.\/+/, "");
  if (!raw || raw.startsWith("/") || raw.includes("\0")) return "";
  const normalized = raw
    .replace(/\/+/g, "/")
    .split("/")
    .filter((part) => part && part !== ".")
    .join("/");
  return normalized;
}

function escapeRegex(value) {
  return value.replace(/[|\\{}()[\]^$+?.]/g, "\\$&");
}

function patternToRegex(pattern) {
  const normalized = normalizePatternPath(pattern);
  let source = "";

  for (let i = 0; i < normalized.length; i += 1) {
    const char = normalized[i];
    const next = normalized[i + 1];

    if (char === "*" && next === "*") {
      const after = normalized[i + 2];
      if (after === "/") {
        source += "(?:.*/)?";
        i += 2;
      } else {
        source += ".*";
        i += 1;
      }
    } else if (char === "*") {
      source += "[^/]*";
    } else {
      source += escapeRegex(char);
    }
  }

  return new RegExp(`^${source}$`);
}

function isSafePath(value) {
  const parts = normalizeRepositoryPath(value).split("/");
  return !parts.includes("..");
}

function matchesGlob(pattern, value) {
  if (!pattern || !value || !isSafePath(value)) return false;
  return patternToRegex(pattern).test(normalizeRepositoryPath(value));
}

function matchesAny(patterns, value) {
  return (patterns || []).some((pattern) => matchesGlob(pattern, value));
}

module.exports = {
  matchesGlob,
  matchesAny,
  normalizePath,
  normalizePatternPath,
  normalizeRepositoryPath,
  patternToRegex,
};

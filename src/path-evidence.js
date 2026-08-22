const DEFAULT_MAX_FILE_EVIDENCE_BYTES = 6000;
const DEFAULT_MAX_FILE_EVIDENCE_COUNT = 200;

function filePathCandidates(file) {
  const paths = [];
  if (typeof file === "string") {
    addPath(paths, file);
    return paths;
  }

  if (!file || typeof file !== "object") return paths;

  addPath(paths, file.filename);
  addPath(paths, file.path);
  addPath(paths, file.previous_filename);

  return paths;
}

function primaryFilePath(file) {
  return filePathCandidates(file)[0] || "";
}

function uniquePaths(paths) {
  const seen = new Set();
  const unique = [];
  for (const path of paths) {
    if (seen.has(path)) continue;
    seen.add(path);
    unique.push(path);
  }
  return unique;
}

function collectChangedFileEvidence(files = [], options = {}) {
  const maxBytes =
    options.maxBytes === undefined
      ? DEFAULT_MAX_FILE_EVIDENCE_BYTES
      : options.maxBytes;
  const maxCount =
    options.maxCount === undefined
      ? DEFAULT_MAX_FILE_EVIDENCE_COUNT
      : options.maxCount;
  const allPaths = uniquePaths(files.flatMap(filePathCandidates));
  const paths = [];
  let usedBytes = 2; // JSON array brackets.

  for (const path of allPaths) {
    const encodedBytes = Buffer.byteLength(JSON.stringify(path), "utf8");
    const separatorBytes = paths.length > 0 ? 1 : 0;
    if (
      paths.length >= maxCount ||
      usedBytes + separatorBytes + encodedBytes > maxBytes
    ) {
      continue;
    }
    paths.push(path);
    usedBytes += separatorBytes + encodedBytes;
  }

  return {
    paths,
    total: allPaths.length,
    omitted: allPaths.length - paths.length,
    capped: paths.length < allPaths.length,
    maxBytes,
    maxCount,
  };
}

function addPath(paths, value) {
  if (typeof value !== "string") return;
  if (value.length === 0 || value.includes("\0")) return;
  if (!paths.includes(value)) paths.push(value);
}

module.exports = {
  DEFAULT_MAX_FILE_EVIDENCE_BYTES,
  DEFAULT_MAX_FILE_EVIDENCE_COUNT,
  collectChangedFileEvidence,
  filePathCandidates,
  primaryFilePath,
  uniquePaths,
};

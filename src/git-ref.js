/**
 * Branch name from a git ref.
 *
 * `refs/heads/main` is `main`. A bare name such as `main` is returned as is,
 * because GITHUB_REF_NAME and pull request `base.ref` already carry a bare
 * name. Any other fully qualified ref (`refs/tags/v1`, `refs/pull/7/merge`)
 * is not a branch and yields an empty string.
 */
function branchFromGitRef(ref) {
  const value = String(ref || "");
  if (value.startsWith("refs/heads/")) return value.slice("refs/heads/".length);
  if (!value.startsWith("refs/")) return value;
  return "";
}

/**
 * True only when the ref is present and is definitely not a branch:
 * `refs/tags/v1`, `refs/pull/7/merge`, and anything else under `refs/` that is
 * not `refs/heads/`.
 *
 * An empty ref is false, not true. "No ref was supplied" and "the ref is a
 * tag" are different facts and only the second one is a reason to skip branch
 * protection, so callers must not read one as the other. This is the same
 * question `fatalRequiresProtectedPush` asks as `ref && !branchFromGitRef(ref)`;
 * it lives here so the two cannot drift.
 */
function isNonBranchRef(ref) {
  const value = String(ref || "");
  if (!value) return false;
  return branchFromGitRef(value) === "";
}

function isZeroSha(value) {
  return /^0{40}$/.test(String(value || ""));
}

module.exports = { branchFromGitRef, isNonBranchRef, isZeroSha };

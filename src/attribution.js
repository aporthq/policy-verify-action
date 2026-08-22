const TRAILER_RE = /^([A-Za-z0-9-]+):\s*(.+)$/;

const KNOWN_BOTS = new Set([
  "dependabot[bot]",
  "renovate[bot]",
  "github-actions[bot]",
  "copilot-swe-agent[bot]",
]);

const AGENT_BRANCH_PREFIXES = ["claude/", "cursor/", "codex/", "devin/", "copilot/"];

const AGENT_MARKERS = [
  { name: "claude-code", patterns: [/generated with .*claude code/i, /co-authored-by:\s*claude\b/i] },
  { name: "cursor", patterns: [/co-authored-by:\s*cursor\b/i, /generated with .*cursor/i] },
  { name: "codex", patterns: [/co-authored-by:\s*codex\b/i, /generated with .*codex/i] },
  { name: "devin", patterns: [/co-authored-by:\s*devin\b/i, /generated with .*devin/i] },
];

const AGENT_EMAIL_DOMAINS = new Map([
  ["anthropic.com", "claude-code"],
  ["claude.ai", "claude-code"],
  ["cursor.com", "cursor"],
  ["cursor.sh", "cursor"],
  ["openai.com", "codex"],
  ["cognition.ai", "devin"],
  ["devin.ai", "devin"],
]);

const AGENT_EMAIL_LOCALS = new Set([
  "agent",
  "bot",
  "noreply",
  "no-reply",
  "claude",
  "claude-code",
  "cursor",
  "cursor-agent",
  "codex",
  "codex-agent",
  "devin",
  "devin-ai",
]);

function normalize(value) {
  return String(value || "").trim();
}

function parseTrailers(message) {
  const trailers = {};
  for (const line of normalize(message).split(/\r?\n/)) {
    const match = line.match(TRAILER_RE);
    if (match) {
      trailers[match[1].toLowerCase()] = match[2].trim();
    }
  }
  return trailers;
}

function commitText(commit) {
  const parts = [
    commit.message,
    commit.commit?.message,
    commit.author?.email,
    commit.committer?.email,
    commit.commit?.author?.email,
    commit.commit?.committer?.email,
  ];
  return parts.filter(Boolean).join("\n");
}

function commitEmails(commit) {
  return [
    commit.author?.email,
    commit.committer?.email,
    commit.commit?.author?.email,
    commit.commit?.committer?.email,
  ].filter(Boolean);
}

function agentEmailHit(commits) {
  for (const commit of commits) {
    for (const rawEmail of commitEmails(commit)) {
      const email = normalize(rawEmail).toLowerCase();
      const match = email.match(/^([^@\s<>]+)@([^@\s<>]+)$/);
      if (!match) continue;

      const [, local, domain] = match;
      const agent = AGENT_EMAIL_DOMAINS.get(domain);
      if (!agent) continue;

      if (AGENT_EMAIL_LOCALS.has(local) || local.includes("agent") || local.endsWith("bot")) {
        return { agent, email };
      }
    }
  }
  return null;
}

function checked(name, hit, detail = "") {
  return { name, hit: Boolean(hit), detail };
}

function classify(input) {
  const actor = normalize(input.actor).toLowerCase();
  const actorType = normalize(input.actorType).toLowerCase();
  const appSlug = normalize(input.appSlug).toLowerCase();
  const headRef = normalize(input.headRef).toLowerCase();
  const commits = Array.isArray(input.commits) ? input.commits : [];
  const signals = [];

  for (const commit of commits) {
    const trailers = parseTrailers(commit.message || commit.commit?.message || "");
    const hasAportTrailer = trailers["aport-decision"] || trailers["aport-session"] || trailers["aport-agent"];
    signals.push(checked("aport_commit_trailer", hasAportTrailer, hasAportTrailer ? JSON.stringify({
      agent: trailers["aport-agent"] || "",
      decision: trailers["aport-decision"] || "",
      session: trailers["aport-session"] || "",
    }) : ""));
    if (hasAportTrailer) {
      return {
        class: "coding_agent",
        confidence: "high",
        agent: trailers["aport-agent"] || "aport-agent",
        signals,
      };
    }
  }

  const botHit = KNOWN_BOTS.has(actor) || KNOWN_BOTS.has(appSlug);
  signals.push(checked("known_bot_slug", botHit, botHit ? (actor || appSlug) : ""));
  if (botHit) {
    return { class: "known_bot", confidence: "high", signals };
  }

  for (const marker of AGENT_MARKERS) {
    const textHit = commits.some((commit) => marker.patterns.some((pattern) => pattern.test(commitText(commit))));
    signals.push(checked(`agent_marker:${marker.name}`, textHit));
    if (textHit) {
      return { class: "coding_agent", confidence: "high", agent: marker.name, signals };
    }
  }

  const emailHit = agentEmailHit(commits);
  signals.push(checked("agent_domain_email", emailHit, emailHit ? emailHit.email : ""));
  if (emailHit) {
    return { class: "coding_agent", confidence: "medium", agent: emailHit.agent, signals };
  }

  const branchPrefix = AGENT_BRANCH_PREFIXES.find((prefix) => headRef.startsWith(prefix));
  signals.push(checked("agent_branch_prefix", branchPrefix, branchPrefix || ""));
  if (branchPrefix) {
    return { class: "coding_agent", confidence: "medium", agent: branchPrefix.replace("/", ""), signals };
  }

  const unknownBot = actorType === "bot";
  signals.push(checked("unknown_bot_actor_type", unknownBot, unknownBot ? actorType : ""));
  if (unknownBot) {
    return { class: "unknown_automation", confidence: "medium", signals };
  }

  signals.push(checked("default_human", true));
  return { class: "human", confidence: "high", signals };
}

module.exports = { classify, parseTrailers };

// Pi coding-agent extension — intrupt approval gate.
//
// Gates high-risk tool calls behind a human approval. Before Pi runs a
// destructive shell command or writes/edits a file, this extension POSTs to the
// intrupt API (which notifies the approver via Slack), polls for a decision,
// and returns { block: true, reason } to block the tool if it is rejected /
// times out / errors.
//
// Pi extension contract:
//   - Default-export a factory function receiving the ExtensionAPI (`pi`).
//   - Register the `tool_call` hook, which fires BEFORE a tool executes and is
//     async-capable.
//   - Block by RETURNING { block: true, reason: "..." } from the handler.
//     Returning nothing (undefined) allows the call.
//   - File lives in ~/.pi/agent/extensions/*.ts (global) or .pi/extensions/*.ts
//     (project). Loaded via jiti, so plain-JS syntax is fine.
//
// This file is intentionally written in plain-JS-compatible syntax (no TS type
// annotations) so it doubles as a runnable module for the offline smoke tests.
//
// FAIL CLOSED: any error, timeout, or unreachable API returns { block: true }.
// The handler is wrapped so ANY unexpected exception becomes a block — Pi can
// never fail open.
//
// Config via environment variables (see .env.example):
//   AEGMIS_BASE_URL, AEGMIS_API_KEY (required)
//   AEGMIS_FORWARD_ALL, AEGMIS_TIMEOUT, AEGMIS_POLL_INTERVAL, AEGMIS_CHANNEL,
//   AEGMIS_BYPASS_PATTERNS, AEGMIS_PROTECTED_PATHS, AEGMIS_BLOCKED_PATHS,
//   AEGMIS_APPROVAL (optional)

import { resolve, join, normalize, isAbsolute } from "node:path";
import { homedir } from "node:os";

const env = (typeof process !== "undefined" && process.env) || {};

const BASE_URL = (env.AEGMIS_BASE_URL || "https://api.aegmis.com").replace(/\/+$/, "");
const API_KEY = env.AEGMIS_API_KEY || "";
const TIMEOUT = parseInt(env.AEGMIS_TIMEOUT || "600", 10);
const POLL_INTERVAL = parseInt(env.AEGMIS_POLL_INTERVAL || "5", 10);
// Approval delivery channel: "slack" (default) or "email".
const CHANNEL = env.AEGMIS_CHANNEL || "slack";
// When true (default), forward every gated tool call to the Aegmis policy engine
// and let server-side policies decide — unmatched calls are auto-approved. When
// false, fall back to the local SHELL_GATE_PATTERNS pre-filter. A few hard local
// gates (workspace wipe, self-protection, AEGMIS_BLOCKED_PATHS) always apply, in
// BOTH modes.
const FORWARD_ALL = ["1", "true", "yes"].includes((env.AEGMIS_FORWARD_ALL || "true").toLowerCase());
// Kill switch: AEGMIS_APPROVAL=false disables the gate entirely (allow all).
const APPROVAL_ENABLED = !["0", "false", "no", "off", "disable", "disabled"].includes(
  (env.AEGMIS_APPROVAL || "true").toLowerCase()
);

const HOME = homedir();

const SHELL_TOOL = "bash";
const COMMAND_KEYS = ["command", "cmd", "script"];
const PATH_KEYS = ["file_path", "filePath", "path", "filename", "file"];
const CONTENT_KEYS = ["content", "new_str", "new_string", "new_text", "contents", "patch"];

// Shell commands matching ANY of these patterns require approval. Evaluated per
// command SEGMENT (a chain like `a && b | c ; d` is split on && || ; & and
// newlines; pipelines stay intact) so a benign command can't shield a risky one.
const SHELL_GATE_PATTERNS = [
  // Catastrophic deletions — home/root/system dirs or a bare */./..  (Project /
  // workspace wipes are handled separately by rmHitsWorkspace, which resolves the
  // target against cwd and so also catches ./ , "$PWD", quoted "$HOME", etc.)
  /\brm\b[\s\S]*\s(~\/?(\s|$)|\$\{?HOME\}?\/?(\s|$)|\/(\s|$)|\/\*|\/(Users|home)\/[^\/\s]+\/?(\s|$)|\/(etc|usr|var|bin|sbin|opt|System|Library|private|boot|dev|lib|sys|proc)(\/|\s|$)|\*(\s|$)|\.(\s|$)|\.\.(\/|\s|$))/i,
  // ── Destructive / mass deletes beyond plain rm ─────────────────────────────
  /\bfind\b[\s\S]*\s-delete\b/i,
  /\bfind\b[\s\S]*-exec\s+rm\b/i,
  /\bgit\s+clean\s+-[a-z]*f/i,          // git clean -f / -fd / -fdx
  /\brsync\b[\s\S]*--delete\b/i,
  /\bshred\b/i,
  /\bunlink\b\s/i,
  // ── History / repo rewrites ────────────────────────────────────────────────
  /\bgit\s+reset\s+--hard\b/i,
  /\bgit\s+(rebase|filter-branch|filter-repo)\b/i,
  /\bgit\s+branch\s+-D\b/i,
  // ── Code / data egress (exfiltration) ──────────────────────────────────────
  /\bgit\s+push\b/i,                    // any git push (including --force)
  /\bgit\s+remote\s+(add|set-url)\b/i,  // re-point a remote (then push elsewhere)
  /\bgh\s+repo\s+create\b/i,            // can publish a repo (--public --push)
  /\bgh\s+repo\s+edit\b[\s\S]*--visibility/i,
  /\bgh\s+gist\s+create\b/i,            // public gist = code leak
  /\bgh\s+pr\s+merge\b/i,
  /\bgh\s+release\b/i,
  /\bcurl\b[\s\S]*(\s-T\b|--upload-file\b|\s-F\b|--form\b|--data-binary\s*@|\s-d\s*@|--data\s*@)/i,
  /\bwget\b[\s\S]*--post-file\b/i,
  /\bscp\b\s/i,                         // copy off-box
  /\brsync\b[\s\S]*\s[^\s]+@[^\s:]+:/i, // rsync to user@host:
  /\b(nc|ncat|netcat)\b\s/i,            // netcat pipe-out
  // ── Publish / release / deploy ─────────────────────────────────────────────
  /\bnpm\s+publish\b/i,
  /\b(pip|twine)\s+upload\b|\btwine\s+upload\b/i,
  /\b(cargo\s+publish|gem\s+push|poetry\s+publish)\b/i,
  /\bdocker\s+(push|login)\b/i,
  /\bdeploy\b/i,
  /\bkubectl\s+delete\b/i,
  /\bkubectl\s+apply\b/i,
  /\bterraform\s+apply\b/i,
  /\bterraform\s+destroy\b/i,
  // ── Database ───────────────────────────────────────────────────────────────
  /DROP\s+(TABLE|DATABASE|SCHEMA)/i,
  /TRUNCATE\s+TABLE/i,
  // ── Disk / device ──────────────────────────────────────────────────────────
  /\bdd\s+if=/i,
  /\b(mkfs|wipefs|fdisk)\b/i,
  />\s*\/dev\/(sd|nvme|disk|hd)/i,
  // ── Privilege / perms ──────────────────────────────────────────────────────
  /\bsudo\b/i,
  /\bchmod\s+[0-7]*7[0-7][0-7]\b/i,     // world-writable
  /\bchown\b.*root/i,
  // ── Remote-to-shell & obfuscation (denylists can't see through these; gate) ─
  /\|\s*(ba|z|k)?sh\b/i,                // ANY pipe to a shell (curl|sh, echo|sh…)
  /\bbase64\b[\s\S]*(-d|-D|--decode)\b/i, // decode-then-run smell
  /\beval\b/i,
  /\b(ba|z|k)?sh\s+-c\b/i,              // sh -c "…" wrapper
  /\bxargs\b[\s\S]*\brm\b/i,
  /\bpython[0-9.]*\b[\s\S]*-c\b[\s\S]*(rmtree|os\.remove|os\.unlink|shutil)/i,
  /\bperl\b[\s\S]*-e\b[\s\S]*unlink/i,
];

// User-defined protected paths (AEGMIS_PROTECTED_PATHS) — literal entries also
// get a raw-command fallback pattern (regex entries are handled by _PROTECTED_REGEX).
for (const _pp of (env.AEGMIS_PROTECTED_PATHS || "").split(",")) {
  const _t = _pp.trim();
  if (_t && !_t.startsWith("re:")) {
    const _esc = _t.replace(/\/+$/, "").replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    SHELL_GATE_PATTERNS.push(new RegExp("\\brm\\b[\\s\\S]*\\s" + _esc + "(/|\\s|$)", "i"));
  }
}

// ── Path helpers (mirror the Python hook's _tokenize / _expand / _resolve) ──────

// Shell-aware token split (handles single/double quotes and backslash escapes);
// falls back to a plain whitespace split on unbalanced quotes.
function tokenizeStrict(command) {
  const tokens = [];
  let cur = "";
  let quote = null;
  let has = false;
  for (let i = 0; i < command.length; i++) {
    const c = command[i];
    if (quote) {
      if (c === quote) {
        quote = null;
      } else if (quote === '"' && c === "\\" && i + 1 < command.length) {
        i++;
        cur += command[i];
      } else {
        cur += c;
      }
    } else if (c === "'" || c === '"') {
      quote = c;
      has = true;
    } else if (c === "\\" && i + 1 < command.length) {
      i++;
      cur += command[i];
      has = true;
    } else if (/\s/.test(c)) {
      if (has) {
        tokens.push(cur);
        cur = "";
        has = false;
      }
    } else {
      cur += c;
      has = true;
    }
  }
  if (quote) throw new Error("unbalanced quote");
  if (has) tokens.push(cur);
  return tokens;
}

function tokenize(command) {
  try {
    return tokenizeStrict(command);
  } catch {
    return command.split(/\s+/).filter(Boolean);
  }
}

// Expand ~, $HOME/${HOME}, $PWD/${PWD} the way the shell would.
function expand(path, cwd) {
  let p = path;
  const pwd = cwd || ".";
  p = p.split("${PWD}").join(pwd).split("$PWD").join(pwd);
  p = p.split("${HOME}").join(HOME).split("$HOME").join(HOME);
  if (p === "~") p = HOME;
  else if (p.startsWith("~/")) p = HOME + p.slice(1);
  return p;
}

// Resolve a path token to a normalized absolute path against cwd.
function resolvePath(path, cwd) {
  let p = expand(path, cwd);
  if (!isAbsolute(p)) p = join(cwd || ".", p);
  return normalize(p).replace(/\/+$/, "") || "/";
}

// Candidate path tokens from a command (skip flags / verbs / redirection ops).
const _SKIP_TOKENS = new Set([
  "rm", "sudo", "--", "mv", "cp", "tee", "sed", "ln", "chmod", "chown",
  "install", "touch", "cat", "&&", "||", ";", "|",
]);
function pathTokens(command) {
  const out = [];
  for (const tok of tokenize(command)) {
    let t = tok.replace(/^[<>&|]+/, ""); // strip redirection glyphs (>file, 2>&1…)
    t = t.replace(/^['"]+|['"]+$/g, "");
    if (!t || t.startsWith("-") || _SKIP_TOKENS.has(t)) continue;
    out.push(t);
  }
  return out;
}

const _STATE = { cwd: "" };

// ── Protected / blocked path config (cwd-aware, literal + re: regex) ────────────

const _PROTECTED_LITERAL = [];
const _PROTECTED_REGEX = [];
const _BLOCKED_LITERAL = [];
const _BLOCKED_REGEX = [];

function loadPathList(raw, literals, regexes, label) {
  for (const _pp of (raw || "").split(",")) {
    const _t = _pp.trim();
    if (!_t) continue;
    if (_t.startsWith("re:")) {
      try {
        regexes.push(new RegExp(_t.slice(3)));
      } catch (e) {
        console.error(`[intrupt hook] ignoring invalid ${label} regex ${JSON.stringify(_t.slice(3))}: ${e && e.message}`);
      }
    } else {
      const _p = _t.replace(/\/+$/, "");
      const _abs = _p.startsWith("~") ? HOME + _p.slice(1) : _p;
      literals.push(normalize(_abs).replace(/\/+$/, "") || "/");
    }
  }
}
loadPathList(env.AEGMIS_PROTECTED_PATHS, _PROTECTED_LITERAL, _PROTECTED_REGEX, "AEGMIS_PROTECTED_PATHS");
loadPathList(env.AEGMIS_BLOCKED_PATHS, _BLOCKED_LITERAL, _BLOCKED_REGEX, "AEGMIS_BLOCKED_PATHS");

// True if an rm target (resolved against cwd) matches a literal path (dir + subtree)
// or a `re:` regex (tested against the resolved absolute path).
function rmHits(command, literals, regexes) {
  if ((!literals.length && !regexes.length) || !/\brm\b/.test(command)) return false;
  for (const t of pathTokens(command)) {
    const cand = resolvePath(t, _STATE.cwd);
    for (const prot of literals) if (cand === prot || cand.startsWith(prot + "/")) return true;
    for (const rx of regexes) if (rx.test(cand)) return true;
  }
  return false;
}
function rmHitsProtected(command) {
  return rmHits(command, _PROTECTED_LITERAL, _PROTECTED_REGEX);
}
function rmHitsBlocked(command) {
  return rmHits(command, _BLOCKED_LITERAL, _BLOCKED_REGEX);
}

// Write/create gate for AEGMIS_PROTECTED_PATHS — gate not just `rm` of a protected
// path but also file CREATION / writes INTO it (touch, tee, cp/mv, `>`/`>>`
// redirection). Scoped to protected dirs only, so writes elsewhere stay free.
// Mirrors the rm-based protected-path gate.
const WRITE_VERB = /\b(touch|tee|cp|mv|install|dd|ln)\b|>\s*\S|>>\s*\S/;

// True if a write/create verb targets a path under a literal dir (+subtree) or a
// `re:` regex.
function writeHits(command, literals, regexes) {
  if ((!literals.length && !regexes.length) || !WRITE_VERB.test(command)) return false;
  for (const t of pathTokens(command)) {
    const cand = resolvePath(t, _STATE.cwd);
    for (const prot of literals) if (cand === prot || cand.startsWith(prot + "/")) return true;
    for (const rx of regexes) if (rx.test(cand)) return true;
  }
  return false;
}
function writeHitsProtected(command) {
  return writeHits(command, _PROTECTED_LITERAL, _PROTECTED_REGEX);
}

// True if a delete targets the whole project — the working dir itself or any
// ancestor of it (or filesystem root). Deleting a SUBDIR (rm -rf build) stays
// free; wiping the project (rm -rf . / ./ / "$PWD" / .. / the cwd path) gates.
function rmHitsWorkspace(command) {
  const cwd = _STATE.cwd;
  if (!cwd) return false;
  if (!/\b(rm|find)\b/.test(command)) return false;
  const cwdN = normalize(cwd).replace(/\/+$/, "") || "/";
  for (const t of pathTokens(command)) {
    const cand = resolvePath(t, cwd);
    if (cand === "/" || cand === cwdN || cwdN.startsWith(cand + "/")) return true;
  }
  return false;
}

// Self-protection: the gate must not let the agent quietly disarm it. Writes,
// deletes, or edits touching the hook's own config/dirs are always gated. (Real
// containment is the OS sandbox — see README — but this closes the obvious
// "edit the extension / .env.intrupt" hole.)
const _SELF_PROTECT = [normalize(join(HOME, ".pi")).replace(/\/+$/, "")];
// Extra self-protect suffixes matched anywhere (project-local .pi, git hooks).
const _SELF_PROTECT_SUFFIX = [".pi", join(".git", "hooks")];
const _MUTATING_VERB = /\b(rm|mv|cp|tee|truncate|dd|chmod|chown|ln|install|touch)\b|\bsed\s+-i|>\s*\S|>>\s*\S/;

function pathUnderSelfProtect(cand) {
  for (const prot of _SELF_PROTECT) if (cand === prot || cand.startsWith(prot + "/")) return true;
  const norm = cand.replace(/\\/g, "/");
  for (const suffix of _SELF_PROTECT_SUFFIX) {
    const s = suffix.replace(/\\/g, "/").replace(/\/+$/, "");
    if (norm === s || (norm + "/").includes("/" + s + "/") || norm.endsWith("/" + s)) return true;
  }
  return false;
}

function hitsSelfProtect(command) {
  if (!_MUTATING_VERB.test(command)) return false;
  for (const t of pathTokens(command)) {
    if (pathUnderSelfProtect(resolvePath(t, _STATE.cwd))) return true;
  }
  return false;
}

// ── Segment splitting + bypass (per-segment) ───────────────────────────────────

// Statement separators for chained commands. We DON'T split on a single pipe so
// that pipe-to-shell patterns (curl … | sh) stay inside one segment.
function segments(command) {
  const segs = command.split(/&&|\|\||;|&(?!&)|\n/).map((s) => s.trim()).filter(Boolean);
  return segs.length ? segs : [command];
}

const BYPASS = (env.AEGMIS_BYPASS_PATTERNS || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean)
  .map((s) => new RegExp(s, "i"));

function segmentBypassed(seg) {
  return BYPASS.some((b) => b.test(seg));
}

// True only if EVERY segment matches a bypass pattern (so a benign segment can't
// waive a chained risky one).
function fullyBypassed(command) {
  if (!BYPASS.length) return false;
  return segments(command).every(segmentBypassed);
}

// Local-mode risk decision, evaluated per command segment so a benign segment
// can't shield a risky one.
function shouldGateShell(command) {
  for (const seg of segments(command)) {
    if (segmentBypassed(seg)) continue;
    if (rmHitsProtected(seg)) return true;
    if (writeHitsProtected(seg)) return true;
    if (SHELL_GATE_PATTERNS.some((re) => re.test(seg))) return true;
  }
  return false;
}

// Local gates that ALWAYS apply, in both forward-all and local mode: hard-blocked
// paths (denied outright), workspace wipes, and self-protection. Returns
// { deny: true } (hard block), { gate: true } (always-ask), or null.
function hardLocalGate(command) {
  if (rmHitsBlocked(command)) return { deny: true };
  if (rmHitsWorkspace(command)) return { gate: true };
  if (hitsSelfProtect(command)) return { gate: true };
  return null;
}

// ── HTTP + helpers ─────────────────────────────────────────────────────────────

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function first(obj, keys) {
  for (const k of keys) {
    const v = obj[k];
    if (typeof v === "string" && v) return v;
  }
  return null;
}

function extractOrgId(apiKey) {
  if (!apiKey.startsWith("sk_org_")) throw new Error("Invalid AEGMIS_API_KEY format");
  const afterPrefix = apiKey.slice(7);
  const last = afterPrefix.lastIndexOf("_");
  if (last === -1) throw new Error("Invalid AEGMIS_API_KEY format");
  const orgId = afterPrefix.slice(0, last);
  if (!orgId.startsWith("org_")) throw new Error(`Could not extract org ID — got '${orgId}'`);
  return orgId;
}

async function api(method, path, body) {
  const res = await fetch(`${BASE_URL}${path}`, {
    method,
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${API_KEY}`,
      "User-Agent": "intrupt-hook/1.0",
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`intrupt API ${method} ${path} → HTTP ${res.status}: ${text}`);
  }
  return res.json();
}

// ── Classification ──────────────────────────────────────────────────────────────

// Pure, synchronous. Returns { gate, action, message, kwargs } / { gate:false } /
// { gate:true, hardBlock:true } (blocked path — denied locally, no API round-trip).
function classify(toolName, input) {
  input = input || {};
  const command = first(input, COMMAND_KEYS);
  if (toolName === SHELL_TOOL || command !== null) {
    const cmd = command || "";
    // Hard local gates apply in BOTH modes (deny blocked / always-ask workspace
    // wipe + self-protect).
    const hard = hardLocalGate(cmd);
    if (hard && hard.deny) return { gate: true, hardBlock: true };
    if (!hard) {
      if (FORWARD_ALL) {
        // Forward everything to the policy engine, but let a FULLY bypassed
        // command short-circuit to avoid a network round-trip.
        if (fullyBypassed(cmd)) return { gate: false };
      } else {
        if (!shouldGateShell(cmd)) return { gate: false };
      }
    }
    const short = (cmd.split("\n")[0] || "").slice(0, 120);
    return { gate: true, action: "bash_command", message: `Run: \`${short}\``, kwargs: input };
  }
  const path = first(input, PATH_KEYS);
  const hasContent = CONTENT_KEYS.some((k) => k in input);
  const looksLikeEdit = /edit|write|create|replace|patch|append|insert/i.test(toolName || "");
  if (path !== null && (hasContent || looksLikeEdit)) {
    return { gate: true, action: "edit_file", message: `Edit file: \`${path}\``, kwargs: input };
  }
  return { gate: false };
}

// Returns undefined (allow) or { block: true, reason } (deny). NEVER throws —
// any error becomes a block so Pi cannot fail open.
async function requireApproval(toolName, input) {
  if (!APPROVAL_ENABLED) return undefined; // AEGMIS_APPROVAL disabled — allow without gating
  try {
    const decision = classify(toolName, input);
    if (!decision.gate) return undefined;
    if (decision.hardBlock) {
      // Denied locally — no approval API round-trip, never sent to a human.
      return {
        block: true,
        reason: "Deletion of a hard-blocked path is denied (AEGMIS_BLOCKED_PATHS) — not sent for approval.",
      };
    }

    if (!API_KEY) throw new Error("AEGMIS_API_KEY is not set");
    const orgId = extractOrgId(API_KEY);

    const threadId =
      (globalThis.crypto && crypto.randomUUID && crypto.randomUUID()) ||
      `${Date.now()}-${Math.round(Math.random() * 1e9)}`;

    const resp = await api("POST", `/org/${orgId}/approval`, {
      thread_id: threadId,
      action: decision.action,
      message: decision.message,
      channel: CHANNEL,
      tool_name: toolName,
      tool_kwargs: decision.kwargs,
      adapter: "pi",
    });

    let status = resp.status || "pending";
    if (status === "approved") return undefined;
    if (status === "rejected" || status === "denied") {
      return { block: true, reason: `[intrupt] Approval rejected (status=${status})` };
    }

    const approvalId = resp.approval_id || resp.audit_id;
    if (!approvalId) throw new Error("API did not return approval_id/audit_id");

    const deadline = Date.now() + TIMEOUT * 1000;
    while (Date.now() < deadline) {
      await sleep(POLL_INTERVAL * 1000);
      const s = await api("GET", `/org/${orgId}/approval/${approvalId}`);
      status = s.status || "pending";
      if (status === "approved") return undefined;
      if (status === "rejected" || status === "denied") {
        return { block: true, reason: `[intrupt] Approval rejected (approval_id=${approvalId})` };
      }
    }
    return {
      block: true,
      reason: `[intrupt] Approval timed out after ${TIMEOUT}s — tool call blocked (approval_id=${approvalId}).`,
    };
  } catch (e) {
    // Fail closed: any error blocks the tool.
    return { block: true, reason: `[intrupt hook error] ${e && e.message ? e.message : e}` };
  }
}

export default function (pi) {
  pi.on("tool_call", async (event, _ctx) => {
    // Wrap EVERYTHING — any unexpected exception must become a block, never a
    // silent allow (fail closed).
    try {
      _STATE.cwd = (event && (event.cwd || event.working_dir)) || (_ctx && _ctx.cwd) || "";
      const toolName = event.toolName || event.tool || event.name || "";
      const input = event.input || event.args || event.arguments || {};
      const decision = await requireApproval(toolName, input);
      if (decision) return decision; // { block: true, reason }
      return undefined; // allow
    } catch (e) {
      return { block: true, reason: `[intrupt hook error] ${e && e.message ? e.message : e}` };
    }
  });
}

// Exported for offline smoke tests (see test.mjs).
export const __test = {
  classify,
  shouldGateShell,
  requireApproval,
  extractOrgId,
  hardLocalGate,
  rmHitsWorkspace,
  hitsSelfProtect,
  tokenize,
  resolvePath,
  pathTokens,
  segments,
  setCwd: (c) => {
    _STATE.cwd = c || "";
  },
};

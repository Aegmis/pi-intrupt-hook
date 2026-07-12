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
//     Returning nothing allows the call.
//   - File lives in ~/.pi/agent/extensions/*.ts (global) or .pi/extensions/*.ts
//     (project). Loaded via jiti, so plain-JS syntax is fine.
//
// This file is intentionally written in plain-JS-compatible syntax (no TS type
// annotations) so it doubles as a runnable module for the offline smoke tests.
//
// Config via environment variables (see .env.example):
//   AEGMIS_BASE_URL, AEGMIS_API_KEY (required)
//   AEGMIS_FORWARD_ALL, AEGMIS_TIMEOUT, AEGMIS_POLL_INTERVAL,
//   AEGMIS_BYPASS_PATTERNS (optional)

import { resolve } from "node:path";
import { homedir } from "node:os";

const env = (typeof process !== "undefined" && process.env) || {};

const BASE_URL = (env.AEGMIS_BASE_URL || "https://api.aegmis.com").replace(/\/+$/, "");
const API_KEY = env.AEGMIS_API_KEY || "";
const TIMEOUT = parseInt(env.AEGMIS_TIMEOUT || "600", 10);
const POLL_INTERVAL = parseInt(env.AEGMIS_POLL_INTERVAL || "5", 10);
const FORWARD_ALL = ["1", "true", "yes"].includes((env.AEGMIS_FORWARD_ALL || "true").toLowerCase());
// Kill switch: AEGMIS_APPROVAL=false disables the gate entirely (allow all).
const APPROVAL_ENABLED = !["0", "false", "no", "off", "disable", "disabled"].includes(
  (env.AEGMIS_APPROVAL || "true").toLowerCase()
);

const SHELL_TOOL = "bash";
const COMMAND_KEYS = ["command", "cmd", "script"];
const PATH_KEYS = ["file_path", "filePath", "path", "filename", "file"];
const CONTENT_KEYS = ["content", "new_str", "new_string", "new_text", "contents", "patch"];

const SHELL_GATE_PATTERNS = [
  // Catastrophic deletions only — home/root/system dirs or a bare */./..  Routine
  // and project-local deletes (rm file, rm -rf node_modules/build) pass through.
  /\brm\b[\s\S]*\s(~\/?(\s|$)|\$\{?HOME\}?\/?(\s|$)|\/(\s|$)|\/\*|\/(Users|home)\/[^\/\s]+\/?(\s|$)|\/(etc|usr|var|bin|sbin|opt|System|Library|private|boot|dev|lib|sys|proc)(\/|\s|$)|\*(\s|$)|\.(\s|$)|\.\.(\/|\s|$))/i,
  /\bgit\s+push\b/i,
  /\bgit\s+reset\s+--hard\b/i,
  /\bgh\s+pr\s+merge\b/i,
  /\bgh\s+release\b/i,
  /\bnpm\s+publish\b/i,
  /\bdeploy\b/i,
  /\bkubectl\s+delete\b/i,
  /\bkubectl\s+apply\b/i,
  /\bterraform\s+apply\b/i,
  /\bterraform\s+destroy\b/i,
  /DROP\s+TABLE/i,
  /TRUNCATE\s+TABLE/i,
  /\bdd\s+if=/i,
  /\bmkfs\b/i,
  /\bsudo\b/i,
  /\bchmod\s+[0-7]*7[0-7][0-7]\b/i,
  /\bchown\b.*root/i,
  /\bcurl\b.*\|\s*(ba)?sh\b/i,
  /\bwget\b.*-O\s*-\b.*\|\s*(ba)?sh\b/i,
];

// User-defined protected paths (AEGMIS_PROTECTED_PATHS) — also gate `rm` of each
// listed path and anything under it, on top of the built-in catastrophic targets.
for (const _pp of (env.AEGMIS_PROTECTED_PATHS || "").split(",")) {
  const _t = _pp.trim();
  if (_t && !_t.startsWith("re:")) {   // literal entry -> raw-command fallback pattern
    const _esc = _t.replace(/\/+$/, "").replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    SHELL_GATE_PATTERNS.push(new RegExp("\\brm\\b[\\s\\S]*\\s" + _esc + "(/|\\s|$)", "i"));
  }
}


// cwd-aware protected-path resolution. Each entry is a LITERAL dir (dir + subtree)
// or, prefixed "re:", a REGEX tested against the resolved absolute rm target.
const _PROTECTED_LITERAL = [];
const _PROTECTED_REGEX = [];
for (const _pp of (env.AEGMIS_PROTECTED_PATHS || "").split(",")) {
  const _t = _pp.trim();
  if (!_t) continue;
  if (_t.startsWith("re:")) {
    try { _PROTECTED_REGEX.push(new RegExp(_t.slice(3))); }
    catch (e) { console.error(`[intrupt hook] ignoring invalid AEGMIS_PROTECTED_PATHS regex ${JSON.stringify(_t.slice(3))}: ${e.message}`); }
  } else {
    const _p = _t.replace(/\/+$/, "");
    _PROTECTED_LITERAL.push(resolve(_p.startsWith("~") ? homedir() + _p.slice(1) : _p));
  }
}
const _STATE = { cwd: "" };
function rmHitsProtected(command) {
  if ((!_PROTECTED_LITERAL.length && !_PROTECTED_REGEX.length) || !/\brm\b/.test(command)) return false;
  for (let tok of command.split(/\s+/)) {
    tok = tok.replace(/^['"]|['"]$/g, "");
    if (!tok || tok === "rm" || tok === "sudo" || tok === "--" || tok.startsWith("-")) continue;
    const t = tok.startsWith("~") ? homedir() + tok.slice(1) : tok;
    const cand = resolve(_STATE.cwd || ".", t).replace(/\/+$/, "");
    for (const prot of _PROTECTED_LITERAL) if (cand === prot || cand.startsWith(prot + "/")) return true;
    for (const rx of _PROTECTED_REGEX) if (rx.test(cand)) return true;
  }
  return false;
}

const BYPASS = (env.AEGMIS_BYPASS_PATTERNS || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean)
  .map((s) => new RegExp(s, "i"));

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

function bypassed(command) {
  return BYPASS.some((re) => re.test(command));
}

function shouldGateShell(command) {
  if (bypassed(command)) return false;
  if (rmHitsProtected(command)) return true;
  return SHELL_GATE_PATTERNS.some((re) => re.test(command));
}

// Pure, synchronous. Returns { gate, action, message, kwargs } or { gate:false }.
function classify(toolName, input) {
  input = input || {};
  const command = first(input, COMMAND_KEYS);
  if (toolName === SHELL_TOOL || command !== null) {
    const cmd = command || "";
    if (FORWARD_ALL) {
      if (bypassed(cmd)) return { gate: false };
    } else if (!shouldGateShell(cmd)) {
      return { gate: false };
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

    if (!API_KEY) throw new Error("AEGMIS_API_KEY is not set");
    const orgId = extractOrgId(API_KEY);

    const threadId =
      (globalThis.crypto && crypto.randomUUID && crypto.randomUUID()) ||
      `${Date.now()}-${Math.round(Math.random() * 1e9)}`;

    const resp = await api("POST", `/org/${orgId}/approval`, {
      thread_id: threadId,
      action: decision.action,
      message: decision.message,
      channel: "slack",
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
    _STATE.cwd = (event && (event.cwd || event.working_dir)) || (_ctx && _ctx.cwd) || "";
    const toolName = event.toolName || event.tool || event.name || "";
    const input = event.input || event.args || event.arguments || {};
    const decision = await requireApproval(toolName, input);
    if (decision) return decision; // { block: true, reason }
    return undefined; // allow
  });
}

// Exported for offline smoke tests (see test.mjs).
export const __test = { classify, shouldGateShell, requireApproval, extractOrgId };

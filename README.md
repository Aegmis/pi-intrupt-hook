# pi-intrupt-hook

A [Pi](https://github.com/earendil-works/pi) coding-agent extension that gates high-risk tool calls behind a human approval. Before Pi runs a destructive shell command or writes/edits a file, it pauses, notifies your approver via Slack (or any intrupt channel), and waits. The tool only runs if a human clicks **Approve**.

```
Pi coding agent
  └─ wants to run: git push origin main
        │
        ▼
  pi.on("tool_call")  (extension hook, fires before execution)
        │
        ▼
  POST /org/{id}/approval  ──►  intrupt API  ──►  Slack message
        │                                              │
        │  poll every 5s                     human clicks Approve / Reject
        │                                              │
        ▼                                              ▼
  GET /approval/{id}  ◄──────────────────────  status = "approved"
        │
        ▼
  return undefined            →  Pi continues
  return { block: true, … }   →  Pi is blocked (reason shown to the agent)
```

Unlike the script-based intrupt hooks, Pi uses a **TypeScript extension**. The `tool_call` hook is `async` and fires before execution, so the extension `await`s the approval round-trip and **returns a decision object** to allow or block.

---

## Prerequisites

- Pi (`packages/coding-agent`) with extension support (`~/.pi/agent/extensions/`)
- Node.js 18+ / Bun runtime (provides a global `fetch`)
- An [Aegmis](https://aegmis.com) account with an API key
- Slack workspace connected to your Aegmis org (for the default channel)

---

## Installation

```bash
curl -fsSL https://raw.githubusercontent.com/Aegmis/pi-intrupt-hook/main/install.sh | bash
```

<details>
<summary>Prefer to clone first?</summary>

```bash
git clone https://github.com/Aegmis/pi-intrupt-hook.git
cd pi-intrupt-hook
bash install.sh
```

</details>

`install.sh`:

1. Copies `intrupt.ts` to `~/.pi/agent/extensions/intrupt.ts` (auto-discovered by Pi)
2. Creates `~/.pi/agent/.env.intrupt` with placeholder env vars

Then fill in your credentials and **restart Pi**:

```bash
nano ~/.pi/agent/.env.intrupt
source ~/.pi/agent/.env.intrupt   # add this to ~/.zshrc or ~/.bashrc too
```

Verify the extension loads:

```bash
pi -e ~/.pi/agent/extensions/intrupt.ts
```

Project-scoped install instead? Drop `intrupt.ts` into `<repo>/.pi/extensions/`.

---

## How it works

Pi calls the `tool_call` hook before every tool executes. The extension inspects `event.toolName` and `event.input`:

- a **`command`** (or `cmd`/`script`) string → treated as a **shell command**
- a **file path** key **plus** content, or an edit-like tool name → treated as a **file write/edit**
- anything else (reads, listings, searches) → **allowed** immediately

Shell commands are checked against a risk-pattern list in local mode (**catastrophic `rm`** targeting home/root/system dirs — routine & project-local deletes pass, `git push`, `sudo`, `terraform apply`, `curl … | sh`, etc.); writes/edits are always gated. In **forward-all mode** (the default), every gated call is sent to the Aegmis policy engine instead.

| Outcome | Extension returns | Pi |
|---|---|---|
| Human clicks **Approve** | `undefined` | Tool runs normally |
| Human clicks **Reject** | `{ block: true, reason }` | Tool blocked, reason shown to agent |
| Timeout (default 10 min) | `{ block: true, reason }` | Tool blocked |
| API unreachable / any error | `{ block: true, reason }` | Tool blocked (fail closed) |

The handler **never throws** — every error path returns a `block` decision, so Pi cannot fail open.

---

## Configuration

| Variable | Required | Default | Description |
|---|---|---|---|
| `AEGMIS_BASE_URL` | yes | — | intrupt API base URL |
| `AEGMIS_API_KEY` | yes | — | API key from Account → API Keys |
| `AEGMIS_APPROVAL` | no | `true` | Master kill switch — set `false` to disable the gate entirely (allow all) |
| `AEGMIS_FORWARD_ALL` | no | `true` | Forward every gated call to the policy engine (unmatched auto-approve) |
| `AEGMIS_TIMEOUT` | no | `600` | Max seconds to wait for a decision |
| `AEGMIS_POLL_INTERVAL` | no | `5` | Seconds between status polls |
| `AEGMIS_BYPASS_PATTERNS` | no | — | Comma-separated regex; matching shell commands skip approval |
| `AEGMIS_PROTECTED_PATHS` | no | — | Comma-separated dirs to also gate `rm` on (dir + subtree), on top of built-in home/root/system targets |

---

## Example: catastrophic-deletion gate + protecting your own paths

In **local mode** (`AEGMIS_FORWARD_ALL=false`) the hook gates only *catastrophic*
deletions and lets routine ones run untouched:

```bash
rm abc.txt                 # runs   — routine single-file delete
rm -rf node_modules        # runs   — project-local
rm -rf ~                   # ⛔ approval — wipes home
rm -rf /                   # ⛔ approval — wipes root
rm *                       # ⛔ approval — bare glob
```

To also require approval before deleting **specific dirs of yours**, list them:

```bash
export AEGMIS_PROTECTED_PATHS=/Users/you/work,/Users/you/important
```

Targets are resolved against the command's working directory, so relative refs are
caught too:

```bash
# with AEGMIS_PROTECTED_PATHS=/Users/you/work
cd /Users/you && rm -rf ./work     # ⛔ approval  (./work → /Users/you/work)
rm -rf /Users/you/work/build       # ⛔ approval  (under a protected dir)
rm -rf /Users/you/other            # runs        — not protected
```

---

## Testing

```bash
node test.mjs
```

The test copies the shipped `intrupt.ts` to a temp `.mjs` and imports it, so it
exercises the real module (classifier, fail-closed behaviour, and the actual
`pi.on("tool_call")` handler wiring). Expected output:

```
[PASS] bash — git push (gated)
...
[PASS] wiring — handler returns block for gated call
[PASS] wiring — handler returns undefined for non-gated call

Results: 15/15 passed ✓
```

> ⚠️ **Verify against your Pi version.** Pi's extension API is young. This
> extension targets the documented contract — default-export factory,
> `pi.on("tool_call", …)`, `event.toolName` / `event.input`, and blocking by
> returning `{ block: true, reason }`. If your Pi build differs, adjust the
> field names in the `default(...)` handler at the bottom of `intrupt.ts`; the
> gating logic above it stays the same. Do a one-time live check (`git push`)
> after install.

---

## Security notes

- **Fails closed**: unreachable API, missing env vars, timeout, or any error returns a `block` decision.
- `AEGMIS_API_KEY` is a `Bearer` token — keep it in `.env.intrupt` with `600` permissions, not in shell history.

---

## Project structure

```
pi-intrupt-hook/
├── intrupt.ts           # the Pi extension
├── test.mjs             # offline smoke tests (node test.mjs)
├── install.sh           # one-line installer
├── policies.example.sh  # example Aegmis approval policies
├── .env.example         # environment variable template
└── README.md
```

---

## Uninstalling

```bash
rm ~/.pi/agent/extensions/intrupt.ts
```

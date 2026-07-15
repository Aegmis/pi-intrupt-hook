# pi-intrupt-hook

A [Pi](https://github.com/earendil-works/pi) coding-agent extension that gates high-risk tool calls behind a human approval. Before Pi runs a destructive shell command or writes/edits a file, it pauses, notifies your approver via Slack (or any intrupt channel), and waits. The tool only runs if a human clicks **Approve**.

```
Pi coding agent
  │
  ├─ rm -rf /home/user          (matches AEGMIS_BLOCKED_PATHS)
  │     ⇒  ⛔ denied locally — no API call, no Slack
  │
  └─ kubectl delete pod nginx   (matches a risk pattern)
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

## Quick start

```bash
# 1. Install
curl -fsSL https://raw.githubusercontent.com/Aegmis/pi-intrupt-hook/main/install.sh | bash

# 2. Set your API key, then load the env
nano ~/.pi/agent/.env.intrupt          # set AEGMIS_API_KEY=sk_org_...
source ~/.pi/agent/.env.intrupt        # also add this line to ~/.zshrc or ~/.bashrc

# 3. Restart Pi — done. High-risk actions now pause for Slack approval.
```

Installer defaults: **local mode**, **shell-only** gating, and deleting the home
dir itself routes to approval (`AEGMIS_PROTECTED_PATHS=re:^$HOME$`). To make a path
**impossible to delete** — denied instantly, never sent to a human — add it to
`AEGMIS_BLOCKED_PATHS` (e.g. `export AEGMIS_BLOCKED_PATHS=re:^$HOME$` in your env file).

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

## What gets gated

Two tiers, evaluated in **local mode** (`AEGMIS_FORWARD_ALL=false`, the installer default):

**Hard-blocked — denied instantly, never sent to a human** (`AEGMIS_BLOCKED_PATHS`)

Only an `rm` whose target (resolved against the command's cwd, so relative paths
count) matches a `AEGMIS_BLOCKED_PATHS` entry. Denied locally with no approval
round-trip. Opt-in — nothing is hard-blocked unless you list it.

**Gated — paused for Slack approval**

The hook ships **20 built-in risk patterns**, identical across all 9 hooks. Several are families (one pattern, many commands), so they cover **30+ distinct dangerous commands**:

| Category | Matches | Passes through |
|---|---|---|
| Catastrophic `rm` | `rm -rf ~`, `rm -rf /`, `rm -rf /Users/you`, `rm *`, `rm -rf .` | `rm file.txt`, `rm -rf node_modules`, `rm -rf build` |
| Protected paths | `rm` of any dir in `AEGMIS_PROTECTED_PATHS` (default `re:^$HOME$`) + its subtree | anything not listed |
| Git | `git push` (incl. `--force`), `git reset --hard` | `git status`, `git commit`, `git pull` |
| Publish / release | `gh pr merge`, `gh release`, `npm publish`, `deploy` | builds, tests |
| Infra | `kubectl delete`/`apply`, `terraform apply`/`destroy` | `kubectl get`, `terraform plan` |
| Database | `DROP TABLE`, `TRUNCATE TABLE` | `SELECT`, `INSERT` |
| Disk | `dd if=`, `mkfs` | — |
| Privilege / perms | `sudo`, `chmod 777`, `chown … root` | `chmod 644` |
| Remote-to-shell | `curl … \| sh`, `wget -O- … \| sh` | plain `curl`/`wget` downloads |

Plus any **file write/edit** tool call is gated whenever that tool is in
`AEGMIS_GATED_TOOLS` — the installer default gates the **shell only**, so file
writes run free out of the box until you add them.

Everything else — reads, listings, `ls`, routine deletes — runs untouched. In
**forward-all mode** (`AEGMIS_FORWARD_ALL=true`) these local patterns are bypassed
and every gated tool call is sent to the **server-side policy engine** instead,
where your Aegmis policies decide — any command you write a policy for. The
`policies.example.sh` reference ships **~23 more** ready-to-use destructive-action
regexes (`find -delete`, `shred`, `docker push`, `crontab -r`, cloud-CLI deletes,
`kill`/`shutdown`, and more).

---

## Guarding your paths (approval vs hard-block)

Two env vars control what happens when the agent tries to `rm` a path you care
about. Both take a comma-separated list of **literal dirs** or **`re:`-prefixed
regexes**, resolved against the command's cwd (so relative targets like `./work`
are caught too).

| Variable | A matching `rm`… | Reach for it when |
|---|---|---|
| `AEGMIS_PROTECTED_PATHS` | pauses for **Slack approval** — a human can still allow it | the path matters but is *sometimes* legitimately deleted |
| `AEGMIS_BLOCKED_PATHS` | is **denied locally, instantly** — no Slack, nothing to approve | the path must **never** be deleted by the agent |

If a path matches **both**, the hard block wins — it's checked first, before any
approval round-trip. Both are **local-mode** features (`AEGMIS_FORWARD_ALL=false`,
the installer default).

### Minimal steps

1. Open your env file: `~/.pi/agent/.env.intrupt`
2. Add either variable — one path or many, comma-separated:

   ```bash
   # Ask a human before deleting these  →  approval
   export AEGMIS_PROTECTED_PATHS="$HOME/work,$HOME/important"

   # Never let the agent delete these   →  hard block (no approval)
   export AEGMIS_BLOCKED_PATHS="re:^$HOME$,$HOME/.ssh"
   ```
3. Reload it: `source ~/.pi/agent/.env.intrupt` (or restart Pi).

### Examples

| Goal | Entry |
|---|---|
| Approve before wiping the home dir itself | `AEGMIS_PROTECTED_PATHS=re:^$HOME$` |
| Approve deletes of `work` + `important` (and their subtrees) | `AEGMIS_PROTECTED_PATHS=re:^$HOME/(work\|important)(/\|$)` |
| Hard-block `~/.ssh` and everything under it | `AEGMIS_BLOCKED_PATHS=$HOME/.ssh` |
| Hard-block the home dir itself (its contents still run free) | `AEGMIS_BLOCKED_PATHS=re:^$HOME$` |
| Mix — approve `work`, hard-block `~/.ssh` | `AEGMIS_PROTECTED_PATHS=$HOME/work` · `AEGMIS_BLOCKED_PATHS=$HOME/.ssh` |

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
| `AEGMIS_CHANNEL` | no | `slack` | Where the approval request is delivered — `slack` or `email` |
| `AEGMIS_BYPASS_PATTERNS` | no | — | Comma-separated regex; matching shell commands skip approval |
| `AEGMIS_PROTECTED_PATHS` | no | `re:^$HOME$` (set by installer) | Comma-separated dir(s) to also gate `rm` on — each dir **and everything under it**, cwd-resolved. List **one or many** (e.g. `~/work,~/secrets`). Prefix an entry with **`re:`** for a regex tested against the resolved absolute path, e.g. `re:^$HOME$` (home dir only) or `re:^$HOME/(work\|important)(/\|$)` |
| `AEGMIS_BLOCKED_PATHS` | no | — | Same syntax as `AEGMIS_PROTECTED_PATHS`, but an `rm` hitting one is **denied locally with no approval round-trip** — never sent to a human. Use for paths that must *never* be deleted. **Local mode only** (`AEGMIS_FORWARD_ALL=false`). |

**Approval channel:** requests go to **Slack** by default. To deliver them over **email** instead, set `AEGMIS_CHANNEL=email` in your env file.

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

### `AEGMIS_PROTECTED_PATHS` — literal paths and `re:` regexes

Comma-separated entries — each a **literal** dir or a **`re:`**-prefixed **regex** (the regex is tested against the resolved absolute `rm` target):

| Entry | Effect |
|---|---|
| `re:^$HOME$` | gate `rm` of the **home dir itself only** — `rm -rf ~` gates, but `rm -rf ~/project` and `rm ~/notes.txt` run free *(installer default)* |
| `re:^$HOME/(work\|important)(/\|$)` | gate the `work` + `important` **subtrees** |
| `~/work,re:^$HOME$` | **mixed** — literal `work` subtree *and* regex home-exact both gate; anything else runs free |
| `~/work` | plain **literal** — that dir and everything under it |

Anchor a regex with `^…$` to match a dir exactly (not its contents). Invalid regexes are skipped with a stderr warning.

**Worked examples** (write these as `AEGMIS_PROTECTED_PATHS` entries; `$HOME` expands when the env file is sourced):

| Intent | Entry |
|---|---|
| Protect **only the home dir itself**, not its contents | `re:^$HOME$` |
| Protect `work` + `important` (and their subtrees) | `re:^$HOME/(work\|important)(/\|$)` |
| Protect `project/demo` **except** `project/demo/scratch` | `re:^$HOME/project/demo/(?!scratch(/\|$)).*` |
| Protect any `.env` / secrets file anywhere under home | `re:^$HOME/.*(\.env(\|\.)\|/secrets?/)` |
| Multiple, mixed with literal | `$HOME/work,re:^$HOME$` |


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

Results: 35/35 passed ✓
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

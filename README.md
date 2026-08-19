# omp-permission-guard

A classifier-based tool-approval gate for the [oh-my-pi](https://github.com/can1357/oh-my-pi) (`omp`) coding agent.

It intercepts every tool call via the extension `tool_call` hook and, depending on the active mode, **allows / blocks / prompts** — using a vendored shell-command analyzer, risky-path rules, and an optional ephemeral LLM "guardian" judge.

This is a standalone port of the (rejected) core PR [can1357/oh-my-pi#1510](https://github.com/can1357/oh-my-pi/pull/1510) — "Multi-mode tool permissions: heuristic / guardian / hybrid" — which the maintainer closed as *not planned* (issue #1542). The logic is lifted essentially verbatim; only the wiring is adapted from core's approval engine to the extension `tool_call` hook.

## Modes

| Mode | Behavior |
|---|---|
| `off` | Disabled — pass-through (default). |
| `heuristic` | Prove-or-block. Bash → vendored command analyzer + workspace/path containment; `eval` → dangerous-code detection; `write`/`edit`/`ast_edit`/`lsp`/`tts` → risky-path rules. `allow` on positive proof; anything not proven safe (proven danger/escape or unprovable) is blocked — a confirm dialog when a UI exists (`promptOnBlock`), else a hard `deny`. No judge. |
| `guardian` | An ephemeral one-shot LLM judge reviews **exec-tier** calls (bash, eval, ssh, browser, task, …); read/write auto-allow. |
| `hybrid` | Heuristic first. Proven-safe → allow. `uncertain` escalates to the guardian; a proven `deny` also escalates (`escalateBlocked`) so the judge can allow an action the **user explicitly requested** — upgrade-only, a judge deny/error/absence keeps the block. A call that stays blocked is a confirm dialog (`promptOnBlock` + UI) or a hard `deny`. **Recommended.** |

A tool call resolves to one of three actions:
- **allow** → the call runs.
- **deny** → blocked; the model receives the reason as the tool error.
- **prompt** → in an interactive session you get a confirm dialog; with **no UI** (print mode, subagents) it fails safe (blocks).

`read`-tier tools are never gated.

## Intent awareness & overrides

An **explicit user request wins**, without opening a prompt-injection hole:

- The guardian is given your most recent instruction(s), read from the session transcript — **user-role turns only**, so text the agent merely *read* from a file or command output can never masquerade as authorization. It allows an otherwise-dangerous call **only** when your instruction explicitly and specifically directed that exact action.
- In `hybrid`, a heuristic-blocked call escalates to the guardian (`escalateBlocked`, default on). **Upgrade-only**: the judge can turn a block into an allow, but a judge deny / error / absence leaves the block in place — the safety net never weakens when no judge can weigh in.
- A blocked call is not a dead end interactively: with a UI it becomes a **confirm dialog** (`promptOnBlock`, default on) so you can override; in headless runs (print mode, subagents) it stays a hard block.

## Mode precedence

`/guard <mode>` (session) > `OMP_GUARD_MODE` env > `~/.omp/agent/permission-guard.json` > default (`off`).

## Configuration

`~/.omp/agent/permission-guard.json`:

```json
{
  "mode": "hybrid",
  "guardianModel": "",
  "maxAttempts": 3,
  "escalateBlocked": true,
  "promptOnBlock": true,
  "readOmpConfig": true,
  "skill": { "work-obsidian": "allow", "obsidian-*": "allow" },
  "paths": { "~/.omp/agent/git.md": "allow", "/tmp/*": "allow" },
  "approval": { "bash": "prompt" }
}
```

- `mode` — `off` | `heuristic` | `guardian` | `hybrid`.
- `guardianModel` — model spec (`provider/id`) or role alias for the judge. Empty → the fast role chain (`@smol` → `@commit`) → the session model.
- `maxAttempts` — guardian retry budget (default 3).
- `escalateBlocked` — hybrid only: escalate a heuristic-blocked exec call to the guardian so it can allow an explicitly user-requested action (upgrade-only). Default `true`; set `false` for strict prove-or-block.
- `promptOnBlock` — when a UI exists, surface a confirm dialog instead of a hard block so you can override; headless runs still hard-deny. Default `true`; set `false` for a hard wall even interactively.
- `approval` — per-tool overrides, authoritative in **every** mode: `allow` bypasses the classifier, `deny` always blocks, `prompt` always asks. **Exception:** `skill://` / `rule://` reads are governed by `skill` (not `approval`) — a `read: deny` approval entry still blocks skill loads, but `read: allow` / `read: prompt` are overridden by the `skill` policy map.
- `readOmpConfig` — also read omp's own `tools.approval` allow-list from `config.yml` and apply it under this file's `approval` (which wins on conflict). Default `true`; set `false` to ignore omp's list. See [Reading omp's approval list](#reading-omps-approval-list).
- `skill` — a **map of glob patterns to policies** (same shape and `allow`/`deny`/`prompt` values as `approval`) governing `skill://` / `rule://` auto-loads (the agent pulling one of omp's installed, read-only instruction docs into context). Keys match against the doc **name** and support `*`/`?` wildcards, e.g. `{ "work-obsidian": "allow", "obsidian-*": "allow", "*": "prompt" }`. A matched `allow` loads silently, a matched `deny` blocks; a matched `prompt` — or **no match** — escalates to a dedicated skill-load dialog (headless runs, having no one to ask, fail-safe **deny**). A `deny` match wins over an overlapping `allow`. Absent/empty → every load is confirmed interactively. It is a **separate key from `approval`** because `approval` is keyed by tool name (a skill load's tool is always `read`), whereas this matches skill/rule names. See [Skill and rule loads](#skill-and-rule-loads).
- `paths` — a **map of glob patterns to `allow` or `deny` policies** for exact target-path matching, same shape as `skill` and `approval`. Matched against the EXACT `read` / `grep` / `bash` / write target path (after `~` expansion and resolution). Only `*` / `?` wildcards; `*` spans `/`. **Granular and non-recursive:** `"/tmp/*": "allow"` covers scratch/temp dirs; `"~/.omp/agent/git.md": "allow"` a single file; a bare directory matches only that path (contents need `/*`). A `deny` match hard-blocks even inside a broader `allow` glob. Secret/env files are **still denied** regardless. Targets matching no pattern still escalate. Distinct from omp's `/add-dir` recursive roots; also distinct from `approval` (keyed by tool name) and `skill` (matched against skill/rule doc names).

Runtime: `/guard status` shows the mode plus how many calls are allowed this session; `/guard hybrid` (or `off`/`heuristic`/`guardian`) switches the mode for the current session; `/guard allowed` and `/guard revoke <call>` manage the session allow-list (see below). When a call needs confirmation, the guard pauses the agent (the streaming spinner switches to "waiting for you to approve …") and shows a selector:

- **Allow once** — run this call now.
- **Allow this exact call this session** — skip the prompt for an identical call until you restart or `/guard off`. Identity is the tool plus its safety-relevant arguments; volatile fields the agent varies between otherwise-identical calls (e.g. bash's `timeout`) are ignored, so the same command is not re-prompted just because its timeout changed.
- **Allow the directory `<dir>` this session** — shown only when the call was blocked for escaping the workspace root; whitelists that directory for the rest of the session so calls under it stop prompting.
- **Deny** — block and tell the agent it was refused. The guard only prompts when it could not prove the call safe, so Deny is **pre-selected**.
- **Deny (type your own)** — block and type a message that is forwarded to the agent verbatim.

The dialog waits until you choose (ESC denies). When the guardian model produced the ruling behind a prompt (a guardian **deny** in guardian/hybrid mode), the footer names the judging model and its self-reported confidence (e.g. `↳ judged by <model> (confidence 0.9)`); heuristic blocks, fail-safes, and declined escalations show no judge (the model did not rule).

The "this session" choices (allow this exact call, allow the directory) are held in memory for the running session only — they are never written to `permission-guard.json` and are cleared on restart. For a persistent rule, add an `approval` entry (e.g. `"bash": "allow"`) to the config file instead.

**Managing the session allow-list:** `/guard allowed` opens a scrollable selector of every call allowed this session, sorted by when you allowed it (last added at the bottom); pick one to revoke it immediately (it will prompt again next time). `/guard revoke <call>` removes a specific entry directly — its argument autocompletes from the current allow-list, so you can type-to-filter like `/add-dir`. Both are session-only and need no restart.

### Reading omp's approval list

With `readOmpConfig` (default `true`), the guard also reads omp's own `tools.approval` map from `config.yml` and treats each entry as an authoritative policy, exactly like its own `approval` map. A tool with a matching rule is allowed / denied / prompted directly; a tool with **no** matching rule falls through to the normal tier → heuristic → guardian flow.

This is what makes the [recommended pairing](#recommended-pairing) work end to end: under core `tools.approvalMode: yolo`, core stops consulting its own `tools.approval` allow-list, so the guard picks it up and keeps honoring it.

Which files are read: the active agent directory's `config.yml` (profile-aware — `--profile`, `PI_CODING_AGENT_DIR`, and `PI_CONFIG_DIR` are honored) and the project `<cwd>/.omp/config.yml`, with the project layer overriding the global one. Your own `permission-guard.json` `approval` entry overrides both.

**Limitations:**

- **Exact tool names only.** Any `tools.approval` key containing a glob metacharacter (`* ? [ ] { }`) is skipped. There is no wildcard matching.
- **`bash.patterns` are not read** — they are glob-based, so they fall under the wildcard limitation above.
- **Config overlays are not reflected.** `--config` and `PI_CONFIG_FILES` overlays are ignored; only the global and project `config.yml` files are read.
- **XDG path relocation is not handled** (`$XDG_*_HOME/omp`).

### Skill and rule loads

`skill://<name>` and `rule://<name>` reads are the agent loading one of omp's own installed, read-only instruction docs into context — a benign, expected step. They resolve only to omp-managed docs (never arbitrary filesystem paths), so they carry no workspace-escape or exfiltration risk and are **not** routed through the generic "cannot be verified as staying within the workspace" prompt every other un-provable internal URL gets.

Instead, the glob-keyed `skill` policy map decides which docs auto-load (matched against the doc **name**, `*`/`?` wildcards supported):

- **A matching `allow` rule** (e.g. `"work-obsidian": "allow"` or `"obsidian-*": "allow"`) → the doc loads silently, no prompt. Put the skills you routinely use here.
- **A matching `deny` rule** → the load is blocked outright, no prompt. A `deny` match wins over an overlapping `allow`.
- **A matching `prompt` rule, or no matching rule at all** → escalates to the user through a dedicated, **name-forward** dialog that leads with the skill/rule name (the salient fact — *which* doc the agent wants) and **recommends Allow** (pre-selected), unlike the deny-leaning generic gate. It offers:
  - **Allow** — load this doc now (a skill loads at most once per session).
  - **Deny** / **Deny (type your own)** — block, optionally with a message forwarded to the agent.

  There is no session-wide "always load" toggle: to stop prompting for a skill, add an `allow` rule for its name (or a matching glob) to `skill`.

**Headless sessions (print mode, subagents) cannot show the dialog**, so a load with no matching `allow` rule fails safe to a **deny** — exactly like every other unprovable call with no UI. To let a subagent auto-load a skill unattended, add an `allow` rule that matches its name (e.g. `"*": "allow"`) to `skill`.

## Debugging

The guard emits a `[permission-guard]` debug log for every decision it makes, so you can trace exactly what was gated and why. Each line carries the tool name and an argument preview in the message, plus a structured payload:

- **verdict** — `allow` or `deny` (the message begins with this).
- **`tool`, `args`, `tier`, `mode`** — the call and how it was classified.
- **`via`** — where the decision came from: `session-cache` (a prior "allow this call"), `classifier` (heuristic/guardian auto allow/deny), `headless` (no UI, hard deny), or `prompt` (you were asked).
- **`choice`** — for a prompt, what you picked: `allow-once`, `allow-session`, `allow-dir` (with `dir`), `deny`, or `deny-custom` (with your `reason`). Skill/rule loads log their own choices (with the `skill` name): `skill-load-once`, `skill-load-deny`, or `skill-load-deny-custom`.
- **`reason`** — the classifier/guardian explanation or your typed message.

Escalations to the Guardian judge log separately: `[permission-guard] escalate <tool>: <args>` (with `trigger: blocked | uncertain`) when the judge is invoked, and `[permission-guard] guardian verdict <decision> for <tool>` with its ruling. Grep your omp debug log for `[permission-guard]` to see the full decision trail.

## Install

### Marketplace (recommended)

```
omp plugin marketplace add hank-warren/omp-permission-guard
omp plugin install omp-permission-guard@hank-warren
```

Upgrade later with `omp plugin upgrade omp-permission-guard@hank-warren`.

### Direct git install

```
omp plugin install "git+https://github.com/hank-warren/omp-permission-guard.git"
```

Re-run the same command to upgrade (git installs are not covered by `omp plugin upgrade`).

### Local link (development)

```
git clone https://github.com/hank-warren/omp-permission-guard.git
cd omp-permission-guard && omp plugin link .
```

After any install, start (or restart) `omp`; verify with `omp plugin list` / `omp plugin doctor`.

The plugin has **no external runtime dependencies** (`shell-quote` is vendored under `src/safety-net/vendor/`), so marketplace symlink installs work without `bun install`. The guardian's LLM call resolves `@oh-my-pi/pi-ai` from the global omp install at runtime; if it can't be found, `guardian`/`hybrid` fail safe (prompt with UI, deny without) and `heuristic` mode is unaffected.

### Recommended pairing

The guard runs **in addition to** core's own tier approval (`tools.approvalMode`). To make it the *primary* smart gate — auto-allowing proven-safe calls instead of double-prompting — pair it with core in `yolo`:

```yaml
# ~/.omp/agent/config.yml
tools:
  approvalMode: yolo
```

with the guard in `hybrid`. Core then stops prompting on tier, and the guard decides. Left in core `write`/`always-ask` mode, the guard only *adds* gating (it can block/deny but core still prompts on exec-tier).

## Disable

`/guard off`, or `OMP_GUARD_MODE=off`, or set `"mode": "off"` in the config, or `omp plugin disable omp-permission-guard@hank-warren` (marketplace install) / `omp plugin uninstall omp-permission-guard` (git/link install).

## Provenance & license

- Extension logic ported from PR #1510 (`packages/coding-agent/src/tools/permission/*`, `edit/approval-path.ts`, `tools/bash-cwd.ts`, `tools/critical-bash-patterns.ts`, `prompts/system/guardian-system.md`).
- `src/safety-net/` is vendored from [`cc-safety-net`](https://github.com/kenryu42/claude-code-safety-net) (MIT, v0.9.0) — see `src/safety-net/LICENSE`.
- `src/safety-net/vendor/shell-quote.ts` is vendored from [`shell-quote`](https://github.com/ljharb/shell-quote) (MIT, v1.10.0) — see `src/safety-net/vendor/shell-quote.LICENSE`. Inlined so the plugin has zero external runtime deps (marketplace installs don't run `bun install`).
- This package: MIT.

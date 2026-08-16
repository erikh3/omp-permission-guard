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
  "approval": { "bash": "prompt" }
}
```

- `mode` — `off` | `heuristic` | `guardian` | `hybrid`.
- `guardianModel` — model spec (`provider/id`) or role alias for the judge. Empty → the fast role chain (`@smol` → `@commit`) → the session model.
- `maxAttempts` — guardian retry budget (default 3).
- `escalateBlocked` — hybrid only: escalate a heuristic-blocked exec call to the guardian so it can allow an explicitly user-requested action (upgrade-only). Default `true`; set `false` for strict prove-or-block.
- `promptOnBlock` — when a UI exists, surface a confirm dialog instead of a hard block so you can override; headless runs still hard-deny. Default `true`; set `false` for a hard wall even interactively.
- `approval` — per-tool overrides, authoritative in **every** mode: `allow` bypasses the classifier, `deny` always blocks, `prompt` always asks.

Runtime: `/guard status` shows the mode; `/guard hybrid` (or `off`/`heuristic`/`guardian`) switches the mode for the current session. When a call needs confirmation, the guard pauses the agent (the streaming spinner switches to "waiting for you to approve …") and shows a dialog with three choices — **Allow once**, **Allow this exact call this session** (skips the prompt for an identical call until you restart or `/guard off`), and **Deny**. The guard only prompts when it could not prove the call safe, so **Deny is pre-selected**; pick **Other** to deny with a message in your own words that is passed to the agent. The dialog has no timeout: it waits until you choose (or abort the turn with ESC, which denies).

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

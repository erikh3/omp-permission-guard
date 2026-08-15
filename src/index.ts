/**
 * omp-permission-guard
 *
 * A classifier-based tool-approval gate for the oh-my-pi coding agent, ported
 * from the (rejected) core PR #1510 "heuristic / guardian / hybrid" modes into a
 * standalone extension. It intercepts every tool call via the `tool_call` hook
 * and, depending on the active mode, allows / blocks / prompts:
 *
 *   - `off`        — disabled (pass-through).
 *   - `heuristic`  — vendored command analyzer + risky-path rules; prove-or-block.
 *   - `guardian`   — an ephemeral LLM judge reviews exec-tier calls.
 *   - `hybrid`     — heuristic first; escalate only `uncertain` calls to the judge.
 *
 * Mode precedence: `/guard <mode>` (session) > `OMP_GUARD_MODE` env >
 * `~/.omp/agent/permission-guard.json` > default (`hybrid`).
 */
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import type { Api, Model } from "@oh-my-pi/pi-ai";
import type { ExtensionAPI } from "@oh-my-pi/pi-coding-agent";
import { evaluatePermission, type GuardMode } from "./evaluate";
import { GuardianJudge } from "./guardian";
import { getToolTier } from "./tier";

type Mode = GuardMode | "off";
const MODES: Record<string, true> = { off: true, heuristic: true, guardian: true, hybrid: true };
const DEFAULT_MODE: Mode = "hybrid";
const CONFIG_PATH = path.join(os.homedir(), ".omp", "agent", "permission-guard.json");

/**
 * The host's fixed per-handler budget (`EXTENSION_HANDLER_TIMEOUT_MS` in
 * pi-coding-agent). The host arms this timer when the handler is invoked and
 * kills it — surfacing "Extension … timed out after 30000ms" — if it hasn't
 * returned by then. A plugin cannot raise it: the host's setter mutates a
 * *different* lazily-evaluated module instance than the one that arms the timer
 * (verified empirically), so the guard must finish heuristic + guardian + the
 * confirm dialog within this window. Lifting the real ceiling needs an upstream
 * omp change (a config key, or exempting interactive dialogs).
 */
const HOST_HANDLER_BUDGET_MS = 30_000;
/** Slack before the host budget so the dialog resolves and tears down cleanly
 *  (a deny) rather than being killed mid-prompt. */
const CONFIRM_SAFETY_MARGIN_MS = 2_000;
/** Floor for the confirm window, even when the guardian ate most of the budget. */
const MIN_CONFIRM_TIMEOUT_MS = 1_000;
/**
 * Default confirm-dialog window. Kept under the host budget because the dialog
 * must resolve before the host's kill-timer fires; the effective value is always
 * clamped by {@link confirmDialogTimeoutMs}.
 */
const DEFAULT_CONFIRM_TIMEOUT_MS = 20_000;

/**
 * Clamp the configured confirm window to what actually fits inside the host's
 * fixed handler budget, given the time already spent in this handler (heuristic
 * + guardian run before the prompt). Guarantees the dialog times out — a clean
 * deny — before the host kills the handler with a "timed out" error.
 */
export function confirmDialogTimeoutMs(configuredMs: number, elapsedMs: number): number {
	const remaining = HOST_HANDLER_BUDGET_MS - elapsedMs - CONFIRM_SAFETY_MARGIN_MS;
	return Math.max(MIN_CONFIRM_TIMEOUT_MS, Math.min(configuredMs, remaining));
}

interface GuardConfig {
	mode?: Mode;
	guardianModel?: string;
	maxAttempts?: number;
	/** Per-tool overrides, authoritative in every mode: `allow` | `deny` | `prompt`. */
	approval?: Record<string, string>;
	/** Hybrid only: escalate a heuristic-blocked exec call to the Guardian (upgrade-only). Default true. */
	escalateBlocked?: boolean;
	/** Surface a confirm dialog instead of a hard block when a UI exists (headless still hard-denies). Default true. */
	promptOnBlock?: boolean;
	/**
	 * Upper bound (ms) on the interactive confirm dialog before it gives up and
	 * denies. Default 20 000. The host caps every handler at 30 s and a plugin
	 * cannot raise that, so this is clamped per call to fit the budget left after
	 * the guardian runs (see {@link confirmDialogTimeoutMs}); values at or above
	 * ~28 s gain nothing. Lower it for a snappier auto-deny.
	 */
	confirmTimeoutMs?: number;
}

function isMode(value: unknown): value is Mode {
	return typeof value === "string" && Object.hasOwn(MODES, value);
}

function loadConfig(logger?: { debug?: (...a: unknown[]) => void }): GuardConfig {
	try {
		const raw = fs.readFileSync(CONFIG_PATH, "utf8");
		const parsed = JSON.parse(raw) as GuardConfig;
		return parsed && typeof parsed === "object" ? parsed : {};
	} catch (err) {
		if ((err as NodeJS.ErrnoException).code !== "ENOENT") {
			logger?.debug?.("permission-guard: config read failed", { error: String(err) });
		}
		return {};
	}
}

/** A short, single-line preview of the tool args for the confirm dialog. */
function previewArgs(toolName: string, args: unknown): string {
	if (toolName === "bash" && args && typeof args === "object") {
		const command = (args as Record<string, unknown>).command;
		if (typeof command === "string") return command.length > 300 ? `${command.slice(0, 300)}…` : command;
	}
	let text: string;
	try {
		text = JSON.stringify(args);
	} catch {
		text = String(args);
	}
	return text.length > 300 ? `${text.slice(0, 300)}…` : text;
}

const MAX_INTENT_TURNS = 3;
const MAX_INTENT_CHARS = 4000;

/** Text of a session message's content, whether a bare string or a block array. */
function messageText(content: unknown): string {
	if (typeof content === "string") return content;
	if (!Array.isArray(content)) return "";
	const parts: string[] = [];
	for (const block of content) {
		if (!block || typeof block !== "object") continue;
		if (!("type" in block) || block.type !== "text") continue;
		if ("text" in block && typeof block.text === "string") parts.push(block.text);
	}
	return parts.join("\n");
}

interface TranscriptCtx {
	sessionManager?: { getEntries?: () => readonly unknown[] };
}

/**
 * The user's most recent instruction(s), read from the (read-only) session
 * transcript, so the Guardian can honor explicitly-requested dangerous actions.
 * Returns up to the last few genuine user turns (oldest first), bounded — the
 * `tool_call` event itself carries no conversation.
 */
function recentUserIntent(ctx: TranscriptCtx): string | undefined {
	const getEntries = ctx.sessionManager?.getEntries;
	if (typeof getEntries !== "function") return undefined;
	let entries: readonly unknown[];
	try {
		entries = getEntries.call(ctx.sessionManager);
	} catch {
		return undefined;
	}
	const turns: string[] = [];
	for (let i = entries.length - 1; i >= 0 && turns.length < MAX_INTENT_TURNS; i--) {
		const entry = entries[i];
		if (!entry || typeof entry !== "object") continue;
		if (!("type" in entry) || entry.type !== "message") continue;
		if (!("message" in entry) || !entry.message || typeof entry.message !== "object") continue;
		const message = entry.message;
		if (!("role" in message) || message.role !== "user") continue;
		const content = "content" in message ? message.content : undefined;
		const text = messageText(content).trim();
		if (text) turns.push(text);
	}
	if (turns.length === 0) return undefined;
	const joined = turns.reverse().join("\n\n");
	return joined.length > MAX_INTENT_CHARS ? joined.slice(joined.length - MAX_INTENT_CHARS) : joined;
}

export default function permissionGuard(pi: ExtensionAPI): void {
	const logger = pi.logger;
	let sessionMode: Mode | undefined;

	pi.setLabel("Permission Guard");

	const resolveMode = (): Mode => {
		if (sessionMode) return sessionMode;
		const envMode = process.env.OMP_GUARD_MODE;
		if (isMode(envMode)) return envMode;
		const cfgMode = loadConfig(logger).mode;
		return isMode(cfgMode) ? cfgMode : DEFAULT_MODE;
	};

	pi.registerCommand("guard", {
		description: "View or set the permission-guard mode (off | heuristic | guardian | hybrid | status)",
		handler: async (args, ctx) => {
			const arg = (Array.isArray(args) ? args.join(" ") : String(args ?? "")).trim().toLowerCase();
			if (arg === "" || arg === "status") {
				const configured = loadConfig(logger).confirmTimeoutMs ?? DEFAULT_CONFIRM_TIMEOUT_MS;
				const effective = confirmDialogTimeoutMs(configured, 0);
				ctx.ui.notify(
					`Permission guard mode: ${resolveMode()} | confirm dialog ${configured}ms (effective ≤ ${effective}ms), host handler cap ${HOST_HANDLER_BUDGET_MS}ms (config: ${CONFIG_PATH})`,
					"info",
				);
				return;
			}
			if (!isMode(arg)) {
				ctx.ui.notify(`Unknown mode "${arg}". Use: off | heuristic | guardian | hybrid | status`, "warn");
				return;
			}
			sessionMode = arg;
			ctx.ui.notify(`Permission guard mode set to "${arg}" for this session.`, "info");
		},
	});

	pi.on("tool_call", async (event, ctx) => {
		// Stamp handler entry so the confirm dialog can be clamped to the host's
		// remaining budget (heuristic + guardian eat into it before the prompt).
		const startedAt = Date.now();
		const mode = resolveMode();
		if (mode === "off") return;

		let tools: readonly { name: string; approval?: unknown }[] | undefined;
		try {
			tools = pi.getAllTools() as unknown as { name: string; approval?: unknown }[];
		} catch {
			tools = undefined;
		}

		const tier = getToolTier(event.toolName, event.input, tools);
		if (tier === "read") return; // read-tier tools carry no write/exec risk

		const cfg = loadConfig(logger);
		const guardian =
			mode === "guardian" || mode === "hybrid"
				? new GuardianJudge(
						{
							resolveModel: (): Model<Api> | undefined => {
								const models = ctx.models;
								if (!models) return undefined;
								const spec = cfg.guardianModel?.trim();
								return (
									(spec ? models.resolve(spec) : undefined) ??
									models.resolve("@smol") ??
									models.resolve("@commit") ??
									models.current()
								);
							},
							getApiKey: (model: Model<Api>) => ctx.modelRegistry.getApiKey(model),
							logger,
						},
						{ maxAttempts: cfg.maxAttempts },
					)
				: undefined;

		const action = await evaluatePermission({
			toolName: event.toolName,
			args: event.input,
			tier,
			mode,
			userPolicies: cfg.approval ?? {},
			workspaceRoot: ctx.cwd,
			hasUI: ctx.hasUI,
			guardian,
			intent: recentUserIntent(ctx),
			escalateBlocked: cfg.escalateBlocked !== false,
			promptOnBlock: cfg.promptOnBlock !== false,
		});

		if (action.action === "allow") return;
		if (action.action === "deny") return { block: true, reason: `[permission-guard] ${action.reason}` };

		// prompt
		const reason = action.reason ?? "This call could not be proven safe.";
		if (!ctx.hasUI) return { block: true, reason: `[permission-guard] ${reason} (no UI to confirm)` };
		const configured = cfg.confirmTimeoutMs ?? DEFAULT_CONFIRM_TIMEOUT_MS;
		// A timed-out prompt MUST deny. In the interactive TUI the selector
		// auto-selects its highlighted option on timeout — and confirm defaults to
		// "Yes" — so without this an unattended prompt would auto-*allow*. `onTimeout`
		// fires before that auto-select (and on the RPC path too), so we latch it and
		// override the returned value.
		let timedOut = false;
		const ok = await ctx.ui.confirm(
			"Permission guard",
			`${reason}\n\n${event.toolName}: ${previewArgs(event.toolName, event.input)}\n\nAllow this call?`,
			{
				timeout: confirmDialogTimeoutMs(configured, Date.now() - startedAt),
				onTimeout: () => {
					timedOut = true;
				},
			},
		);
		if (timedOut) return { block: true, reason: `[permission-guard] Timed out waiting for confirmation: ${reason}` };
		if (!ok) return { block: true, reason: `[permission-guard] Denied by user: ${reason}` };
	});
}

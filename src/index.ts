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

/** Default confirm-dialog window: how long we wait for a human before denying. */
const DEFAULT_CONFIRM_TIMEOUT_MS = 120_000;
/**
 * Head-room added on top of the confirm window when lifting the host handler
 * budget. Covers the guardian model round-trip (which runs before the dialog,
 * inside the same handler budget) plus dialog render/teardown, so the dialog's
 * own timeout — not the host's kill-switch — is what fires first.
 */
const HOOK_TIMEOUT_MARGIN_MS = 30_000;

/**
 * Lift the extension host's per-handler timeout so a long confirm dialog isn't
 * killed mid-prompt.
 *
 * The host caps every handler at `EXTENSION_HANDLER_TIMEOUT_MS` (30 s) and arms
 * that timer when the handler is *invoked*, so the ceiling MUST be raised before
 * the first `tool_call` — bumping it from inside a handler cannot rescue an
 * already-armed timer. The only lever the host exposes is the module-level
 * `testSetExtensionHandlerTimeoutMs` setter; it is a process-global mutation,
 * applied once at load.
 *
 * Imported dynamically and defensively: the host package is an optional peer
 * (absent in the test env), and the setter is an internal API that may vanish in
 * a future release. On any failure the guard degrades to the host's 30 s default
 * rather than crashing.
 */
async function raiseHostHandlerTimeout(
	budgetMs: number,
	logger?: { debug?: (...a: unknown[]) => void },
): Promise<void> {
	try {
		// Dynamic import: `@oh-my-pi/pi-coding-agent` is an optional peer that is not
		// installed in the test env, so a static import would fail module resolution
		// at load. Inside omp the host is already loaded, so this resolves instantly.
		const host = (await import("@oh-my-pi/pi-coding-agent")) as Record<string, unknown>;
		const setter = host.testSetExtensionHandlerTimeoutMs;
		if (typeof setter === "function") {
			(setter as (ms: number) => void)(budgetMs);
			logger?.debug?.("permission-guard: raised host handler timeout", { budgetMs });
		} else {
			logger?.debug?.(
				"permission-guard: testSetExtensionHandlerTimeoutMs unavailable; confirm dialog capped at host default (30s)",
			);
		}
	} catch (err) {
		logger?.debug?.("permission-guard: could not raise host handler timeout", { error: String(err) });
	}
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
	 * How long (ms) an interactive confirm dialog waits for a human before it
	 * gives up and the call is denied. Default 120 000 (2 min). Because the
	 * extension host caps every handler at 30 s, the guard lifts that ceiling to
	 * cover this window (see `raiseHostHandlerTimeout`); otherwise the dialog is
	 * killed mid-prompt with "Extension … timed out after 30000ms".
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

	// Fix the confirm-dialog window at load and lift the host's per-handler ceiling
	// to cover it. The host arms its 30 s kill-timer when the handler is invoked, so
	// the budget must be raised now — before the first `tool_call` — and the dialog
	// timeout must stay within it. Reading it once here keeps the two in lockstep;
	// changing `confirmTimeoutMs` takes effect on the next session.
	const confirmTimeoutMs = loadConfig(logger).confirmTimeoutMs ?? DEFAULT_CONFIRM_TIMEOUT_MS;
	void raiseHostHandlerTimeout(confirmTimeoutMs + HOOK_TIMEOUT_MARGIN_MS, logger);

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
				ctx.ui.notify(`Permission guard mode: ${resolveMode()} (config: ${CONFIG_PATH})`, "info");
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
		const ok = await ctx.ui.confirm(
			"Permission guard",
			`${reason}\n\n${event.toolName}: ${previewArgs(event.toolName, event.input)}\n\nAllow this call?`,
			{ timeout: confirmTimeoutMs },
		);
		if (!ok) return { block: true, reason: `[permission-guard] Denied by user: ${reason}` };
	});
}

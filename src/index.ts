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
		// Wait indefinitely for the user's decision. The host pauses the 30s
		// extension-handler budget while a tool_call dialog is open, so the prompt is
		// never force-killed; it resolves only when the user answers or the turn is
		// aborted (ESC / interrupt / shutdown), which cancels the dialog.
		const ok = await ctx.ui.confirm(
			"Permission guard",
			`${reason}\n\n${event.toolName}: ${previewArgs(event.toolName, event.input)}\n\nAllow this call?`,
		);
		if (!ok) return { block: true, reason: `[permission-guard] Denied by user: ${reason}` };
	});
}

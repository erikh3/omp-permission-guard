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
import type { ExtensionAPI, ExtensionUIContext } from "@oh-my-pi/pi-coding-agent";
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

interface ApprovalOutcome {
	decision: "allow" | "allow-session" | "deny";
	/** For a deny: custom text the user typed ("Other") or attached ("note"), forwarded to the agent. */
	message?: string;
}

/**
 * Swap the streaming spinner to a clear "paused, waiting on you" message while
 * an approval dialog is open, then restore it. Without this the host keeps
 * showing the in-flight tool's own working message, so a blocked agent looks
 * like it is still busy running the tool.
 */
async function withBlockedIndicator<T>(ui: ExtensionUIContext, toolName: string, run: () => Promise<T>): Promise<T> {
	ui.setWorkingMessage?.(`Permission guard: waiting for you to approve ${toolName}`);
	try {
		return await run();
	} finally {
		ui.setWorkingMessage?.();
	}
}

/**
 * Ask the user to approve a gated call. Prefers the rich ask dialog (labelled
 * options + descriptions, the same surface the ask tool uses); falls back to a
 * plain yes/no confirm on hosts without `askDialog`. `recommended` marks the
 * option the guard leans toward (Deny when it could not prove the call safe).
 * A denial carries any custom text the user typed ("Other") or attached
 * ("note") so their own words reach the agent instead of a generic refusal.
 */
async function askApproval(
	ui: ExtensionUIContext,
	reason: string,
	toolName: string,
	argsPreview: string,
	recommended: number,
): Promise<ApprovalOutcome> {
	const question = `${reason}\n${toolName}: ${argsPreview}`;
	if (ui.askDialog) {
		const res = await ui.askDialog([
			{
				id: "permission-guard",
				header: "Permission guard",
				question,
				options: [
					{ label: "Allow once", description: "Run this call now." },
					{ label: "Allow this exact call this session", description: "Skip the prompt for an identical call until you restart or run /guard off." },
					{ label: "Deny", description: 'Block the call; pick "Other" to tell the agent why in your own words.' },
				],
				recommended,
			},
		]);
		if (!res || res.kind !== "submit") return { decision: "deny" };
		const item = res.results[0];
		const picked = item?.selectedOptions[0];
		if (picked === "Allow once") return { decision: "allow" };
		if (picked?.startsWith("Allow this exact call")) return { decision: "allow-session" };
		// "Deny", "Other (type your own)", or a bare note -> deny, forwarding the
		// user's own words to the agent when they supplied any.
		const custom = item?.customInput?.trim();
		const note = item?.note?.trim();
		const message = [custom, note].filter(Boolean).join(" - ") || undefined;
		return { decision: "deny", message };
	}
	const ok = await ui.confirm("Permission guard", `${question}\n\nAllow this call?`, {
		initialIndex: recommended === 2 ? 1 : 0,
	});
	return { decision: ok ? "allow" : "deny" };
}

export default function permissionGuard(pi: ExtensionAPI): void {
	const logger = pi.logger;
	let sessionMode: Mode | undefined;
	const sessionAllow = new Set<string>();

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
		const callKey = `${event.toolName}:${JSON.stringify(event.input)}`;
		if (sessionAllow.has(callKey)) return;

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
		// The guard only prompts when it could not prove the call safe, so it
		// recommends Deny (option index 2) unless the lean is neutral.
		const recommended = action.recommend === "deny" ? 2 : 0;
		// The dialog blocks indefinitely: the host pauses the 30s handler budget
		// while a tool_call dialog is open, so it resolves only when the user
		// answers or the turn is aborted (ESC / interrupt / shutdown).
		const outcome = await withBlockedIndicator(ctx.ui, event.toolName, () =>
			askApproval(ctx.ui, reason, event.toolName, previewArgs(event.toolName, event.input), recommended),
		);
		if (outcome.decision === "allow") return;
		if (outcome.decision === "allow-session") {
			sessionAllow.add(callKey);
			ctx.ui.notify(`Permission guard: allowing this ${event.toolName} call for the rest of the session.`, "info");
			return;
		}
		return { block: true, reason: `[permission-guard] Denied by user: ${outcome.message ?? reason}` };
	});
}

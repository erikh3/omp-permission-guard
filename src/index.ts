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
import * as path from "node:path";
import type { Api, Model } from "@oh-my-pi/pi-ai";
import type { ExtensionAPI, ExtensionUIContext } from "@oh-my-pi/pi-coding-agent";
import { evaluatePermission, type GuardMode } from "./evaluate";
import { GuardianJudge } from "./guardian";
import { loadOmpApprovalRules, resolveAgentDir } from "./omp-config";
import { matchWorkspaceEscape } from "./risky-paths";
import { getToolTier } from "./tier";

type Mode = GuardMode | "off";
const MODES: Record<string, true> = { off: true, heuristic: true, guardian: true, hybrid: true };
const DEFAULT_MODE: Mode = "hybrid";
const CONFIG_PATH = path.join(resolveAgentDir(), "permission-guard.json");

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
	/** Read omp's own `tools.approval` allow-list from config.yml and apply it under this file's `approval`. Default true. */
	readOmpConfig?: boolean;
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

/** Max characters shown in a confirm-dialog args preview before truncation. */
const MAX_PREVIEW = 300;
/** Clip a preview string to `MAX_PREVIEW` with a trailing ellipsis. */
function clip(s: string): string {
	return s.length > MAX_PREVIEW ? `${s.slice(0, MAX_PREVIEW)}…` : s;
}

/** A short, single-line preview of the tool args for the confirm dialog. */
function previewArgs(toolName: string, args: unknown): string {
	if (args && typeof args === "object") {
		const rec = args as Record<string, unknown>;
		if (toolName === "bash" && typeof rec.command === "string") {
			return clip(rec.command);
		}
		if (toolName === "grep") {
			// The gate on grep is about WHERE it searches, so lead with pattern + path.
			// An empty-string `path` is treated as absent so a populated `paths` still shows.
			const pattern = typeof rec.pattern === "string" ? rec.pattern : "";
			const rawWhere =
				typeof rec.path === "string" && rec.path.length > 0 ? rec.path : (rec.paths ?? rec.path);
			const where =
				typeof rawWhere === "string"
					? rawWhere
					: Array.isArray(rawWhere)
						? rawWhere.filter(v => typeof v === "string").join("; ")
						: "";
			if (pattern || where) {
				return clip(where ? `pattern "${pattern}" in ${where}` : `pattern "${pattern}"`);
			}
		}
	}
	let text: string;
	try {
		text = JSON.stringify(args);
	} catch {
		text = String(args);
	}
	return clip(text);
}

/**
 * Fields that vary between otherwise-identical tool calls and are irrelevant to
 * the safety decision, so they must not be part of the session-allow identity.
 * `bash`'s `timeout` is the culprit behind the "allow this exact call" miss: the
 * agent re-issues the same command with a different (or omitted) `timeout`, which
 * changed `JSON.stringify(input)` and defeated the cache.
 */
const VOLATILE_INPUT_KEYS: Record<string, true> = { timeout: true };

/**
 * Deterministic stringify with sorted keys — does NOT filter volatile fields; that
 * stripping happens at the top level only in `sessionCallKey`.
 */
function stableStringify(value: unknown): string {
	if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
	if (value && typeof value === "object") {
		const rec = value as Record<string, unknown>;
		const keys = Object.keys(rec).sort();
		return `{${keys.map(k => `${JSON.stringify(k)}:${stableStringify(rec[k])}`).join(",")}}`;
	}
	return JSON.stringify(value) ?? "null";
}

let _sessionCallKeyCounter = 0;
/** Stable identity for a tool call used by the "allow this exact call this session" cache. */
function sessionCallKey(toolName: string, input: unknown): string {
	try {
		// Strip volatile keys at the TOP LEVEL only to avoid over-broadening identity for
		// nested fields that happen to share the same name (e.g. a nested `timeout`).
		let sanitized: unknown = input;
		if (input && typeof input === "object" && !Array.isArray(input)) {
			const rec = input as Record<string, unknown>;
			const stripped: Record<string, unknown> = {};
			for (const k of Object.keys(rec)) {
				if (!Object.hasOwn(VOLATILE_INPUT_KEYS, k)) stripped[k] = rec[k];
			}
			sanitized = stripped;
		}
		return `${toolName}:${stableStringify(sanitized)}`;
	} catch {
		// A circular or pathological input must degrade to a cache MISS (re-prompt)
		// rather than throwing out of the hot tool_call handler.
		return `${toolName}:__fallback_${_sessionCallKeyCounter++}__`;
	}
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
	decision: "allow" | "allow-session" | "allow-dir" | "deny";
	/** For a deny: a message the user typed ("Deny (type your own)"), forwarded to the agent. */
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
 * Ask the user to approve a gated call via a labelled radio selector. The guard
 * recommends Deny when it could not prove the call safe (`recommendDeny`), offers
 * to whitelist an escaped directory for the session when one is known
 * (`externalDir`), and — via "Deny (type your own)" — collects a free-text reason
 * that is forwarded to the agent instead of a generic refusal.
 */
async function askApproval(
	ui: ExtensionUIContext,
	reason: string,
	toolName: string,
	argsPreview: string,
	opts: { recommendDeny: boolean; externalDir?: string; judge?: string; confidence?: number; hideCall?: boolean; guardianError?: boolean },
): Promise<ApprovalOutcome> {
	const denyLabel = opts.recommendDeny ? "Deny (recommended)" : "Deny";
	const options: string[] = ["Allow once", "Allow this exact call this session"];
	if (opts.externalDir) options.push(`Allow the directory ${opts.externalDir} this session`);
	options.push(denyLabel, "Deny (type your own)");

	// The host selector renders the title through its own highlighter (directory
	// paths in the reason, shell syntax in the command), so we pass plain text and
	// let it style consistently. Embedding our own ANSI double-styles the text and
	// the colors flip when a theme re-render (e.g. focus change) re-runs the
	// highlighter over our codes. `hideCall` drops the command line entirely when
	// the host already shows the call above the prompt (e.g. an `eval` py block).
	// `previewArgs` clips a long command with a trailing ellipsis; surface that as
	// an explicit "(truncated)" note instead.
	const truncated = argsPreview.endsWith("…");
	const shownArgs = truncated ? `${argsPreview.slice(0, -1)}...(truncated)` : argsPreview;
	const title = opts.hideCall ? reason : `${reason}\n\n${toolName}: ${shownArgs}`;

	const denyIndex = options.indexOf(denyLabel);
	// The selector footer is `helpText ?? <default nav>` (it replaces, not appends), so we
	// reconstruct the nav hints and append a status note — the only edge slot the selector exposes.
	// `opts.judge` marks a guardian ruling (a model deny); `opts.guardianError` marks the opposite —
	// the guardian could not be reached or returned no parseable verdict, so this prompt is the
	// fail-safe fallback and the recommendation is not a model's judgment. They are mutually exclusive.
	const nav = "up/down navigate  enter select  esc cancel";
	const status = opts.judge
		? ` ↳ judged by ${opts.judge}${opts.confidence !== undefined ? ` (confidence ${opts.confidence})` : ""}`
		: opts.guardianError
			? " ↳ guardian unavailable (no verdict) — deciding for it"
			: undefined;
	const picked = await ui.select(title, options, {
		initialIndex: opts.recommendDeny ? denyIndex : 0,
		outline: true,
		selectionMarker: "radio",
		helpText: status ? `${nav}   ·  ${status}` : undefined,
	});
	if (picked === "Allow once") return { decision: "allow" };
	if (picked?.startsWith("Allow this exact call")) return { decision: "allow-session" };
	if (picked?.startsWith("Allow the directory")) return { decision: "allow-dir" };
	if (picked === "Deny (type your own)") {
		const message = (await ui.input("Message to the agent", "Why are you denying this call?"))?.trim();
		return { decision: "deny", message: message || undefined };
	}
	// "Deny", "Deny (recommended)", or cancel (undefined) -> block.
	return { decision: "deny" };
}

export default function permissionGuard(pi: ExtensionAPI): void {
	const logger = pi.logger;
	let sessionMode: Mode | undefined;
	// Session "allow this exact call" entries, keyed by `sessionCallKey`. The value carries a
	// human-readable label (for `/guard allowed`) and a monotonic sequence so the list can be
	// shown in insertion order (last-added at the bottom). A Map is required here: dynamic
	// insertion/removal, `.size`, iteration, and stable insertion order.
	const sessionAllow = new Map<string, { label: string; seq: number }>();
	let allowSeq = 0;
	const sessionAllowedRoots = new Set<string>();

	pi.setLabel("Permission Guard");

	const resolveMode = (): Mode => {
		if (sessionMode) return sessionMode;
		const envMode = process.env.OMP_GUARD_MODE;
		if (isMode(envMode)) return envMode;
		const cfgMode = loadConfig(logger).mode;
		return isMode(cfgMode) ? cfgMode : DEFAULT_MODE;
	};

	/** Session-allow entries sorted by insertion order — last added at the bottom, matching the list UX. */
	const sortedAllowed = (): { key: string; label: string }[] =>
		[...sessionAllow.entries()]
			.sort((a, b) => a[1].seq - b[1].seq)
			.map(([key, v]) => ({ key, label: v.label }));

	const MODE_HINT = "off | heuristic | guardian | hybrid | status | allowed | revoke <call>";

	pi.registerCommand("guard", {
		description: `Permission guard: set mode (${MODE_HINT})`,
		getArgumentCompletions: (prefix: string) => {
			const p = prefix.trimStart();
			// `revoke ` (or a partial `revoke`+space): complete the remainder against the allow-list.
			const revokeMatch = /^revoke(\s+(.*))?$/is.exec(p);
			if (revokeMatch && (p.length > "revoke".length || /\s$/.test(prefix))) {
				const term = (revokeMatch[2] ?? "").toLowerCase();
				return sortedAllowed()
					.filter(e => e.label.toLowerCase().includes(term))
					.map(e => ({ value: `revoke ${e.label}`, label: e.label, description: "revoke session allow" }));
			}
			// Otherwise complete the subcommand word itself.
			const subs = ["status", "off", "heuristic", "guardian", "hybrid", "allowed", "revoke"];
			const term = p.toLowerCase();
			return subs
				.filter(s => s.startsWith(term))
				.map(s => ({ value: s, label: s, description: "permission-guard" }));
		},
		handler: async (args, ctx) => {
			const raw = (Array.isArray(args) ? args.join(" ") : String(args ?? "")).trim();
			const sub = (raw.split(/\s+/)[0] ?? "").toLowerCase();
			const rest = raw.slice(sub.length).trim();

			if (raw === "" || sub === "status") {
				ctx.ui.notify(
					`Permission guard mode: ${resolveMode()} · ${sessionAllow.size} session-allowed call(s) (config: ${CONFIG_PATH})`,
					"info",
				);
				return;
			}
			if (sub === "allowed") {
				const entries = sortedAllowed();
				if (entries.length === 0) {
					ctx.ui.notify("Permission guard: no calls allowed for this session.", "info");
					return;
				}
				// Build index-prefixed option strings so each selection is unique even when labels collide.
				const options = entries.map((e, i) => `${i + 1}. ${e.label}`);
				const picked = await ctx.ui.select(
					`Session-allowed calls (${entries.length}) — select one to revoke`,
					options,
					{ outline: true },
				);
				if (picked === undefined) return; // ESC / cancel: leave the list untouched
				// Parse the leading "N." back to the unique key — deterministic even with colliding labels.
				const match = /^(\d+)\./.exec(picked);
				if (match) {
					const idx = parseInt(match[1], 10) - 1;
					const entry = entries[idx];
					if (entry) {
						sessionAllow.delete(entry.key);
						ctx.ui.notify(`Permission guard: revoked session allow for ${entry.label}`, "info");
					}
				}
				return;
			}
			if (sub === "revoke") {
				if (!rest) {
					ctx.ui.notify("Usage: /guard revoke <call> — see /guard allowed for the list.", "warn");
					return;
				}
				// Delete ALL entries whose label matches, so colliding labels are fully cleared.
				const matching = sortedAllowed().filter(e => e.label === rest);
				if (matching.length === 0) {
					ctx.ui.notify(`Permission guard: no session-allowed call matching "${rest}".`, "warn");
					return;
				}
				for (const entry of matching) sessionAllow.delete(entry.key);
				ctx.ui.notify(
					matching.length === 1
						? `Permission guard: revoked session allow for ${rest}`
						: `Permission guard: revoked ${matching.length} session allows for ${rest}`,
					"info",
				);
				return;
			}
			if (!isMode(sub)) {
				ctx.ui.notify(`Unknown argument "${sub}". Use: ${MODE_HINT}`, "warn");
				return;
			}
			sessionMode = sub;
			ctx.ui.notify(`Permission guard mode set to "${sub}" for this session.`, "info");
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
		// Read-tier tools carry no write/exec risk and are skipped — EXCEPT `grep` and
		// `read`, whose `path`/`paths` can reach anywhere on disk (secret/env files,
		// paths outside the workspace). They stay read-tier but are proved by the
		// classifier below.
		if (tier === "read" && event.toolName !== "grep" && event.toolName !== "read") return;

		const argsPreview = previewArgs(event.toolName, event.input);
		const log = (verdict: string, extra?: Record<string, unknown>) =>
			logger?.debug?.(`[permission-guard] ${verdict} ${event.toolName}: ${argsPreview}`, {
				tool: event.toolName,
				args: argsPreview,
				tier,
				mode,
				...extra,
			});
		const callKey = sessionCallKey(event.toolName, event.input);
		if (sessionAllow.has(callKey)) {
			log("allow", { via: "session-cache" });
			return;
		}

		const cfg = loadConfig(logger);
		let judgeModel: Model<Api> | undefined;
		const guardian =
			mode === "guardian" || mode === "hybrid"
				? new GuardianJudge(
						{
							resolveModel: (): Model<Api> | undefined => {
								const models = ctx.models;
								if (!models) return undefined;
								const spec = cfg.guardianModel?.trim();
								judgeModel =
									(spec ? models.resolve(spec) : undefined) ??
									models.resolve("@smol") ??
									models.resolve("@commit") ??
									models.current();
								return judgeModel;
							},
							getApiKey: (model: Model<Api>) => ctx.modelRegistry.getApiKey(model),
							logger,
						},
						{ maxAttempts: cfg.maxAttempts },
					)
				: undefined;

		// omp's own `tools.approval` allow-list feeds the same authoritative policy
		// layer; the guard's own `approval` map overrides it on conflict. Unmatched
		// tools fall through to tier/heuristic/guardian unchanged.
		const ompRules = cfg.readOmpConfig !== false ? loadOmpApprovalRules(ctx.cwd, logger) : {};
		const userPolicies = { ...ompRules, ...(cfg.approval ?? {}) };

		const action = await evaluatePermission({
			toolName: event.toolName,
			args: event.input,
			tier,
			mode,
			userPolicies,
			workspaceRoot: ctx.cwd,
			hasUI: ctx.hasUI,
			guardian,
			intent: recentUserIntent(ctx),
			escalateBlocked: cfg.escalateBlocked !== false,
			promptOnBlock: cfg.promptOnBlock !== false,
			// Session dir-allow choices + omp's multi-root workspace dirs (`/add-dir`),
			// both treated as in-workspace by the containment heuristic.
			allowedRoots: [...sessionAllowedRoots, ...(ctx.sessionManager?.getAdditionalDirectories?.() ?? [])],
		});

		if (action.action === "allow") {
			log("allow", { via: "classifier" });
			return;
		}
		if (action.action === "deny") {
			log("deny", { via: "classifier", reason: action.reason });
			return { block: true, reason: `[permission-guard] ${action.reason}` };
		}

		// prompt
		const reason = action.reason ?? "This call could not be proven safe.";
		if (!ctx.hasUI) {
			log("deny", { via: "headless", reason });
			return { block: true, reason: `[permission-guard] ${reason} (no UI to confirm)` };
		}
		// The guard only prompts when it could not prove the call safe, so it leans
		// Deny; a workspace-escape reason yields the directory we can offer to allow.
		const externalDir = matchWorkspaceEscape(reason);
		// The host renders `eval` code (py or js) as a syntax-highlighted block
		// above the prompt, so skip the redundant command line for both languages.
		const input = event.input;
		const hideCall =
			event.toolName === "eval" &&
			typeof input === "object" &&
			input !== null &&
			"language" in input &&
			(input.language === "py" || input.language === "js");
		// The dialog blocks indefinitely: the host pauses the 30s handler budget
		// while a tool_call dialog is open, so it resolves only when the user
		// answers or the turn is aborted (ESC / interrupt / shutdown).
		const outcome = await withBlockedIndicator(ctx.ui, event.toolName, () =>
			askApproval(ctx.ui, reason, event.toolName, previewArgs(event.toolName, event.input), {
				recommendDeny: action.recommend === "deny",
				externalDir,
				judge: action.judged && judgeModel ? `${judgeModel.provider}/${judgeModel.id}` : undefined,
				confidence: action.judged ? action.confidence : undefined,
				hideCall,
				guardianError: action.guardianError === true,
			}),
		);
		if (outcome.decision === "allow") {
			log("allow", { via: "prompt", choice: "allow-once" });
			return;
		}
		if (outcome.decision === "allow-session") {
			sessionAllow.set(callKey, { label: `${event.toolName}: ${argsPreview}`, seq: allowSeq++ });
			log("allow", { via: "prompt", choice: "allow-session" });
			ctx.ui.notify(`Permission guard: allowing this ${event.toolName} call for the rest of the session.`, "info");
			return;
		}
		if (outcome.decision === "allow-dir" && externalDir) {
			sessionAllowedRoots.add(externalDir);
			log("allow", { via: "prompt", choice: "allow-dir", dir: externalDir });
			ctx.ui.notify(`Permission guard: allowing the directory ${externalDir} for the rest of the session.`, "info");
			return;
		}
		log("deny", { via: "prompt", choice: outcome.message ? "deny-custom" : "deny", reason: outcome.message ?? reason });
		return { block: true, reason: `[permission-guard] Denied by user: ${outcome.message ?? reason}` };
	});
}

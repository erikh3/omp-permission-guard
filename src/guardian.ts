/**
 * Guardian: an ephemeral LLM safety judge for tool calls.
 *
 * Adapted from PR #1510's `tools/permission/guardian.ts`. The one-shot review
 * pattern (a single `completeSimple` call with a forced `verdict` tool, never
 * touching the live conversation) is preserved verbatim; only the wiring is
 * changed for an extension:
 *
 * - `completeSimple` is imported DYNAMICALLY from `@oh-my-pi/pi-ai/stream` the
 *   first time the judge runs, so `heuristic` mode carries no runtime
 *   `@oh-my-pi/*` dependency and a missing/renamed package degrades gracefully
 *   (guardian reports `error` → caller fails safe) instead of breaking load.
 * - model selection + API-key lookup are injected by the caller from the live
 *   extension context (`ctx.models` / `ctx.modelRegistry`).
 */
import type { Api, AssistantMessage, Model, Tool } from "@oh-my-pi/pi-ai";
import { GUARDIAN_SYSTEM_PROMPT } from "./guardian-system";

const VERDICT_TOOL_NAME = "verdict";
// The Guardian is the sole authorization gate in `guardian` mode, so it must see the whole
// security-relevant argument. Bound the prompt generously and elide only the MIDDLE on overflow
// (head + tail) — head-only truncation could drop a trailing `; rm -rf /`.
const MAX_ARGS_CHARS = 8000;
// The user's recent instruction is the authorization signal for explicitly-requested dangerous
// actions; bound it so a long turn can't dominate the judge prompt (head-truncate: the ask is usually up front).
const MAX_INTENT_CHARS = 2000;
const GUARDIAN_MAX_TOKENS = 200;
const REASONING_SAFE_MAX_TOKENS = 1024;
const DEFAULT_MAX_ATTEMPTS = 3;
const DEFAULT_BASE_BACKOFF_MS = 500;

const verdictTool: Tool = {
	name: VERDICT_TOOL_NAME,
	description: "Record the safety verdict for the proposed tool call.",
	parameters: {
		type: "object",
		properties: {
			decision: {
				type: "string",
				enum: ["allow", "deny"],
				description: "Whether the proposed tool call is safe to run.",
			},
			reason: {
				type: "string",
				description: "Short justification for the decision; required when denying.",
			},
		},
		required: ["decision"],
		additionalProperties: false,
	},
};

/** Outcome of a Guardian review. `error` means retries were exhausted / unavailable. */
export type GuardianVerdict =
	| { decision: "allow"; reason?: string }
	| { decision: "deny"; reason: string }
	| { decision: "error" };

export interface GuardianRequest {
	toolName: string;
	args: unknown;
	/** Reason a prior heuristic flagged the call (hybrid mode). */
	reason?: string;
	cwd?: string;
	/** The user's recent instruction(s), so the judge can honor explicitly-requested actions. */
	intent?: string;
	/** True when a heuristic already BLOCKED this as dangerous (escalated deny): allow ONLY on explicit user authorization. */
	blocked?: boolean;
}

/** Live dependencies injected from the extension handler context. */
export interface GuardianDeps {
	/** Resolve the model to judge with (configured guardian model, a fast role, or the session model). */
	resolveModel: () => Model<Api> | undefined;
	/** Look up the API key for the resolved model (usually `ctx.modelRegistry.getApiKey`). */
	getApiKey: (model: Model<Api>) => Promise<string | undefined>;
	logger?: { debug?: (...args: unknown[]) => void };
}

export interface GuardianOptions {
	maxAttempts?: number;
	baseBackoffMs?: number;
}

type CompleteSimpleFn = (
	model: Model<Api>,
	context: { systemPrompt: string[]; messages: { role: string; content: string; timestamp: number }[]; tools: Tool[] },
	options: Record<string, unknown>,
) => Promise<AssistantMessage>;

let cachedCompleteSimple: CompleteSimpleFn | null | undefined;

/**
 * Resolve `completeSimple` lazily. Tries the bare package subpath first (works
 * when the extension's `node_modules/@oh-my-pi` is linked to the global install),
 * then a couple of well-known absolute fallbacks. Cached across calls; `null`
 * means "confirmed unavailable" so we do not re-probe on every call.
 */
async function loadCompleteSimple(): Promise<CompleteSimpleFn | null> {
	if (cachedCompleteSimple !== undefined) return cachedCompleteSimple;
	const home = process.env.HOME ?? "";
	const candidates = [
		"@oh-my-pi/pi-ai/stream",
		`${home}/.bun/install/global/node_modules/@oh-my-pi/pi-ai/src/stream.ts`,
	];
	for (const spec of candidates) {
		try {
			const mod = (await import(spec)) as { completeSimple?: CompleteSimpleFn };
			if (typeof mod.completeSimple === "function") {
				cachedCompleteSimple = mod.completeSimple;
				return cachedCompleteSimple;
			}
		} catch {
			// try next candidate
		}
	}
	cachedCompleteSimple = null;
	return null;
}

function safeStringify(value: unknown): string {
	if (typeof value === "string") return value;
	try {
		return JSON.stringify(value, null, 2) ?? String(value);
	} catch {
		return String(value);
	}
}

/** Bound an argument string for the prompt while preserving BOTH ends (middle elided on overflow). */
function truncateArgsForJudgment(value: string, maxChars: number): string {
	if (value.length <= maxChars) return value;
	const half = Math.max(1, Math.floor((maxChars - 1) / 2));
	const omitted = value.length - half * 2;
	return `${value.slice(0, half)}\n… (${omitted} chars elided) …\n${value.slice(value.length - half)}`;
}

function buildUserMessage(req: GuardianRequest): string {
	const lines = [`Tool: ${req.toolName}`];
	if (req.cwd) lines.push(`Working directory: ${req.cwd}`);
	if (req.reason) {
		lines.push(
			req.blocked
				? `A safety heuristic BLOCKED this call as dangerous: ${req.reason}`
				: `A safety heuristic could not prove this call safe: ${req.reason}`,
		);
	}
	lines.push("Arguments:", truncateArgsForJudgment(safeStringify(req.args), MAX_ARGS_CHARS));
	const intent = req.intent?.trim();
	lines.push(
		"",
		"The user's most recent instruction(s) to the agent:",
		intent ? truncateArgsForJudgment(intent, MAX_INTENT_CHARS) : "(no explicit user instruction available)",
	);
	return lines.join("\n");
}

function parseVerdict(content: AssistantMessage["content"]): GuardianVerdict | null {
	for (const block of content) {
		if (block.type === "toolCall" && block.name === VERDICT_TOOL_NAME) {
			const args = block.arguments as Record<string, unknown>;
			const reason = typeof args.reason === "string" && args.reason.length > 0 ? args.reason : undefined;
			if (args.decision === "allow") return reason ? { decision: "allow", reason } : { decision: "allow" };
			if (args.decision === "deny") return { decision: "deny", reason: reason ?? "Guardian denied the tool call." };
		}
	}
	return null;
}

async function abortableDelay(ms: number, signal?: AbortSignal): Promise<void> {
	if (ms <= 0 || signal?.aborted) return;
	await new Promise<void>(resolve => {
		const onAbort = () => {
			clearTimeout(timer);
			resolve();
		};
		const timer = setTimeout(() => {
			signal?.removeEventListener("abort", onAbort);
			resolve();
		}, ms);
		signal?.addEventListener("abort", onAbort, { once: true });
	});
}

export class GuardianJudge {
	readonly #deps: GuardianDeps;
	readonly #options: GuardianOptions;

	constructor(deps: GuardianDeps, options: GuardianOptions = {}) {
		this.#deps = deps;
		this.#options = options;
	}

	#maxAttempts(): number {
		const configured = this.#options.maxAttempts;
		return typeof configured === "number" && configured >= 1 ? Math.floor(configured) : DEFAULT_MAX_ATTEMPTS;
	}

	/**
	 * Review a proposed tool call. Retries transient failures with exponential
	 * backoff, then returns `{ decision: "error" }` so the caller can fail safe.
	 */
	async evaluate(req: GuardianRequest, signal?: AbortSignal): Promise<GuardianVerdict> {
		const log = this.#deps.logger?.debug ?? (() => {});
		let argsPreview: string;
		try {
			argsPreview = (JSON.stringify(req.args) ?? "undefined").slice(0, 500);
		} catch {
			argsPreview = "(unserializable)";
		}
		log(`[permission-guard] escalate ${req.toolName}: ${argsPreview}`, {
			tool: req.toolName,
			args: argsPreview,
			trigger: req.blocked ? "blocked" : "uncertain",
			reason: req.reason,
		});
		const completeSimple = await loadCompleteSimple();
		if (!completeSimple) {
			log("guardian: completeSimple unavailable");
			return { decision: "error" };
		}
		const model = this.#deps.resolveModel();
		if (!model) {
			log("guardian: no model available");
			return { decision: "error" };
		}
		const apiKey = await this.#deps.getApiKey(model);
		if (!apiKey) {
			log("guardian: no API key", { provider: model.provider, id: model.id });
			return { decision: "error" };
		}

		const userMessage = buildUserMessage(req);
		const maxTokens = model.reasoning
			? Math.max(GUARDIAN_MAX_TOKENS, REASONING_SAFE_MAX_TOKENS)
			: GUARDIAN_MAX_TOKENS;
		const maxAttempts = this.#maxAttempts();
		const baseBackoff = this.#options.baseBackoffMs ?? DEFAULT_BASE_BACKOFF_MS;

		for (let attempt = 0; attempt < maxAttempts; attempt++) {
			if (signal?.aborted) return { decision: "error" };
			try {
				const response = await completeSimple(
					model,
					{
						systemPrompt: [GUARDIAN_SYSTEM_PROMPT],
						messages: [{ role: "user", content: userMessage, timestamp: Date.now() }],
						tools: [verdictTool],
					},
					{
						apiKey,
						maxTokens,
						disableReasoning: true,
						toolChoice: { type: "tool", name: VERDICT_TOOL_NAME },
						signal,
					},
				);
				if (response.stopReason === "error") {
					throw new Error(response.errorMessage ?? "guardian completion error");
				}
				const verdict = parseVerdict(response.content);
				if (verdict) {
					log(`[permission-guard] guardian verdict ${verdict.decision} for ${req.toolName}`, {
						tool: req.toolName,
						decision: verdict.decision,
						reason: verdict.reason,
					});
					return verdict;
				}
				throw new Error("guardian returned no parseable verdict");
			} catch (err) {
				if (signal?.aborted) return { decision: "error" };
				log("guardian: attempt failed", { attempt, error: err instanceof Error ? err.message : String(err) });
				if (attempt < maxAttempts - 1) await abortableDelay(baseBackoff * 2 ** attempt, signal);
			}
		}
		return { decision: "error" };
	}
}

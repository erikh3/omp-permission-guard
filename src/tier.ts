/**
 * Tool capability tier resolution for the permission guard.
 *
 * A faithful, dependency-free replica of core's `getToolDecision(...).tier`
 * (`packages/coding-agent/src/tools/approval.ts`), so the guard classifies the
 * SAME tier core would — including function-valued `approval` declarations used
 * by argument-dependent xd-device tools. Kept local so the extension needs no
 * runtime `@oh-my-pi/*` import for the heuristic path.
 */

/** Capability tier — matches core's `ToolTier`. */
export type ToolTier = "read" | "write" | "exec";

export type ApprovalPolicy = "allow" | "deny" | "prompt";

/** Minimal shape of a tool's approval declaration (mirrors core `ApprovalSubject`). */
export interface ApprovalSubject {
	name: string;
	approval?: unknown;
	formatApprovalDetails?: unknown;
}

const TIERS: Record<string, true> = { read: true, write: true, exec: true };
function isToolTier(value: unknown): value is ToolTier {
	return typeof value === "string" && Object.hasOwn(TIERS, value);
}

/**
 * Resolve a single tool's effective tier from its `approval` declaration.
 * Runs a function-valued `approval` with the call args (so a mounted xd device
 * reports the tier it picks for those args). Defaults to `exec` — the safe
 * default core uses for any tool that omits an approval declaration.
 */
export function resolveToolTier(tool: ApprovalSubject | undefined, args: unknown): ToolTier {
	const approval = tool?.approval;
	const decision = typeof approval === "function" ? (approval as (a: unknown) => unknown)(args) : approval;
	if (isToolTier(decision)) return decision;
	if (decision && typeof decision === "object" && !Array.isArray(decision)) {
		const tier = (decision as Record<string, unknown>).tier;
		return isToolTier(tier) ? tier : "exec";
	}
	return "exec";
}

/**
 * Static fallback tiers for the built-in tool set, used only when the live tool
 * registry is unavailable or does not list the tool. Unknown non-MCP tools fall
 * through to `exec` (fail safe). MCP tools (`mcp__*`) declare `write` in core.
 */
const STATIC_TIERS: Readonly<Record<string, ToolTier>> = {
	read: "read",
	grep: "read",
	glob: "read",
	ast_grep: "read",
	todo: "read",
	ls: "read",
	tree: "read",
	recall: "read",
	reflect: "read",
	inspect_image: "read",
	web_search: "read",
	ask: "read",
	write: "write",
	edit: "write",
	ast_edit: "write",
	tts: "write",
	generate_image: "write",
	memory_edit: "write",
	retain: "write",
	lsp: "write",
	bash: "exec",
	eval: "exec",
	browser: "exec",
	task: "exec",
	debug: "exec",
	hub: "exec",
	learn: "exec",
	checkpoint: "exec",
	rewind: "exec",
	manage_skill: "exec",
	github: "exec",
	ssh: "exec",
	recipe: "exec",
};

/**
 * Effective tier for a tool call. A known built-in's static tier wins (the live
 * registry strips `approval`, so trusting it for built-ins would fail-safe every
 * one to `exec`); otherwise a non-built-in with an `approval` declaration reports
 * its own tier (covers xd/SDK devices), then `mcp__*` → write, then `exec`.
 */
export function getToolTier(
	toolName: string,
	args: unknown,
	tools: readonly ApprovalSubject[] | undefined,
): ToolTier {
	// A known built-in's static tier is authoritative. The live tool registry's
	// `ToolInfo` (from `getAllToolInfos`) does NOT carry the `approval` field, so
	// consulting it for a built-in would resolve `undefined` → the `exec` fail-safe
	// for EVERY built-in (grep/read/glob/ast_grep/web_search included), gating
	// harmless read-tier tools. Static first keeps them correctly classified.
	if (Object.hasOwn(STATIC_TIERS, toolName)) return STATIC_TIERS[toolName]!;
	// A non-built-in that actually exposes an `approval` declaration (an SDK/xd
	// device tool) is trusted to report its own tier; argument-dependent devices
	// resolve per-call. Registry entries without `approval` fall through.
	const tool = tools?.find(t => t.name === toolName);
	if (tool && tool.approval !== undefined) return resolveToolTier(tool, args);
	if (toolName.startsWith("mcp__")) return "write";
	return "exec";
}

const POLICIES: Record<string, true> = { allow: true, deny: true, prompt: true };

/** Best-effort conversion of an arbitrary user-supplied value to a policy. */
export function normalizePolicy(value: unknown): ApprovalPolicy | undefined {
	if (typeof value !== "string") return undefined;
	const lowered = value.trim().toLowerCase();
	return Object.hasOwn(POLICIES, lowered) ? (lowered as ApprovalPolicy) : undefined;
}

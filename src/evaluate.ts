/**
 * Permission orchestrator. Maps a tool call + guard mode to a concrete action
 * (`allow` / `deny` / `prompt`), layering the heuristic blacklist and the
 * Guardian LLM judge. Adapted from PR #1510's `tools/permission/evaluate.ts`;
 * the tier-mode delegation is dropped (core still owns `always-ask`/`write`/
 * `yolo`) — this only implements the new `heuristic` / `guardian` / `hybrid`
 * modes on top.
 */
import type { GuardianRequest, GuardianVerdict } from "./guardian";
import { classifyHeuristic } from "./heuristic";
import { normalizePolicy, type ToolTier } from "./tier";

export type GuardMode = "heuristic" | "guardian" | "hybrid";

export type PermissionAction =
	| { action: "allow" }
	| { action: "deny"; reason: string }
	| { action: "prompt"; reason?: string; recommend?: "allow" | "deny" };

/** Minimal guardian surface the orchestrator needs. */
export interface Guardian {
	evaluate(req: GuardianRequest, signal?: AbortSignal): Promise<GuardianVerdict>;
}

export interface EvaluatePermissionInput {
	toolName: string;
	args: unknown;
	tier: ToolTier;
	mode: GuardMode;
	/** User per-tool policies (`approval` map), authoritative in every mode. */
	userPolicies: Record<string, unknown>;
	workspaceRoot: string;
	/** Whether an interactive UI exists to prompt the user. */
	hasUI: boolean;
	guardian?: Guardian;
	signal?: AbortSignal;
	/** The user's recent instruction(s), forwarded to the Guardian for intent-aware judgment. */
	intent?: string;
	/**
	 * Hybrid only: escalate a heuristic-blocked (`deny`) exec call to the Guardian so it can
	 * allow ones the user explicitly requested. Upgrade-only — a judge deny/error/absence keeps
	 * the block. Default (in the caller) on; set false for strict prove-or-block.
	 */
	escalateBlocked?: boolean;
	/**
	 * When a call is blocked (proven danger/escape or unprovable), present a confirm dialog
	 * instead of a hard `deny` — but only when a UI exists. Headless runs still hard-deny.
	 * Default (in the caller) on; set false for a hard wall even interactively.
	 */
	promptOnBlock?: boolean;
	/** Extra absolute directories the user allowed for this session (heuristic/hybrid path containment). */
	allowedRoots?: readonly string[];
}

const EXEC_TIER: ToolTier = "exec";

function failSafe(hasUI: boolean, reason?: string): PermissionAction {
	if (hasUI) return reason ? { action: "prompt", reason, recommend: "deny" } : { action: "prompt", recommend: "deny" };
	return {
		action: "deny",
		reason: reason ? `Guardian unavailable: ${reason}` : "Guardian unavailable; denying to fail safe.",
	};
}

/**
 * Resolve the permission action for a tool call under a non-tier guard mode.
 *
 * - User per-tool policy is authoritative first (`deny` blocks, `allow` bypasses,
 *   `prompt` asks) — it never falls through to the heuristic/guardian path.
 * - `guardian`: ask the LLM judge for exec-tier calls; auto-allow others.
 * - `heuristic`: prove-or-block — `allow` on positive proof; otherwise blocked
 *   (proven danger/escape or `uncertain`), surfaced as a confirm dialog when
 *   `promptOnBlock` + UI, else a hard `deny`.
 * - `hybrid`: heuristic first; `uncertain` always escalates to the Guardian, and
 *   (when `escalateBlocked`) a proven `deny` escalates too — but only to allow an
 *   explicitly user-requested action. A call that stays blocked is a confirm
 *   dialog (`promptOnBlock` + UI) or a hard `deny`; a judge deny/error/absence
 *   keeps the block.
 */
export async function evaluatePermission(input: EvaluatePermissionInput): Promise<PermissionAction> {
	const {
		toolName,
		args,
		tier,
		mode,
		userPolicies,
		workspaceRoot,
		hasUI,
		guardian,
		signal,
		intent,
		escalateBlocked,
		promptOnBlock,
		allowedRoots,
	} = input;

	const userPolicy = Object.hasOwn(userPolicies, toolName) ? normalizePolicy(userPolicies[toolName]) : undefined;
	if (userPolicy === "deny") return { action: "deny", reason: `Blocked by user policy for ${toolName}.` };
	if (userPolicy === "allow") return { action: "allow" };
	if (userPolicy === "prompt")
		return { action: "prompt", reason: `Confirmation required by user policy for ${toolName}.` };

	// A blocked call: interactively (and when promptOnBlock) surface a confirm dialog so a human
	// can override; headless — or strict — it is a hard deny. User-policy denies above are
	// absolute and never routed through here.
	const block = (reason: string): PermissionAction =>
		hasUI && promptOnBlock ? { action: "prompt", reason, recommend: "deny" } : { action: "deny", reason };

	const runGuardian = async (opts: { reason?: string; blocked?: boolean }): Promise<PermissionAction> => {
		if (!guardian) return failSafe(hasUI, opts.reason);
		const verdict = await guardian.evaluate(
			{ toolName, args, reason: opts.reason, cwd: workspaceRoot, intent, blocked: opts.blocked },
			signal,
		);
		if (verdict.decision === "allow") return { action: "allow" };
		if (verdict.decision === "deny") return block(verdict.reason);
		return failSafe(hasUI, opts.reason);
	};

	if (mode === "guardian") {
		return tier === EXEC_TIER ? runGuardian({}) : { action: "allow" };
	}

	// heuristic / hybrid: prove-or-block three-state verdict.
	const verdict = classifyHeuristic(toolName, args, { workspaceRoot, tier, extraRoots: allowedRoots });
	if (verdict.decision === "allow") return { action: "allow" };

	if (verdict.decision === "deny") {
		const reason = verdict.reason ?? `Blocked by safety heuristic for ${toolName}.`;
		// hybrid: give the Guardian a chance to honor an explicitly user-requested dangerous
		// action. Upgrade-only — a Guardian that denies, errors, or is unavailable leaves the
		// block in place, so the safety net never weakens when no judge can adjudicate intent.
		if (mode === "hybrid" && escalateBlocked && guardian) {
			const escalated = await guardian.evaluate(
				{ toolName, args, reason, cwd: workspaceRoot, intent, blocked: true },
				signal,
			);
			if (escalated.decision === "allow") return { action: "allow" };
		}
		return block(reason);
	}

	// uncertain
	if (mode === "heuristic") {
		return block(verdict.reason ?? `Refusing un-provable call for ${toolName}.`);
	}
	// hybrid: escalate the uncertain call to the Guardian judge.
	return runGuardian({ reason: verdict.reason });
}

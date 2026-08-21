/**
 * Permission orchestrator. Maps a tool call + guard mode to a concrete action
 * (`allow` / `deny` / `prompt`), layering the heuristic blacklist and the
 * Guardian LLM judge. Adapted from PR #1510's `tools/permission/evaluate.ts`;
 * the tier-mode delegation is dropped (core still owns `always-ask`/`write`/
 * `yolo`) — this only implements the new `heuristic` / `guardian` / `hybrid`
 * modes on top.
 */
import type { GuardianRequest, GuardianVerdict } from "./guardian";
import { classifyHeuristic, isProvablySafeHubCall } from "./heuristic";
import { globToRegExp } from "./path-utils";
import { normalizePolicy, type ToolTier } from "./tier";

export type GuardMode = "heuristic" | "guardian" | "hybrid";

export type PermissionAction =
	| { action: "allow"; loadedSkill?: string }
	| { action: "deny"; reason: string }
	| { action: "prompt"; reason?: string; recommend?: "allow" | "deny"; judged?: boolean; confidence?: number; guardianError?: boolean; skillLoad?: { kind: "skill" | "rule"; name: string } };

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
	/** Directories the user allowed for this session (from `/add-dir` + session dialog choices) — recursive containment. */
	sessionRoots?: readonly string[];
	/** Config glob → policy map (`allow`|`deny`) for exact-path matching. From config `paths`. */
	allowedPaths?: Record<string, string>;
	/**
	 * Per-skill/rule load policy, keyed by a glob pattern matched against the doc NAME.
	 * Only `allow` and `deny` — `prompt` is excluded (a matched prompt is the same as no match:
	 * both escalate to the name-forward dialog). From config `skill`.
	 */
	skillLoadRules?: Record<string, "allow" | "deny">;
	/**
	 * Skill names the user allowed to load THIS session (via the skill-load dialog). A skill/rule
	 * load or resource read for a name in this set auto-allows without re-prompting — the "a loaded
	 * skill's resources need no further checks" rule. Config-allow-listed skills get this for free
	 * (their resources carry the same name and match the same glob), so this covers only the dynamic
	 * user-approved case. The caller owns the set and adds to it when a skill-load prompt is allowed.
	 */
	loadedSkills?: ReadonlySet<string>;
}

const EXEC_TIER: ToolTier = "exec";

function failSafe(hasUI: boolean, reason?: string): PermissionAction {
	if (hasUI)
		return reason
			? { action: "prompt", reason, recommend: "deny", guardianError: true }
			: { action: "prompt", recommend: "deny", guardianError: true };
	return {
		action: "deny",
		reason: reason ? `Guardian unavailable: ${reason}` : "Guardian unavailable; denying to fail safe.",
	};
}

/**
 * Resolve the configured policy for a skill/rule load by matching its NAME against the glob-keyed
 * `skillLoadRules`. A matching `deny` wins outright; otherwise a matching `allow` wins; a matching
 * `prompt` (or no match at all) yields `undefined`, meaning "escalate to the user". Kept here (not
 * in the caller) so both the check and its precedence are unit-tested through `evaluatePermission`.
 */
function resolveSkillPolicy(name: string, rules: Record<string, "allow" | "deny"> | undefined): "allow" | "deny" | undefined {
	if (!rules) return undefined;
	let allow = false;
	for (const [pattern, policy] of Object.entries(rules)) {
		if (!globToRegExp(pattern).test(name)) continue;
		if (policy === "deny") return "deny"; // deny short-circuits: it beats any allow match
		if (policy === "allow") allow = true;
	}
	return allow ? "allow" : undefined;
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
		sessionRoots,
		allowedPaths,
		skillLoadRules,
		loadedSkills,
	} = input;

	const userPolicy = Object.hasOwn(userPolicies, toolName) ? normalizePolicy(userPolicies[toolName]) : undefined;
	if (userPolicy === "deny") return { action: "deny", reason: `Blocked by user policy for ${toolName}.` };
	// Secret reads/greps are denied unconditionally — even a user/omp `allow` or `prompt` policy
	// cannot override the hard deny for secret-file access. Check this before honoring allow/prompt.
	if (toolName === "read" || toolName === "grep") {
		const rv = classifyHeuristic(toolName, args, { workspaceRoot, tier, extraRoots: sessionRoots, allowedPaths });
		if (rv.secret) return { action: "deny", reason: rv.reason ?? `Refusing to read a secret file via ${toolName}.` };
		// Skill/rule loads ride their own rail, governed by the glob-keyed `skill` policy map.
		// A matched `allow` auto-loads silently; a matched `deny` blocks; a matched `prompt` or no
		// match escalates to the user via the dedicated name-forward dialog (or, headless, a
		// fail-safe deny). It never rides the generic (scary, escape-framed) internal-URL prompt.
		if (rv.skillLoad) {
			const { kind, name } = rv.skillLoad;
			// A skill already trusted this session (loaded via config OR a prior dialog allow) needs no
			// further checks — its resources (references, scripts, SKILL.md) auto-allow. A `deny` wins.
			const policy = resolveSkillPolicy(name, skillLoadRules);
			if (policy === "deny") return { action: "deny", reason: `Blocked ${kind} load "${name}" by skill policy.` };
			if (loadedSkills?.has(name)) return { action: "allow" };
			// A config `allow` is a first-class trust source: record it (via `loadedSkill`) so every
			// later resource of this skill is trusted uniformly, exactly like a dialog allow.
			if (policy === "allow") return { action: "allow", loadedSkill: name };
			const reason = rv.reason ?? `Load ${kind} "${name}" into context`;
			if (!hasUI) return { action: "deny", reason: `${reason} — no skill allow rule and no UI to confirm.` };
			return { action: "prompt", reason, recommend: "allow", skillLoad: rv.skillLoad };
		}
	}
	if (userPolicy === "allow") return { action: "allow" };
	if (userPolicy === "prompt")
		return { action: "prompt", reason: `Confirmation required by user policy for ${toolName}.` };

	// A blocked call: interactively (and when promptOnBlock) surface a confirm dialog so a human
	// can override; headless — or strict — it is a hard deny. User-policy denies above are
	// absolute and never routed through here.
	// `judged` marks a prompt whose deny is the Guardian model's own ruling (as
	// opposed to a heuristic block or a fail-safe), so the UI can attribute it.
	const block = (reason: string, judged = false, confidence?: number): PermissionAction =>
		hasUI && promptOnBlock ? { action: "prompt", reason, recommend: "deny", judged, confidence } : { action: "deny", reason };

	const runGuardian = async (opts: { reason?: string; blocked?: boolean }): Promise<PermissionAction> => {
		if (!guardian) return failSafe(hasUI, opts.reason);
		const verdict = await guardian.evaluate(
			{ toolName, args, reason: opts.reason, cwd: workspaceRoot, intent, blocked: opts.blocked },
			signal,
		);
		if (verdict.decision === "allow") return { action: "allow" };
		if (verdict.decision === "deny") return block(verdict.reason, true, verdict.confidence);
		return failSafe(hasUI, opts.reason);
	};

	if (mode === "guardian") {
		// `hub` is exec-tier, but its coordination/inspection ops carry no host risk;
		// auto-allow them so the judge is never invoked for benign agent messaging.
		if (tier === EXEC_TIER && toolName === "hub" && isProvablySafeHubCall(args)) return { action: "allow" };
		// `grep` and `read` are read-tier but can reach anywhere on disk (secret/env
		// files, paths outside the workspace); prove them here and escalate only the
		// unprovable ones to the judge (an in-workspace, non-secret access never
		// bothers the model). Every other read-tier tool is auto-allowed.
		if (toolName === "grep" || toolName === "read") {
			const rv = classifyHeuristic(toolName, args, { workspaceRoot, tier, extraRoots: sessionRoots, allowedPaths });
			if (rv.decision === "allow") return { action: "allow" };
			// A secret/env-file read is always a hard deny — never the guardian, never the user.
			if (rv.secret) return { action: "deny", reason: rv.reason ?? `Refusing to read a secret file via ${toolName}.` };
			// Otherwise an unprovable workspace escape -> escalate to the judge.
			return runGuardian({ reason: rv.reason, blocked: false });
		}
		return tier === EXEC_TIER ? runGuardian({}) : { action: "allow" };
	}

	// heuristic / hybrid: prove-or-block three-state verdict.
	const verdict = classifyHeuristic(toolName, args, { workspaceRoot, tier, extraRoots: sessionRoots, allowedPaths });
	if (verdict.decision === "allow") return { action: "allow" };

	if (verdict.decision === "deny") {
		const reason = verdict.reason ?? `Blocked by safety heuristic for ${toolName}.`;
		// A secret/env-file read is always a hard, non-escalatable deny — no guardian upgrade,
		// no confirm dialog. This is the only deny that unconditionally skips the ladder below.
		if (verdict.secret) return { action: "deny", reason };
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

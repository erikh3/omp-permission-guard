import { extractAllApprovalPaths } from "./approval-path";
import type { ToolTier } from "./tier";
import { extractLeadingCd } from "./bash-cwd";
import { matchCriticalBashPattern } from "./critical-bash-patterns";
import { isInternalUrlPath } from "./path-utils";
import { classifyRiskyPath, isPathInside, realpathOrSelf, resolveTargetPath } from "./risky-paths";
import { analyzeBashCommand, containsDangerousCode } from "./safety-net/index";

/**
 * Heuristic verdict — a THREE-state decision, deliberately not a boolean.
 *
 * The previous binary `block | null` overloaded `null` to mean BOTH "proven
 * workspace-safe" AND "found nothing wrong" — and every shell/tool construct
 * that relocated the effective target (mid-command `cd`, subshell, `lsp request`,
 * the next exec tool) slipped through the second meaning, generating an
 * open-ended stream of bypasses. The fix is prove-or-block: `allow` requires
 * POSITIVE proof of a recognized-safe shape; anything that cannot be proven safe
 * is `uncertain` and fails safe at the orchestrator (heuristic → deny, hybrid →
 * escalate to the Guardian judge). `deny` is reserved for proven-dangerous /
 * proven-out-of-workspace calls.
 */
export type HeuristicDecision = "allow" | "deny" | "uncertain";

export interface HeuristicVerdict {
	decision: HeuristicDecision;
	reason?: string;
}

const ALLOW: HeuristicVerdict = { decision: "allow" };
const deny = (reason: string): HeuristicVerdict => ({ decision: "deny", reason });
const uncertain = (reason: string): HeuristicVerdict => ({ decision: "uncertain", reason });

/** Context required to evaluate path-based heuristics. */
export interface HeuristicContext {
	workspaceRoot: string;
	/** Resolved tool tier; lets the classifier fail safe on unknown write-tier tools. */
	tier?: ToolTier;
	/**
	 * Extra absolute directories the user allowed for this session. A path inside
	 * any of these is treated as in-bounds, exactly like the workspace root.
	 */
	extraRoots?: readonly string[];
}

/**
 * LSP `request` forwards a caller-chosen JSON-RPC method + payload straight to
 * the language server, so it is only provably safe for a frozen set of read-only
 * methods. Everything else (notably `workspace/executeCommand` /
 * `workspace/applyEdit` and any unknown/custom method) is `uncertain`. Adding a
 * method here is a reviewed one-line change — the DEFAULT is fail-safe.
 */
const SAFE_LSP_REQUEST_METHODS: ReadonlySet<string> = new Set([
	"textDocument/hover",
	"textDocument/definition",
	"textDocument/typeDefinition",
	"textDocument/declaration",
	"textDocument/implementation",
	"textDocument/references",
	"textDocument/documentSymbol",
	"textDocument/documentHighlight",
	"textDocument/completion",
	"textDocument/signatureHelp",
	"textDocument/foldingRange",
	"textDocument/selectionRange",
	"textDocument/semanticTokens/full",
	"textDocument/inlayHint",
	"workspace/symbol",
]);

/** Commands that change the working directory the rest of the line runs in. */
const RELOCATORS: ReadonlySet<string> = new Set(["cd", "pushd", "popd", "chdir", "chroot"]);

/** Leading `VAR=value` inline-assignment token. */
const ENV_ASSIGNMENT = /^[A-Za-z_]\w*=/;
/** Shell wrappers that pass through to the real command (`builtin cd …`, `command cd …`). */
const COMMAND_WRAPPERS: ReadonlySet<string> = new Set(["builtin", "command"]);
/**
 * Drop leading inline assignments + `builtin`/`command` wrappers so a wrapped
 * relocator (`builtin cd …`, `X=1 cd …`) is still recognized by RELOCATORS.
 */
function stripCommandPrefix(tokens: string[]): string[] {
	let i = 0;
	while (i < tokens.length && (ENV_ASSIGNMENT.test(tokens[i]!) || COMMAND_WRAPPERS.has(tokens[i]!))) i++;
	return tokens.slice(i);
}

/** Compound / control-flow keywords whose cwd cannot be tracked by flat segmentation. */
const CONTROL_FLOW = /(?:^|[;&|\n\r({]\s*)(?:if|then|elif|else|fi|for|while|until|do|done|case|esac|select|function)\b/;

/** A `-C` / `--directory` style chdir flag on any tool (git, make, tar, env, rsync, …). */
const CHDIR_FLAG = /(?:^|\s)(?:-C|--directory|--chdir|--working-directory)(?:[=\s]|$)/;

/**
 * Shell re-entry: a nested interpreter (`bash -c`, `/bin/sh -c`) or an `eval` /
 * `source` / `.` builtin re-parses a string or file this flat analyzer cannot
 * inspect, so the effective command is unknowable here → `uncertain`. `exec` is
 * deliberately EXCLUDED: `exec cmd …` replaces the shell with a command whose
 * arguments are still statically visible, so it is not opaque re-entry — flagging
 * it would only deny ordinary `exec make`-style calls. (A re-entry that also
 * fetches and pipes to a shell is caught earlier by the terminal critical-pattern
 * check.)
 */
const SHELL_REENTRY = /(?:^|[;&|\n\r(]\s*)(?:eval|source|\.)\s/;
const SHELL_DASH_C = /(?:^|[;&|\n\r(]\s*)(?:\S*\/)?(?:bash|sh|zsh|dash|ash|ksh|fish)(?:\s+-\S+)*\s+-c\b/;
/**
 * A general-purpose interpreter invoked with an inline-code flag (`python -c`, `node -e`,
 * `ruby -e`, `perl -e/-E`, `php -r`, `R -e`, …). The embedded program is arbitrary code in another
 * language, so the shell-shaped static analysis below cannot reason about what it reads or writes
 * (e.g. `python3 -c "open('/etc/x','w')…"` hides an absolute path inside quoted code that the
 * whitespace path scan misreads as an in-workspace relative token). The interpreter is anchored to
 * a segment head (after optional `VAR=…` assignments / `env`,`sudo`,… wrappers) so a mere mention
 * inside a string never trips it.
 */
const INTERPRETER_INLINE_CODE =
	/(?:^|[;&|\n\r(]\s*)(?:\w+=\S+\s+|(?:env|sudo|doas|time|nice|nohup|xargs|stdbuf)\s+)*(?:\S*\/)?(?:python[0-9.]*|nodejs|node|bun|deno|ruby|perl|php|luajit|lua|Rscript|R)\b[^;&|\n\r]*?\s-{1,2}(?:c|e|E|r|p|eval|exec|print)\b/;
/** `deno eval <code>` runs inline code via a subcommand (no `-e` flag), so it needs its own probe. */
const DENO_EVAL = /(?:^|[;&|\n\r(]\s*)(?:\w+=\S+\s+|(?:env|sudo|doas|time|nice|nohup)\s+)*(?:\S*\/)?deno\s+eval\b/;

function asRecord(value: unknown): Record<string, unknown> {
	return value && typeof value === "object" ? (value as Record<string, unknown>) : {};
}

/** A path argument as a string list (a bare string or an array of strings). */
function stringValues(value: unknown): string[] {
	if (typeof value === "string") return [value];
	if (Array.isArray(value)) return value.filter((v): v is string => typeof v === "string");
	return [];
}

/** True when `p` sits inside any session-allowed extra root. */
function isWithinExtraRoot(p: string, ctx: HeuristicContext): boolean {
	const roots = ctx.extraRoots;
	if (!roots || roots.length === 0) return false;
	const real = realpathOrSelf(p);
	return roots.some(root => isPathInside(real, realpathOrSelf(root)));
}

/**
 * Risky-path reason for a single target, or `null` when it is an in-workspace /
 * internal-URL / unknown path that carries no escape risk. Mirrors the skip rules
 * the edit tool's own approval uses.
 */
function riskyPathReason(targetPath: string, ctx: HeuristicContext): string | null {
	if (!targetPath || targetPath === "(unknown)" || isInternalUrlPath(targetPath)) return null;
	if (isWithinExtraRoot(targetPath, ctx)) return null;
	return classifyRiskyPath(targetPath, ctx.workspaceRoot)?.reason ?? null;
}

/**
 * Verdict for a set of caller-supplied write paths. An EMPTY list is `uncertain`
 * ("no path to check" ≠ "proven safe"), NOT `allow` — closing the overloaded-null
 * leak. A risky path → `deny`; all in-workspace → `allow`.
 */
function classifyPathsOrUncertain(paths: string[], ctx: HeuristicContext, label: string): HeuristicVerdict {
	if (paths.length === 0) return uncertain(`${label} has no checkable in-workspace path`);
	for (const p of paths) {
		const reason = riskyPathReason(p, ctx);
		if (reason) return deny(reason);
	}
	return ALLOW;
}

/** True when a `cd` argument is a workspace-relative or absolute literal we can resolve statically. */
function isLiteralPath(target: string): boolean {
	if (!target) return false;
	if (target.includes("$") || target.includes("`")) return false; // variable / command substitution
	if (target.includes("~")) return false; // home expansion — not provably in-workspace
	return !/[*?[]/.test(target); // globs are not a single literal target
}

/** A glued redirection operator (`>`, `>>`, `2>`, `&>`, `<`) that can prefix a path token. */
const REDIRECTION_PREFIX = /^(?:[0-9]*|&)?(?:>>|>|<)/;

/**
 * Extract the filesystem-path candidate from a single shell token, or `null` when
 * the token is a bare word / operator that names no path. Strips a glued
 * redirection operator and surrounding quotes. For an OPTION token (`-o=/x`,
 * `--out=/x`) the value after the first `=` is taken; a plain argument is kept
 * whole so a path that legitimately contains `=` (`/etc/a=b`) is not truncated.
 * Only tokens carrying a `/` separator or a `~` home prefix are returned — a bare
 * word resolves under the cwd and is no escape risk.
 */
function bashPathArgument(token: string): string | null {
	// Unquote FIRST so a fully-quoted option (`"--out=/etc/x"`) is recognized as
	// an option, not mistaken for a bare argument.
	let t = unquote(token.replace(REDIRECTION_PREFIX, ""));
	if (t.startsWith("-")) {
		const eq = t.indexOf("=");
		if (eq === -1) return null; // a bare `-flag` names no path
		t = unquote(t.slice(eq + 1)); // option value may itself be quoted (`--out="/x"`)
	}
	if (!t) return null;
	return t.includes("/") || t.startsWith("~") ? t : null;
}

/** Strip a single leading and/or trailing quote (best-effort; not full shell unquoting). */
function unquote(s: string): string {
	return s.replace(/^["']|["']$/g, "");
}

/** The shell-effective word: strip surrounding quotes + a leading backslash so a
 *  disguised relocator (`\cd`, `'cd'`, `"cd"`) or quoted target is seen as-run. */
function dequoteWord(token: string): string {
	return unquote(token).replace(/^\\/, "");
}

/**
 * Prove-or-block predicate for the bash tool. Returns `allow` ONLY for a flat,
 * statically-analyzable command that provably stays in the workspace and carries
 * no dangerous effect; `deny` for proven-dangerous / proven-escape; `uncertain`
 * for every construct that defeats static cwd-tracking (subshell, substitution,
 * control flow, shell re-entry, here-doc, background, non-leading / dynamic `cd`,
 * tool chdir flags). First firing rule wins.
 */
function proveBashSafe(
	rawCommand: string,
	rawCwdArg: string | undefined,
	ctx: HeuristicContext,
	callerEnv: Record<string, unknown> = {},
): HeuristicVerdict {
	if (rawCommand.trim() === "") return ALLOW;

	// STEP 0: a safety-critical pattern (rm -rf /, fork bomb, curl|bash, mkfs, …) is
	// never legitimate and is cwd-independent, so it is a TERMINAL deny — it must win
	// over the STEP-2/3 "uncertain" gates (e.g. a fork bomb's background `&` and
	// braces would otherwise mask it as merely un-provable).
	if (matchCriticalBashPattern(rawCommand)) return deny("Critical bash pattern detected.");

	const root = ctx.workspaceRoot;
	const realRoot = realpathOrSelf(root);

	// STEP 1: explicit cwd arg. Provable escape → deny. When present it pins the
	// effective cwd and SUPPRESSES leading-cd proving (matching BashTool's `if (!cwd)`).
	let effectiveCwd = root;
	const hasExplicitCwd = typeof rawCwdArg === "string" && rawCwdArg.length > 0;
	if (hasExplicitCwd) {
		if (isInternalUrlPath(rawCwdArg as string))
			return uncertain(`Cannot prove bash internal-URL cwd stays in workspace: ${rawCwdArg}`);
		const resolved = realpathOrSelf(resolveTargetPath(rawCwdArg as string, root));
		if (!isPathInside(resolved, realRoot) && !isWithinExtraRoot(resolved, ctx)) {
			return deny(`Refusing to run bash outside the workspace root: ${resolved}`);
		}
		effectiveCwd = resolved;
	}

	// STEP 2: constructs that defeat static segmentation / cwd-tracking → uncertain.
	if (/\$\(|`/.test(rawCommand))
		return uncertain("Cannot prove bash command stays in workspace: command substitution");
	if (/[<>]\(/.test(rawCommand))
		return uncertain("Cannot prove bash command stays in workspace: process substitution");
	if (/(?:^|[;&|\n\r]\s*)\(/.test(rawCommand))
		return uncertain("Cannot prove bash command stays in workspace: subshell");
	if (/(?:^|[;&|\n\r]\s*)\{\s/.test(rawCommand))
		return uncertain("Cannot prove bash command stays in workspace: brace group");
	if (CONTROL_FLOW.test(rawCommand))
		return uncertain("Cannot prove bash compound/control-flow command stays in workspace");
	if (/<</.test(rawCommand)) return uncertain("Cannot prove bash command stays in workspace: here-document");
	// Background `&` (not part of `&&`, and not a `>&` / `&>` / `&digit` redirection).
	if (/(?<![>&])&(?!&|>|\d)/.test(rawCommand))
		return uncertain("Cannot prove bash command stays in workspace: background job");
	if (SHELL_REENTRY.test(rawCommand) || SHELL_DASH_C.test(rawCommand))
		return uncertain("Cannot prove bash command stays in workspace: nested shell re-entry");
	if (INTERPRETER_INLINE_CODE.test(rawCommand) || DENO_EVAL.test(rawCommand))
		return uncertain("Cannot prove bash command stays in workspace: interpreter inline code");

	// STEP 3: segment split (INCLUDING newlines) + relocation scan.
	const segments = rawCommand.split(/&&|\|\||[;|\n\r]+/);
	for (let i = 0; i < segments.length; i++) {
		const seg = segments[i]!.trim();
		if (!seg) continue;
		const tokens = stripCommandPrefix(seg.split(/\s+/));
		const head = dequoteWord(tokens[0] ?? "");
		if (RELOCATORS.has(head)) {
			const target = dequoteWord(tokens[1] ?? "");
			// A literal `cd` in the FIRST segment runs unconditionally before anything
			// else, so its destination is statically provable: outside the workspace →
			// a proven escape (deny); inside → a proven relocation we keep analyzing
			// from. Every OTHER relocator (a later-segment `cd`, a `pushd`/`chroot`, or
			// a dynamic target) is `uncertain`: proving where a non-leading `cd` lands
			// needs the effective cwd simulated across the intervening segments, and
			// that multi-segment cwd tracking is exactly where the earlier bypasses
			// hid. Failing safe is sound here — heuristic mode denies and hybrid
			// escalates to the judge, so a punted `cd` is never weaker than a deny.
			if (i === 0 && head === "cd" && isLiteralPath(target)) {
				const resolved = realpathOrSelf(resolveTargetPath(target, root));
				if (!isPathInside(resolved, realRoot) && !isWithinExtraRoot(resolved, ctx)) {
					return deny(`Refusing to run bash outside the workspace root: ${resolved}`);
				}
				if (!hasExplicitCwd) effectiveCwd = resolved; // proven in-workspace relocation
				continue;
			}
			return uncertain(`Cannot prove bash '${head}' keeps execution in the workspace`);
		}
		if (CHDIR_FLAG.test(seg)) {
			return uncertain(`Cannot prove tool chdir flag in '${head}' stays in workspace`);
		}
	}

	// STEP 4: proven-dangerous EFFECT (cwd-sensitive) → deny. A proven leading
	// `cd X && …` is stripped (via the SAME helper BashTool uses, so the two can't
	// drift) so the analyzer sees the remaining command in its effective cwd. The
	// cwd-independent critical patterns were already handled terminally in STEP 0.
	const commandForAnalysis = hasExplicitCwd ? rawCommand : extractLeadingCd(rawCommand).command;
	const result = analyzeBashCommand(commandForAnalysis, effectiveCwd);
	if (result) return deny(result.reason);

	// STEP 4.5: a path-shaped ARGUMENT or redirection target that resolves outside
	// the workspace is unprovable → `uncertain`. The analyzer only flags a fixed
	// denylist of destructive shapes (rm -rf, …); a plain `touch /etc/omp-test` or
	// `… > ~/.ssh/config` writes outside the workspace yet reads "clean".
	//
	// This is a deliberately shallow whitespace scan, NOT a shell parser — the
	// lightweight permission module must not take on a tokenizer dependency. It can
	// over-escalate (a `/`-bearing substring inside a quoted string) and a path
	// split across quoted whitespace may be seen only in fragments, but BOTH fail
	// toward `uncertain`, never toward a false `allow`: a flat string cannot tell a
	// read from a write, so an unprovable path escalates (heuristic denies, hybrid
	// asks the judge) rather than hard-denying. Relative tokens resolve from the
	// effective cwd; containment is checked against the workspace root.
	for (const token of commandForAnalysis.split(/\s+/)) {
		const candidate = bashPathArgument(token);
		if (!candidate) continue;
		if (isInternalUrlPath(candidate))
			return uncertain(`Cannot prove bash internal-URL target stays in workspace: ${candidate}`);
		if (riskyPathReason(resolveTargetPath(candidate, effectiveCwd), ctx)) {
			return uncertain(`Cannot prove bash path argument stays in workspace: ${candidate}`);
		}
	}

	// STEP 4.6: a caller-supplied env value that resolves outside the workspace is
	// unprovable → uncertain. BashTool.execute passes `env` into the shell and the
	// command can reference it ($OUT) with no path-shaped token of its own, so the
	// command-only scan above cannot see it. A benign value (a flag, a word) resolves
	// under the effective cwd and is no risk; a path value that escapes does.
	for (const value of Object.values(callerEnv)) {
		if (typeof value !== "string") continue;
		if (isInternalUrlPath(value))
			return uncertain(`Cannot prove bash env internal-URL value stays in workspace: ${value}`);
		if (riskyPathReason(resolveTargetPath(value, effectiveCwd), ctx)) {
			return uncertain(`Cannot prove bash env value stays in workspace: ${value}`);
		}
	}

	// STEP 5: proven safe.
	return ALLOW;
}

/**
 * Classify a tool call by tool name under prove-or-block semantics.
 *
 * - `bash`: `proveBashSafe` (see there) — allow only a flat in-workspace command
 *   with no dangerous effect; uncertain for anything that relocates execution.
 * - `todo`: session-local task tracker with no fs/exec effect → always allow.
 * - `eval`: a destructive shell pattern embedded in the code → deny; otherwise
 *   uncertain (arbitrary unsandboxed code is never provably safe).
 * - `write` / `edit` / `ast_edit` / `tts`: every caller-supplied path proved
 *   in-workspace → allow; a risky one → deny; NO path supplied → uncertain.
 * - `lsp`: read-tier → allow; `request` allowed only for a frozen read-only
 *   method set; write actions via the path rule.
 * - `generate_image` / `report_tool_issue`: fixed write target, no caller path → allow.
 * - any other write/exec-tier tool → uncertain (cannot introspect); read-tier → allow.
 */
export function classifyHeuristic(toolName: string, args: unknown, ctx: HeuristicContext): HeuristicVerdict {
	const record = asRecord(args);
	switch (toolName) {
		case "todo":
			// Session-local task tracker: no filesystem or exec effect, always safe.
			return ALLOW;
		case "bash": {
			const command = typeof record.command === "string" ? record.command : "";
			const rawCwd = typeof record.cwd === "string" && record.cwd.length > 0 ? record.cwd : undefined;
			const env = asRecord(record.env); // {} when absent
			return proveBashSafe(command, rawCwd, ctx, env);
		}
		case "eval": {
			// The eval tool passes a single `code` string (batch variants may use a
			// `cells` array); gather every fragment. A shell-dangerous pattern embedded
			// in the code (e.g. os.system("rm -rf …")) is a deny; otherwise arbitrary
			// unsandboxed code cannot be statically proven safe -> uncertain.
			const fragments: string[] = [];
			if (typeof record.code === "string") fragments.push(record.code);
			if (Array.isArray(record.cells)) {
				for (const cell of record.cells) {
					const cellCode = asRecord(cell).code;
					if (typeof cellCode === "string") fragments.push(cellCode);
				}
			}
			if (fragments.some(containsDangerousCode)) {
				return deny("Detected a potentially destructive command in eval code.");
			}
			return uncertain("eval runs arbitrary unsandboxed code and cannot be statically proven workspace-safe");
		}
		case "write":
		case "edit":
			// `extractAllApprovalPaths` covers the plain `path` field AND every
			// apply-patch / hashline section and rename destination. An empty list
			// (e.g. `write { path: "" }`) is uncertain, not allow.
			return classifyPathsOrUncertain(extractAllApprovalPaths(args), ctx, toolName);
		case "ast_edit":
			return classifyPathsOrUncertain(stringValues(record.paths), ctx, "ast_edit");
		case "tts":
			return classifyPathsOrUncertain(stringValues(record.output_path), ctx, "tts");
		case "lsp": {
			const action = typeof record.action === "string" ? record.action : "";
			if (action === "request") {
				const method = typeof record.query === "string" ? record.query : "";
				return SAFE_LSP_REQUEST_METHODS.has(method)
					? ALLOW
					: uncertain(`lsp request method not provably safe: ${method || "(none)"}`);
			}
			if (ctx.tier !== "write") return ALLOW;
			return classifyPathsOrUncertain(
				[...stringValues(record.file), ...stringValues(record.new_name)],
				ctx,
				`lsp ${action || "write action"}`,
			);
		}
		case "generate_image":
		case "report_tool_issue":
			// Write-tier, but the write target is fixed / tool-allocated with no
			// caller-controlled path (`generate_image.input[].path` is a read source).
			return ALLOW;
		default:
			// An unrecognized write- or exec-tier tool cannot be introspected for
			// safety, so it is uncertain — heuristic mode denies, hybrid escalates to
			// the judge. This is why a future exec tool (or `task`, which spawns yolo
			// subagents) cannot silently bypass the mode. Read-tier carries no risk.
			return ctx.tier === "write" || ctx.tier === "exec"
				? uncertain(`Un-vetted ${ctx.tier}-tier tool: ${toolName}`)
				: ALLOW;
	}
}

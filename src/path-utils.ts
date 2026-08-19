/**
 * Local reimplementation of core `isInternalUrlPath`
 * (`packages/coding-agent/src/tools/path-utils.ts`).
 *
 * True when a tool path argument uses one of omp's internal URL schemes and so
 * must NOT be treated as a filesystem path. The heuristic uses this to punt
 * internal-URL bash/edit targets to `uncertain` instead of misreading them as
 * in-workspace relative paths. Kept in sync with core's
 * `TOP_LEVEL_INTERNAL_URL_PREFIXES`.
 */
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

const INTERNAL_URL_PREFIXES = [
	"agent://",
	"artifact://",
	"skill://",
	"rule://",
	"local://",
	"mcp://",
	"ssh://",
	"vault://",
] as const;

/** Fold a single-slash `local:/x` into the canonical `local://x` form. */
function normalizeLocalScheme(filePath: string): string {
	return filePath.replace(/^(local:)\/(?!\/)/, "$1//");
}

function expandTilde(filePath: string): string {
	if (filePath === "~") return os.homedir();
	if (filePath.startsWith("~/") || filePath.startsWith("~\\")) return os.homedir() + filePath.slice(1);
	return filePath;
}

export function isInternalUrlPath(filePath: string): boolean {
	const normalized = normalizeLocalScheme(filePath.trim());
	const expanded = normalizeLocalScheme(expandTilde(normalized));
	return INTERNAL_URL_PREFIXES.some(prefix => normalized.startsWith(prefix) || expanded.startsWith(prefix));
}

/**
 * Session-local internal URL schemes that resolve only within the calling session's own
 * artifact directory and so carry no workspace-escape or arbitrary-filesystem-read risk:
 *
 * - `artifact://<numericId>` — this session's spilled/truncated tool output (session-local
 *   monotonic IDs, served `text/plain`, capped at 8 MiB).
 * - `agent://<id>` — this session's subagent output (`<id>.md` under the same artifact dir).
 *
 * Every OTHER internal scheme can reach outside the session (`ssh://` remote hosts, `vault://`,
 * `local://`, `mcp://`, `skill://`, `rule://`), so those stay `isInternalUrlPath`-only and remain
 * un-provable. Kept narrow on purpose.
 */
const SESSION_LOCAL_URL_PREFIXES = ["artifact://", "agent://"] as const;

/** True when a path is a session-local artifact/agent URL that cannot escape the session. */
export function isSessionLocalInternalUrl(filePath: string): boolean {
	const normalized = filePath.trim();
	return SESSION_LOCAL_URL_PREFIXES.some(prefix => normalized.startsWith(prefix));
}

/**
 * Internal URL schemes that resolve to omp's own installed, read-only instruction
 * docs (`skill://<name>` skill guides, `rule://<name>` rule details). A "skill load"
 * is the agent pulling one of these into context before acting — a benign, expected
 * step that carries no filesystem-escape or exfiltration risk, so it is gated on its
 * own rail (name-forward dialog, allow-leaning) rather than the scary generic
 * workspace-escape prompt every other un-provable internal URL gets.
 */
const SKILL_LOAD_PREFIXES = ["skill://", "rule://"] as const;

/**
 * When `filePath` is a `skill://` / `rule://` read, return `{ kind, name }` — the
 * scheme and the leading path segment (the skill/rule name, selector and subpath
 * stripped) — otherwise `undefined`.
 */
export function parseSkillLoad(filePath: string): { kind: "skill" | "rule"; name: string } | undefined {
	const normalized = filePath.trim();
	const prefix = SKILL_LOAD_PREFIXES.find(p => normalized.startsWith(p));
	if (!prefix) return undefined;
	const kind = prefix === "skill://" ? "skill" : "rule";
	// First path segment after the scheme, dropping any `/subpath` and `:selector` sugar.
	const rest = normalized.slice(prefix.length);
	const name = rest.split(/[/:]/, 1)[0]?.trim() ?? "";
	// Reject non-identifier names: empty, traversal components (`..`, `.`), or anything
	// containing a path separator. A garbage/traversal skill URL routes to the generic read
	// path (uncertain) rather than being tagged as a skill load and bypassing security gates.
	if (!name || name === "." || name === ".." || name.includes("/") || name.includes("\\")) return undefined;
	return { kind, name };
}

/** Best-effort realpath; returns the input unchanged when the path does not exist or errors. */
function realpathOrSelf(p: string): string {
	try {
		return fs.realpathSync(p);
	} catch {
		return p;
	}
}

/**
 * Compile a simple glob (only `*` and `?` are special; `*` spans `/`) to an anchored RegExp. Every
 * other regex metacharacter is escaped, so a pattern like `/tmp/*` matches literally plus wildcard.
 */
export function globToRegExp(pattern: string): RegExp {
	const body = pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".");
	return new RegExp(`^${body}$`);
}

/** Expand a leading `~`/`~/` to the home directory and normalize to an absolute path. */
function expandPathPattern(pattern: string): string {
	const t = pattern.trim();
	const expanded = t === "~" ? os.homedir() : t.startsWith("~/") ? path.join(os.homedir(), t.slice(2)) : t;
	return path.isAbsolute(expanded) ? path.normalize(expanded) : path.resolve(expanded);
}

/** The leading wildcard-free directory of a glob pattern, used to canonicalize a symlinked prefix (e.g. macOS `/tmp`). */
function staticPrefix(pattern: string): string {
	const star = pattern.search(/[*?]/);
	const head = star === -1 ? pattern : pattern.slice(0, star);
	return head.endsWith("/") ? head.slice(0, -1) : path.dirname(head);
}

/**
 * Resolve the configured policy for a filesystem target against the user's `paths` policy map
 * (glob → `allow`|`deny`). Matching is per-path and NON-recursive: a bare directory pattern
 * (`~/.omp/agent`) matches only that exact path — its contents need a trailing `/*`, and a single
 * file is just its path. Only `*`/`?` are wildcards; `*` spans `/`. Handles macOS prefix symlinks
 * (e.g. `/tmp` → `/private/tmp`) by canonicalizing both the pattern prefix and the target.
 *
 * Returns the first matched policy where `deny` short-circuits (beats `allow`), then `allow`; or
 * `undefined` when no pattern matches.
 */
export function resolvePathPolicy(
	targetPath: string,
	rules: Record<string, string> | undefined,
): "allow" | "deny" | undefined {
	if (!rules || Object.keys(rules).length === 0) return undefined;
	const rawTarget = path.isAbsolute(targetPath) ? path.normalize(targetPath) : path.resolve(targetPath);
	const realTarget = realpathOrSelf(rawTarget);
	let allow = false;
	for (const [raw, rawPolicy] of Object.entries(rules)) {
		if (typeof raw !== "string" || raw.trim() === "") continue;
		if (typeof rawPolicy !== "string") continue; // guard: config values may be non-string from JSON.parse
		const policy = rawPolicy.trim().toLowerCase();
		if (policy !== "allow" && policy !== "deny") continue;
		const expanded = expandPathPattern(raw);
		const prefix = staticPrefix(expanded);
		const realPrefix = realpathOrSelf(prefix);
		const canonPattern = realPrefix !== prefix && prefix ? realPrefix + expanded.slice(prefix.length) : expanded;
		let matched = false;
		for (const pat of new Set([expanded, canonPattern])) {
			const re = globToRegExp(pat);
			if (re.test(rawTarget) || re.test(realTarget)) { matched = true; break; }
		}
		if (!matched) continue;
		if (policy === "deny") return "deny"; // deny short-circuits
		allow = true;
	}
	return allow ? "allow" : undefined;
}

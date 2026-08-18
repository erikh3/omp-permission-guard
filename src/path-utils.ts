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
import * as os from "node:os";

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

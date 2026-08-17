import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

/** A block decision with a human-readable reason. */
export interface RiskyPathBlock {
	block: true;
	reason: string;
}

/** System roots that should never be written to from a dev session. */
const SYSTEM_ROOTS = ["/etc", "/usr", "/bin", "/sbin", "/boot", "/sys", "/proc"] as const;

/**
 * Resolve a tool-supplied path against the workspace root, expanding a leading
 * `~` and normalizing the result to an absolute path.
 */
export function resolveTargetPath(targetPath: string, workspaceRoot: string): string {
	let p = targetPath;
	if (p === "~") {
		p = os.homedir();
	} else if (p.startsWith("~/")) {
		p = path.join(os.homedir(), p.slice(2));
	}
	if (!path.isAbsolute(p)) {
		p = path.resolve(workspaceRoot, p);
	}
	return path.normalize(p);
}

/** True when `child` is `parent` itself or a path nested inside it. */
export function isPathInside(child: string, parent: string): boolean {
	const rel = path.relative(parent, child);
	return rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel));
}

/** Apply the sensitive-path / containment denylist to an absolute, normalized path. */
function classifyResolvedPath(resolved: string, root: string, home: string): RiskyPathBlock | null {
	const segments = resolved.split(path.sep).filter(Boolean);
	const base = path.basename(resolved);

	if (segments.includes(".ssh")) {
		return { block: true, reason: `Refusing to modify SSH path: ${resolved}` };
	}
	if (base === ".env" || base.startsWith(".env.")) {
		return { block: true, reason: `Refusing to modify environment file: ${resolved}` };
	}
	const gitIdx = segments.indexOf(".git");
	if (gitIdx !== -1 && gitIdx < segments.length - 1) {
		return { block: true, reason: `Refusing to modify .git internals: ${resolved}` };
	}
	for (const sys of SYSTEM_ROOTS) {
		if (resolved === sys || resolved.startsWith(`${sys}${path.sep}`)) {
			return { block: true, reason: `Refusing to modify system path: ${resolved}` };
		}
	}
	if (path.dirname(resolved) === home && base.startsWith(".")) {
		return { block: true, reason: `Refusing to modify home dotfile: ${resolved}` };
	}
	if (!isPathInside(resolved, root)) {
		return { block: true, reason: `Path is outside the workspace root: ${resolved}` };
	}
	return null;
}

/**
 * Filename patterns for files whose CONTENTS are secret and must not be read
 * (grepped / catted) even from inside the workspace. Deliberately focused on
 * credential-bearing files — not a general dotfile denylist — so ordinary
 * in-workspace source reads are never gated. Matched case-insensitively against
 * the basename; `.env` and its variants are handled separately (prefix match).
 */
const SECRET_FILE_PATTERNS: readonly RegExp[] = [
	/^\.env(\..+)?$/i, // .env, .env.local, .env.production, …
	/^\.netrc$/i,
	/^\.pgpass$/i,
	/^\.npmrc$/i,
	/^\.htpasswd$/i,
	/(^|[._-])secrets?([._-]|$)/i, // secret(s) as a whole word within the name
	/(^|[._-])credentials?([._-]|$)/i,
	/^id_(rsa|dsa|ecdsa|ed25519)$/i, // private SSH keys
	/\.(pem|key|pfx|p12|keystore|jks)$/i, // key material / keystores
] as const;

/** True when the basename or an enclosing `.ssh` segment marks the path as secret-bearing. */
function isSecretPath(resolved: string): boolean {
	const segments = resolved.split(path.sep).filter(Boolean);
	if (segments.includes(".ssh")) return true;
	const base = path.basename(resolved);
	return SECRET_FILE_PATTERNS.some(re => re.test(base));
}

/**
 * Classify a READ target (e.g. a `grep` search path). Unlike the write denylist,
 * a read is unremarkable anywhere inside the workspace — EXCEPT for secret / env
 * files, whose contents must not be exfiltrated even locally. Returns a reason
 * when the path is outside the workspace root OR names a secret/env file (so the
 * caller escalates it), and `null` for an ordinary in-workspace read.
 */
export function classifyReadPath(targetPath: string, workspaceRoot: string): string | null {
	const resolved = resolveWritePath(resolveTargetPath(targetPath, workspaceRoot));
	const root = realpathOrSelf(path.resolve(workspaceRoot));
	if (!isPathInside(resolved, root)) return `outside the workspace root: ${resolved}`;
	if (isSecretPath(resolved)) return `reads a secret or environment file: ${resolved}`;
	return null;
}

/** Best-effort realpath of an existing path; returns the input unchanged on failure. */
export function realpathOrSelf(p: string): string {
	try {
		return fs.realpathSync.native(p);
	} catch {
		return p;
	}
}

/** Bound on symlink hops while resolving a write target (matches the kernel's ELOOP guard intent). */
const MAX_SYMLINK_HOPS = 40;

/**
 * Best-effort resolution of where a write to `target` would actually land,
 * following symlinks on every component — including *dangling* symlinks (writing
 * through `link -> /etc/x` creates `/etc/x` even when it doesn't exist yet). Each
 * iteration realpaths the longest existing ancestor; if the first non-existing
 * tail element is itself a symlink, it is expanded and resolution restarts on the
 * rewritten path, so multi-hop chains (`a -> b/x`, `b -> /etc`) collapse to their
 * real destination. Bounded by `MAX_SYMLINK_HOPS`. Returns the best path reached.
 */
function resolveWritePath(target: string): string {
	let current = target;
	for (let hop = 0; hop < MAX_SYMLINK_HOPS; hop++) {
		const tail: string[] = [];
		let cur = current;
		let realPrefix: string | undefined;
		for (;;) {
			try {
				realPrefix = fs.realpathSync.native(cur);
				break;
			} catch {
				const parent = path.dirname(cur);
				if (parent === cur) break; // nothing on this path exists
				tail.unshift(path.basename(cur));
				cur = parent;
			}
		}
		if (realPrefix === undefined) return current; // fully non-existing path; lexical result stands
		if (tail.length === 0) return realPrefix; // whole path existed and was canonicalized

		// The first non-existing tail element may be a dangling symlink. A write
		// would follow it, so expand one hop and re-resolve the rewritten path.
		const leaf = path.join(realPrefix, tail[0]!);
		let expanded = false;
		try {
			if (fs.lstatSync(leaf).isSymbolicLink()) {
				const link = fs.readlinkSync(leaf);
				const linkTarget = path.isAbsolute(link) ? link : path.join(realPrefix, link);
				current = path.normalize(path.join(linkTarget, ...tail.slice(1)));
				expanded = true;
			}
		} catch {
			// Not a symlink (or vanished mid-check): treat as a plain non-existing path.
		}
		if (!expanded) return path.normalize(path.join(realPrefix, ...tail));
	}
	return current; // hop budget exhausted (symlink loop); caller still classifies it
}

/**
 * Classify a write/edit target path as risky.
 *
 * A path is risky when it is outside the workspace root, or when it matches a
 * sensitive denylist (`.ssh`, `.env*`, `.git` internals, system roots, or a
 * dotfile directly under the user's home directory). The check runs on both the
 * lexically-resolved path AND its symlink-resolved real target (compared against
 * the canonicalized root), so a workspace symlink pointing outside or at a
 * sensitive path cannot bypass the guard — the write/edit fs APIs follow the same
 * symlinks. Returns `null` for ordinary in-workspace paths.
 */
export function classifyRiskyPath(targetPath: string, workspaceRoot: string): RiskyPathBlock | null {
	const resolved = resolveTargetPath(targetPath, workspaceRoot);
	// Canonicalize the root once so a workspace that itself lives under a symlink
	// (e.g. macOS /tmp -> /private/tmp) doesn't make a legitimate in-workspace
	// target addressed by its real path look like an escape.
	const root = realpathOrSelf(path.resolve(workspaceRoot));
	const home = os.homedir();

	// Resolve where the write would actually land (following symlinks, including
	// dangling ones), then run a single containment/denylist check against the
	// canonical root. This collapses the former lexical-then-realpath two-phase
	// dance: a symlink escaping the workspace still resolves outside and blocks,
	// while a real-path target under a symlinked root resolves inside and passes.
	const real = resolveWritePath(resolved);
	return classifyResolvedPath(real, root, home);
}

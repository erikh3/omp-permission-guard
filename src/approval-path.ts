/**
 * Extract the target file path from `edit`-tool arguments across all edit
 * modes (bracket `[PATH#TAG]` header, legacy `¶PATH#…`/apply-patch headers, or a
 * plain `path` field). Returns `"(unknown)"` when no path can be determined.
 *
 * This is a pure, dependency-free helper shared by the edit tool's own approval
 * logic and the permission heuristic, so neither has to reimplement the
 * mode-specific extraction (which would risk drift).
 */
export function extractApprovalPath(args: unknown): string {
	const record = args && typeof args === "object" ? (args as Record<string, unknown>) : {};
	const input = typeof record.input === "string" ? record.input : undefined;
	if (input) {
		const bracketMatch = /^\[([^#\]]+)#[^\]]*\]/m.exec(input);
		if (bracketMatch?.[1]) return bracketMatch[1].trim();

		const hashlineMatch = /^(?:¶|§|@)([^\s#]+)/m.exec(input);
		if (hashlineMatch?.[1]) return hashlineMatch[1];

		const applyPatchMatch = /^\*\*\* (?:Add|Update|Delete) File:\s*(.+)$/m.exec(input);
		if (applyPatchMatch?.[1]) return applyPatchMatch[1].trim();
	}

	const targetPath = record.path;
	return typeof targetPath === "string" && targetPath.length > 0 ? targetPath : "(unknown)";
}

/**
 * Extract EVERY target path from `edit`-tool arguments: all `[PATH#TAG]` and
 * legacy `¶PATH#…` headers, all apply-patch `*** Add/Update/Delete File:`
 * sections, all `*** Move to:` / `MV` rename destinations, patch-mode
 * `edits[].rename` targets, and the plain `path` field (deduped).
 *
 * `extractApprovalPath` returns only the first path — enough for the approval
 * *prompt* label, but unsafe for a security check: a patch can touch many files
 * and apply them all, so a later section escaping the workspace must not be
 * hidden behind an in-workspace first section. Safety classification uses this.
 */
export function extractAllApprovalPaths(args: unknown): string[] {
	const record = args && typeof args === "object" ? (args as Record<string, unknown>) : {};
	const paths = new Set<string>();

	const input = typeof record.input === "string" ? record.input : undefined;
	if (input) {
		const add = (re: RegExp) => {
			for (const m of input.matchAll(re)) {
				const p = m[1]?.trim();
				if (p) paths.add(p);
			}
		};
		add(/^\[([^#\]]+)#[^\]]*\]/gm); // [PATH#TAG] section header
		add(/^(?:¶|§|@)([^\s#]+)/gm);
		add(/^\*\*\* (?:Add|Update|Delete) File:\s*(.+)$/gm);
		add(/^\*\*\* Move to:\s*(.+)$/gm);
		// `MV DEST` rename destination is a write target; strip surrounding quotes.
		for (const m of input.matchAll(/^MV\s+(.+?)\s*$/gm)) {
			const dest = m[1]?.replace(/^["']|["']$/g, "").trim();
			if (dest) paths.add(dest);
		}
	}

	const targetPath = record.path;
	if (typeof targetPath === "string" && targetPath.length > 0) paths.add(targetPath);

	// Patch mode (`{ path, edits: [{ op?, diff?, rename? }] }`): each edit's
	// `rename` is a write destination the top-level `path` scan would miss, so a
	// rename escaping the workspace must be caught here too.
	if (Array.isArray(record.edits)) {
		for (const entry of record.edits) {
			if (entry && typeof entry === "object" && "rename" in entry && typeof entry.rename === "string" && entry.rename.length > 0) {
				paths.add(entry.rename);
			}
		}
	}

	return [...paths];
}

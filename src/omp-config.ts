/**
 * Reads omp's own tool-approval allow-list from its `config.yml` so the guard
 * can honor rules the user already curated in the host, then applies them under
 * the guard's own `approval` map (which still wins on conflict).
 *
 * Why read the file at all: the omp extension API exposes NO way to obtain the
 * host's resolved config or approval policy at runtime. Neither `ExtensionAPI`
 * nor `ExtensionContext` carries a settings getter; `getAllTools()` returns tool
 * metadata without any policy field; and `SettingsManager` has a private
 * constructor, no static accessor, and does not even model `tools.approval` in
 * its typed `Settings`. So disk is the only source.
 *
 * Fidelity is deliberately "profile-aware global + project": we resolve the
 * active agent directory from the same environment variables omp uses (so
 * `--profile` / `PI_CODING_AGENT_DIR` are honored) and read the global
 * `config.yml` plus the project `<cwd>/.omp/config.yml`. See the limitations
 * below for what is intentionally out of scope.
 *
 * Limitations (documented, by design):
 *   - Exact tool names only. Any `tools.approval` key with a glob metacharacter
 *     (`* ? [ ] { }`) is skipped — no wildcard matching.
 *   - `bash.patterns` (all glob-based) are not read.
 *   - `--config` / `PI_CONFIG_FILES` overlays are not reflected; only the global
 *     and project `config.yml` files are read.
 *   - XDG data/state/cache path relocation is not handled.
 */
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { type ApprovalPolicy, normalizePolicy } from "./tier";

/** Glob metacharacters that mark an unsupported wildcard approval key. */
const WILDCARD = /[*?[\]{}]/;

type Logger = { debug?: (...a: unknown[]) => void } | undefined;

/** Expand a leading `~` / `~/` to the user's home directory. */
function expandTilde(p: string): string {
	if (p === "~") return os.homedir();
	if (p.startsWith("~/")) return path.join(os.homedir(), p.slice(2));
	return p;
}

/**
 * Resolve omp's active agent directory (e.g. `~/.omp/agent`) from the same
 * environment omp itself consults. A local replica of core's `getAgentDir()` +
 * profile relocation, kept dependency-free so the extension needs no runtime
 * `@oh-my-pi/*` import (mirrors `tier.ts`).
 *
 * Resolution order:
 *   - Config dir name: `PI_CONFIG_DIR` or `.omp`.
 *   - Profile: `OMP_PROFILE` if defined (an explicit empty value still selects
 *     the default profile), else `PI_PROFILE`. A non-empty, non-`default`,
 *     non-whitespace name relocates the base to `~/<cfgDir>/profiles/<name>/agent`.
 *   - Default profile: `PI_CODING_AGENT_DIR` (tilde-expanded) if set, else
 *     `~/<cfgDir>/agent`.
 */
export function resolveAgentDir(): string {
	const cfgDir = process.env.PI_CONFIG_DIR?.trim() || ".omp";

	const rawProfile = process.env.OMP_PROFILE !== undefined ? process.env.OMP_PROFILE : process.env.PI_PROFILE;
	const profile = rawProfile?.trim();
	if (profile && profile !== "default") {
		return path.join(os.homedir(), cfgDir, "profiles", profile, "agent");
	}

	const envDir = process.env.PI_CODING_AGENT_DIR?.trim();
	if (envDir) return expandTilde(envDir);

	return path.join(os.homedir(), cfgDir, "agent");
}

/** Minimal shape of Bun's global YAML parser (untyped in this dependency-free build). */
interface YamlParser {
	parse(input: string): unknown;
}
function getBunYaml(): YamlParser | undefined {
	const bun = (globalThis as { Bun?: { YAML?: unknown } }).Bun;
	const yaml = bun?.YAML;
	if (yaml && typeof (yaml as { parse?: unknown }).parse === "function") return yaml as YamlParser;
	return undefined;
}

/**
 * Read `key` off `value` when both `value` and `value[key]` are plain (non-array)
 * objects, narrowing an untyped parse result to a record. Returns undefined for
 * anything else (scalars, arrays, missing keys), so callers can chain safely.
 */
function readNestedObject(value: unknown, key: string): Record<string, unknown> | undefined {
	if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
	if (!(key in value)) return undefined;
	const nested = (value as Record<string, unknown>)[key];
	if (!nested || typeof nested !== "object" || Array.isArray(nested)) return undefined;
	return nested as Record<string, unknown>;
}

/** Parse a `config.{yml,yaml}` file and return its `tools.approval` map, or `{}`. */
function readApprovalMap(dir: string, logger: Logger): Record<string, unknown> {
	const yaml = getBunYaml();
	if (!yaml) {
		logger?.debug?.("permission-guard: Bun.YAML unavailable; skipping omp config");
		return {};
	}
	for (const name of ["config.yml", "config.yaml"]) {
		const file = path.join(dir, name);
		let raw: string;
		try {
			raw = fs.readFileSync(file, "utf8");
		} catch (err) {
			if ((err as NodeJS.ErrnoException).code !== "ENOENT") {
				logger?.debug?.("permission-guard: omp config read failed", { file, error: String(err) });
			}
			continue;
		}
		try {
			const parsed = yaml.parse(raw);
			const approval = readNestedObject(readNestedObject(parsed, "tools"), "approval");
			if (approval) return approval;
		} catch (err) {
			logger?.debug?.("permission-guard: omp config parse failed", { file, error: String(err) });
		}
		return {}; // first existing file wins, even if it had no usable approval map
	}
	return {};
}

/**
 * Load omp's `tools.approval` rules as a normalized, wildcard-free policy map.
 * Merges the global agent-dir config with the project `<cwd>/.omp/config.yml`,
 * with the project layer overriding the global (matching omp precedence). Never
 * throws: any missing/invalid file degrades to no rules.
 */
export function loadOmpApprovalRules(cwd: string, logger?: Logger): Record<string, ApprovalPolicy> {
	const global = readApprovalMap(resolveAgentDir(), logger);
	const project = readApprovalMap(path.join(cwd, ".omp"), logger);
	const merged = { ...global, ...project };

	const rules: Record<string, ApprovalPolicy> = {};
	let skipped = 0;
	for (const [key, value] of Object.entries(merged)) {
		if (WILDCARD.test(key)) {
			skipped++;
			continue;
		}
		const policy = normalizePolicy(value);
		if (policy) rules[key] = policy;
	}
	if (skipped > 0) {
		logger?.debug?.(`permission-guard: skipped ${skipped} wildcard approval key(s) from omp config`);
	}
	return rules;
}

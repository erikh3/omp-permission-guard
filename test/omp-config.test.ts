/**
 * Unit tests for the omp config reader: agent-dir resolution from env, reading
 * and normalizing `tools.approval` from global + project `config.yml`, wildcard
 * filtering, project-over-global precedence, and graceful degradation on
 * missing/invalid input. Runs under `bun test` (needs `Bun.YAML`, always present
 * in the Bun runtime) with no `@oh-my-pi/*` dependency.
 */
import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { loadOmpApprovalRules, resolveAgentDir } from "../src/omp-config";

const ENV_KEYS = ["PI_CODING_AGENT_DIR", "PI_CONFIG_DIR", "OMP_PROFILE", "PI_PROFILE"] as const;
const saved: Record<string, string | undefined> = {};

let tmp: string;
let agentDir: string;
let projectDir: string;

beforeEach(() => {
	for (const k of ENV_KEYS) {
		saved[k] = process.env[k];
		delete process.env[k];
	}
	tmp = fs.mkdtempSync(path.join(os.tmpdir(), "omp-guard-test-"));
	agentDir = path.join(tmp, "agent");
	projectDir = path.join(tmp, "project");
	fs.mkdirSync(agentDir, { recursive: true });
	fs.mkdirSync(path.join(projectDir, ".omp"), { recursive: true });
	process.env.PI_CODING_AGENT_DIR = agentDir;
});

afterEach(() => {
	for (const k of ENV_KEYS) {
		if (saved[k] === undefined) delete process.env[k];
		else process.env[k] = saved[k];
	}
	fs.rmSync(tmp, { recursive: true, force: true });
});

/** Write a `config.yml` with the given `tools.approval` block into `dir`. */
function writeGlobalApproval(dir: string, approval: Record<string, string>): void {
	const lines = ["tools:", "  approval:"];
	for (const [k, v] of Object.entries(approval)) lines.push(`    ${JSON.stringify(k)}: ${v}`);
	fs.writeFileSync(path.join(dir, "config.yml"), `${lines.join("\n")}\n`);
}

describe("resolveAgentDir", () => {
	test("honors PI_CODING_AGENT_DIR", () => {
		expect(resolveAgentDir()).toBe(agentDir);
	});

	test("a named profile relocates under profiles/<name>/agent", () => {
		delete process.env.PI_CODING_AGENT_DIR;
		process.env.OMP_PROFILE = "work";
		expect(resolveAgentDir()).toBe(path.join(os.homedir(), ".omp", "profiles", "work", "agent"));
	});

	test("an explicit empty OMP_PROFILE selects the default profile", () => {
		delete process.env.PI_CODING_AGENT_DIR;
		process.env.OMP_PROFILE = "";
		expect(resolveAgentDir()).toBe(path.join(os.homedir(), ".omp", "agent"));
	});

	test("PI_CONFIG_DIR overrides the config dir name", () => {
		delete process.env.PI_CODING_AGENT_DIR;
		process.env.PI_CONFIG_DIR = ".pi";
		expect(resolveAgentDir()).toBe(path.join(os.homedir(), ".pi", "agent"));
	});
});

describe("loadOmpApprovalRules", () => {
	test("honors allow / deny / prompt from the global config", () => {
		writeGlobalApproval(agentDir, {
			mcp__foo_read: "allow",
			mcp__foo_write: "deny",
			mcp__foo_ask: "prompt",
		});
		const rules = loadOmpApprovalRules(projectDir);
		expect(rules).toEqual({
			mcp__foo_read: "allow",
			mcp__foo_write: "deny",
			mcp__foo_ask: "prompt",
		});
	});

	test("skips wildcard keys", () => {
		writeGlobalApproval(agentDir, { "mcp__foo_*": "allow", mcp__foo_exact: "allow" });
		const rules = loadOmpApprovalRules(projectDir);
		expect(rules["mcp__foo_*"]).toBeUndefined();
		expect(rules.mcp__foo_exact).toBe("allow");
	});

	test("drops non-policy values", () => {
		writeGlobalApproval(agentDir, { mcp__foo: "banana", mcp__bar: "allow" });
		const rules = loadOmpApprovalRules(projectDir);
		expect(rules.mcp__foo).toBeUndefined();
		expect(rules.mcp__bar).toBe("allow");
	});

	test("project config overrides global for the same key", () => {
		writeGlobalApproval(agentDir, { shared: "allow", onlyGlobal: "allow" });
		writeGlobalApproval(path.join(projectDir, ".omp"), { shared: "deny", onlyProject: "prompt" });
		const rules = loadOmpApprovalRules(projectDir);
		expect(rules.shared).toBe("deny");
		expect(rules.onlyGlobal).toBe("allow");
		expect(rules.onlyProject).toBe("prompt");
	});

	test("missing config yields no rules", () => {
		expect(loadOmpApprovalRules(projectDir)).toEqual({});
	});

	test("malformed YAML does not throw and yields no rules", () => {
		fs.writeFileSync(path.join(agentDir, "config.yml"), "tools:\n  approval:\n    key: : : bad\n  - broken");
		expect(loadOmpApprovalRules(projectDir)).toEqual({});
	});

	test("config without a tools.approval map yields no rules", () => {
		fs.writeFileSync(path.join(agentDir, "config.yml"), "theme:\n  dark: x\ntools:\n  approvalMode: yolo\n");
		expect(loadOmpApprovalRules(projectDir)).toEqual({});
	});
});

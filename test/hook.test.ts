/**
 * End-to-end wiring test for the extension entrypoint: builds the real factory
 * with a fake `pi`/`ctx`, captures the registered `tool_call` handler, and
 * asserts the hook's block/allow contract, read-tier skip, and mode gating —
 * without a live model (guardian modes are covered by the manual in-session
 * test). Mode is forced via `OMP_GUARD_MODE`, which takes precedence over the
 * config file.
 */
import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import permissionGuard from "../src/index";
import { resolvePathPolicy } from "../src/path-utils";

type ToolCallResult = { block?: boolean; reason?: string } | undefined;
type Handler = (event: { toolName: string; input: unknown }, ctx: unknown) => Promise<ToolCallResult>;

function harness() {
	let handler: Handler | undefined;
	const busEmits: { channel: string; data: unknown }[] = [];
	const commands: Record<
		string,
		{
			handler: (a: unknown, c: unknown) => Promise<void>;
			getArgumentCompletions?: (prefix: string) => { value: string; label: string; description?: string }[] | null;
		}
	> = {};
	const pi = {
		logger: { debug: (msg: string, data?: unknown) => logs.push({ msg, data }) },
		setLabel: () => {},
		registerCommand: (name: string, def: { handler: (a: unknown, c: unknown) => Promise<void> }) => {
			commands[name] = def;
		},
		on: (evt: string, h: Handler) => {
			if (evt === "tool_call") handler = h;
		},
		// The live registry (`getAllToolInfos`) returns approval-less ToolInfo — no
		// `approval` field — so the guard must lean on its static tier map. Mirror
		// that here so the test exercises the real classification path.
		getAllTools: () => [
			{ name: "bash", description: "", parameters: {} },
			{ name: "read", description: "", parameters: {} },
			{ name: "grep", description: "", parameters: {} },
		],
		// Shared extension bus; the guard emits `herdr:blocked` here while a dialog is open.
		events: { emit: (channel: string, data: unknown) => busEmits.push({ channel, data }) },
	};
	permissionGuard(pi as unknown as Parameters<typeof permissionGuard>[0]);
	return { handler: handler!, commands, busEmits };
}

const notes: string[] = [];
const logs: { msg: string; data?: unknown }[] = [];
const ctx = {
	cwd: process.cwd(),
	hasUI: true,
	ui: { select: async () => undefined, input: async () => undefined, notify: (m: string) => notes.push(m) },
	models: { resolve: () => undefined, current: () => undefined, list: () => [] },
	modelRegistry: { getApiKey: async () => undefined },
	sessionManager: {
		getEntries: () => [
			{ type: "message", message: { role: "user", content: "delete the temp files" } },
			{ type: "message", message: { role: "assistant", content: [{ type: "text", text: "ok" }] } },
		],
	},
};

/** A UI whose `select` picks the first option that includes `target`; `input` returns `inputText`. */
function selectUi(
	target: string,
	opts: { inputText?: string; capture?: (options: string[], dialogOptions: Record<string, unknown> | undefined) => void } = {},
) {
	return {
		notify: (m: string) => notes.push(m),
		input: async () => opts.inputText,
		select: async (_title: string, options: string[], dialogOptions?: Record<string, unknown>) => {
			opts.capture?.(options, dialogOptions);
			return options.find(o => o.includes(target));
		},
	};
}

const ENV_KEYS = ["PI_CODING_AGENT_DIR", "OMP_PROFILE", "PI_PROFILE", "PI_CONFIG_DIR"] as const;
const savedEnv: Record<string, string | undefined> = {};

beforeEach(() => {
	for (const k of ENV_KEYS) {
		savedEnv[k] = process.env[k];
		delete process.env[k];
	}
});

afterEach(() => {
	delete process.env.OMP_GUARD_MODE;
	notes.length = 0;
	logs.length = 0;
	for (const k of ENV_KEYS) {
		if (savedEnv[k] === undefined) delete process.env[k];
		else process.env[k] = savedEnv[k];
	}
});

describe("tool_call hook wiring", () => {
	test("mode off -> pass-through (undefined)", async () => {
		process.env.OMP_GUARD_MODE = "off";
		const { handler } = harness();
		expect(await handler({ toolName: "bash", input: { command: "rm -rf /" } }, ctx)).toBeUndefined();
	});

	test("heuristic: rm -rf / -> blocked", async () => {
		process.env.OMP_GUARD_MODE = "heuristic";
		const { handler } = harness();
		const res = await handler({ toolName: "bash", input: { command: "rm -rf /" } }, ctx);
		expect(res?.block).toBe(true);
		expect(res?.reason).toContain("permission-guard");
	});

	test("heuristic: ls -> allowed (undefined)", async () => {
		process.env.OMP_GUARD_MODE = "heuristic";
		const { handler } = harness();
		expect(await handler({ toolName: "bash", input: { command: "ls -la" } }, ctx)).toBeUndefined();
	});

	test("read of an ordinary in-workspace file is allowed (undefined)", async () => {
		process.env.OMP_GUARD_MODE = "heuristic";
		const { handler } = harness();
		expect(await handler({ toolName: "read", input: { path: "src/index.ts" } }, ctx)).toBeUndefined();
	});

	test("read of a secret file (.env) is gated, not skipped as read-tier", async () => {
		process.env.OMP_GUARD_MODE = "heuristic";
		const { handler } = harness();
		const res = await handler({ toolName: "read", input: { path: ".env" } }, ctx);
		expect(res?.block).toBe(true);
		expect(res?.reason).toContain("permission-guard");
	});

	test("read escaping the workspace (/etc/passwd) is gated, not skipped", async () => {
		process.env.OMP_GUARD_MODE = "heuristic";
		const { handler } = harness();
		expect((await handler({ toolName: "read", input: { path: "/etc/passwd" } }, ctx))?.block).toBe(true);
	});

	test("grep inside the workspace -> allowed (undefined), not skipped as read-tier", async () => {
		process.env.OMP_GUARD_MODE = "heuristic";
		const { handler } = harness();
		// ctx.cwd is this repo; a relative in-workspace search proves safe.
		expect(await handler({ toolName: "grep", input: { pattern: "foo", path: "src" } }, ctx)).toBeUndefined();
	});

	test("grep with no path defaults to the workspace -> allowed", async () => {
		process.env.OMP_GUARD_MODE = "heuristic";
		const { handler } = harness();
		expect(await handler({ toolName: "grep", input: { pattern: "foo" } }, ctx)).toBeUndefined();
	});

	test("grep outside the workspace -> blocked (heuristic denies the escape)", async () => {
		process.env.OMP_GUARD_MODE = "heuristic";
		const { handler } = harness();
		const res = await handler({ toolName: "grep", input: { pattern: "x", path: "/etc" } }, ctx);
		expect(res?.block).toBe(true);
		expect(res?.reason).toContain("permission-guard");
	});

	test("grep of a secret/env file inside the workspace -> blocked", async () => {
		process.env.OMP_GUARD_MODE = "heuristic";
		const { handler } = harness();
		const res = await handler({ toolName: "grep", input: { pattern: "KEY", path: ".env" } }, ctx);
		expect(res?.block).toBe(true);
	});

	test("grep escape prompt title carries the pattern and path", async () => {
		process.env.OMP_GUARD_MODE = "heuristic";
		let title = "";
		const capCtx = {
			...ctx,
			ui: { notify: (m: string) => notes.push(m), input: async () => undefined, select: async (t: string) => { title = t; return "Deny"; } },
		};
		const { handler } = harness();
		await handler({ toolName: "grep", input: { pattern: "SECRET|token", path: "/var/log" } }, capCtx);
		expect(title).toContain('pattern "SECRET|token"');
		expect(title).toContain("/var/log");
	});

	test("prompt with no selection (cancel) -> blocked", async () => {
		process.env.OMP_GUARD_MODE = "guardian"; // exec bash, no model -> failSafe -> prompt; base ctx select -> undefined -> deny
		const { handler } = harness();
		const res = await handler({ toolName: "bash", input: { command: "echo $(date)" } }, ctx);
		expect(res?.block).toBe(true);
	});

	test("a prompt emits balanced herdr:blocked toggles around the dialog", async () => {
		process.env.OMP_GUARD_MODE = "heuristic";
		const { handler, busEmits } = harness();
		// A proven-deny bash call prompts; base ctx.select returns undefined -> deny.
		const res = await handler({ toolName: "bash", input: { command: "rm -rf /" } }, ctx);
		expect(res?.block).toBe(true);
		const blocked = busEmits.filter(e => e.channel === "herdr:blocked");
		expect(blocked.map(e => e.data)).toEqual([{ active: true, label: expect.any(String) }, { active: false }]);
	});

	test("an allowed call never prompts, so no herdr:blocked is emitted", async () => {
		process.env.OMP_GUARD_MODE = "heuristic";
		const { handler, busEmits } = harness();
		expect(await handler({ toolName: "bash", input: { command: "ls -la" } }, ctx)).toBeUndefined();
		expect(busEmits.filter(e => e.channel === "herdr:blocked")).toHaveLength(0);
	});

	test("/guard status shows the mode", async () => {
		const { commands } = harness();
		expect(typeof commands.guard?.handler).toBe("function");
		notes.length = 0;
		await commands.guard!.handler("status", ctx);
		const status = notes.find(n => n.includes("mode"));
		expect(status).toBeDefined();
		expect(status).toContain("Permission guard mode");
	});

	test("reads recent user intent from the session transcript", async () => {
		process.env.OMP_GUARD_MODE = "heuristic";
		let called = false;
		const spyCtx = { ...ctx, sessionManager: { getEntries: () => { called = true; return []; } } };
		const { handler } = harness();
		await handler({ toolName: "bash", input: { command: "ls" } }, spyCtx);
		expect(called).toBe(true);
	});

	test("proven deny + user picks Allow once -> allowed (human override)", async () => {
		process.env.OMP_GUARD_MODE = "heuristic";
		const okCtx = { ...ctx, ui: selectUi("Allow once") };
		const { handler } = harness();
		expect(await handler({ toolName: "bash", input: { command: "rm -rf /" } }, okCtx)).toBeUndefined();
	});

	test("proven deny + headless (no UI) -> hard block despite promptOnBlock default", async () => {
		process.env.OMP_GUARD_MODE = "heuristic";
		const headless = { ...ctx, hasUI: false };
		const { handler } = harness();
		const res = await handler({ toolName: "bash", input: { command: "rm -rf /" } }, headless);
		expect(res?.block).toBe(true);
	});

	test("prompt passes no timeout to select (waits indefinitely)", async () => {
		process.env.OMP_GUARD_MODE = "guardian";
		let seen: Record<string, unknown> | undefined;
		const spyCtx = { ...ctx, ui: selectUi("Allow once", { capture: (_o, d) => { seen = d; } }) };
		const { handler } = harness();
		const res = await handler({ toolName: "bash", input: { command: "echo $(date)" } }, spyCtx);
		expect(seen?.timeout).toBeUndefined(); // no timeout => the dialog blocks until the user answers
		expect(res).toBeUndefined(); // Allow once -> tool runs
	});

	test("guardian unavailable -> dialog footer shows the guardian-error status", async () => {
		process.env.OMP_GUARD_MODE = "guardian"; // exec bash, no model -> failSafe -> guardianError prompt
		let seen: Record<string, unknown> | undefined;
		const spyCtx = { ...ctx, ui: selectUi("Allow once", { capture: (_o, d) => { seen = d; } }) };
		const { handler } = harness();
		await handler({ toolName: "bash", input: { command: "echo $(date)" } }, spyCtx);
		expect(String(seen?.helpText)).toContain("guardian unavailable");
	});

	test("'allow this exact call this session' short-circuits identical later calls", async () => {
		process.env.OMP_GUARD_MODE = "heuristic";
		let dialogCalls = 0;
		const sessionCtx = {
			...ctx,
			ui: {
				notify: (m: string) => notes.push(m),
				input: async () => undefined,
				select: async (_t: string, options: string[]) => {
					dialogCalls++;
					return options.find(o => o.includes("Allow this exact call"));
				},
			},
		};
		const { handler } = harness();
		const call = { toolName: "bash", input: { command: "rm -rf /" } };
		expect(await handler(call, sessionCtx)).toBeUndefined(); // user allows for the session
		expect(await handler(call, sessionCtx)).toBeUndefined(); // identical call auto-allowed
		expect(dialogCalls).toBe(1); // prompted only once
	});

	test("session allow ignores volatile fields: same command, different timeout -> still cached", async () => {
		process.env.OMP_GUARD_MODE = "heuristic";
		let dialogCalls = 0;
		const sessionCtx = {
			...ctx,
			ui: {
				notify: (m: string) => notes.push(m),
				input: async () => undefined,
				select: async (_t: string, options: string[]) => {
					dialogCalls++;
					return options.find(o => o.includes("Allow this exact call"));
				},
			},
		};
		const { handler } = harness();
		// The agent re-issues the SAME command (command-substitution -> uncertain -> prompts) with a
		// different, then absent, `timeout`. Volatile `timeout` must not change the session-allow key.
		expect(await handler({ toolName: "bash", input: { command: "echo $(date)", timeout: 60 } }, sessionCtx)).toBeUndefined();
		expect(await handler({ toolName: "bash", input: { command: "echo $(date)", timeout: 120 } }, sessionCtx)).toBeUndefined();
		expect(await handler({ toolName: "bash", input: { command: "echo $(date)" } }, sessionCtx)).toBeUndefined();
		expect(dialogCalls).toBe(1); // prompted only once despite the timeout variance
	});

	test("'Deny (type your own)' forwards the user's typed message to the agent", async () => {
		process.env.OMP_GUARD_MODE = "heuristic";
		const denyCtx = { ...ctx, ui: selectUi("Deny (type your own)", { inputText: "use the sandbox path instead" }) };
		const { handler } = harness();
		const res = await handler({ toolName: "bash", input: { command: "rm -rf /" } }, denyCtx);
		expect(res?.block).toBe(true);
		expect(res?.reason).toContain("use the sandbox path instead");
	});

	test("a guard-initiated prompt recommends Deny (pre-selected)", async () => {
		process.env.OMP_GUARD_MODE = "heuristic";
		let options: string[] = [];
		let dialogOptions: Record<string, unknown> | undefined;
		const capCtx = { ...ctx, ui: selectUi("Deny", { capture: (o, d) => { options = o; dialogOptions = d; } }) };
		const { handler } = harness();
		await handler({ toolName: "bash", input: { command: "rm -rf /" } }, capCtx);
		const denyIndex = options.findIndex(o => o.startsWith("Deny") && !o.includes("type your own"));
		expect(options[denyIndex]).toContain("(recommended)");
		expect(dialogOptions?.initialIndex).toBe(denyIndex);
	});

	test("workspace escape offers to allow the directory for the session", async () => {
		process.env.OMP_GUARD_MODE = "heuristic";
		let sawDirOption = false;
		let dialogCalls = 0;
		const dirCtx = {
			...ctx,
			ui: {
				notify: (m: string) => notes.push(m),
				input: async () => undefined,
				select: async (_t: string, options: string[]) => {
					dialogCalls++;
					const dir = options.find(o => o.startsWith("Allow the directory"));
					if (dir) sawDirOption = true;
					return dir;
				},
			},
		};
		const { handler } = harness();
		const escape = { toolName: "bash", input: { command: "cd /private/tmp && whoami" } };
		expect(await handler(escape, dirCtx)).toBeUndefined(); // user allows the directory
		expect(sawDirOption).toBe(true);
		// a later call in that now-allowed directory is not prompted again
		expect(await handler({ toolName: "bash", input: { command: "cd /private/tmp && ls" } }, dirCtx)).toBeUndefined();
		expect(dialogCalls).toBe(1);
	});

	test("logs an auto-deny with tool name and arguments", async () => {
		process.env.OMP_GUARD_MODE = "heuristic";
		const headless = { ...ctx, hasUI: false };
		const { handler } = harness();
		logs.length = 0;
		await handler({ toolName: "bash", input: { command: "rm -rf /" } }, headless);
		const entry = logs.find(l => l.msg.includes("deny"));
		expect(entry).toBeDefined();
		expect(entry!.msg).toContain("bash");
		expect(entry!.msg).toContain("rm -rf /");
		expect(entry!.data).toMatchObject({ tool: "bash", tier: "exec", mode: "heuristic", via: "classifier" });
	});

	test("in-workspace grep logs via:classifier on allow", async () => {
		process.env.OMP_GUARD_MODE = "heuristic";
		const { handler } = harness();
		logs.length = 0;
		await handler({ toolName: "grep", input: { pattern: "x", path: "src" } }, ctx);
		const entry = logs.find(l => l.msg.toLowerCase().includes("allow"));
		expect(entry).toBeDefined();
		expect(entry!.data).toMatchObject({ tool: "grep", via: "classifier" });
	});

	test("logs the user's choice on an interactive prompt", async () => {
		process.env.OMP_GUARD_MODE = "heuristic";
		const okCtx = { ...ctx, ui: selectUi("Allow once") };
		const { handler } = harness();
		logs.length = 0;
		await handler({ toolName: "bash", input: { command: "rm -rf /" } }, okCtx);
		const entry = logs.find(l => l.msg.includes("allow"));
		expect(entry?.data).toMatchObject({ via: "prompt", choice: "allow-once" });
	});

	test("logs a custom denial with the user's message", async () => {
		process.env.OMP_GUARD_MODE = "heuristic";
		const denyCtx = { ...ctx, ui: selectUi("Deny (type your own)", { inputText: "nope, use /sandbox" }) };
		const { handler } = harness();
		logs.length = 0;
		await handler({ toolName: "bash", input: { command: "rm -rf /" } }, denyCtx);
		const entry = logs.find(l => l.msg.includes("deny"));
		expect(entry?.data).toMatchObject({ via: "prompt", choice: "deny-custom", reason: "nope, use /sandbox" });
	});

	test("truncated command title has a blank line and a (truncated) marker", async () => {
		process.env.OMP_GUARD_MODE = "heuristic";
		let title = "";
		const capCtx = {
			...ctx,
			ui: {
				notify: (m: string) => notes.push(m),
				input: async () => undefined,
				select: async (t: string) => {
					title = t;
					return "Deny";
				},
			},
		};
		const { handler } = harness();
		const longCmd = `echo $(${"x".repeat(400)})`; // command substitution -> prompt; >300 chars -> truncated
		await handler({ toolName: "bash", input: { command: longCmd } }, capCtx);
		expect(title).toContain("\n\n"); // blank line between reason and command
		expect(title).toContain("...(truncated)");
	});

	test("eval py prompt omits the redundant command line (host renders it)", async () => {
		process.env.OMP_GUARD_MODE = "heuristic";
		let title = "";
		const capCtx = {
			...ctx,
			ui: { notify: (m: string) => notes.push(m), input: async () => undefined, select: async (t: string) => { title = t; return "Deny"; } },
		};
		const { handler } = harness();
		await handler({ toolName: "eval", input: { language: "py", code: "print(open('/etc/passwd').read())" } }, capCtx);
		expect(title).not.toContain("eval:"); // no duplicate command line
		expect(title).not.toContain('"language"');
	});

	test("eval js prompt omits the redundant command line (host renders it)", async () => {
		process.env.OMP_GUARD_MODE = "heuristic";
		let title = "";
		const capCtx = {
			...ctx,
			ui: { notify: (m: string) => notes.push(m), input: async () => undefined, select: async (t: string) => { title = t; return "Deny"; } },
		};
		const { handler } = harness();
		await handler({ toolName: "eval", input: { language: "js", code: "fetch('x')" } }, capCtx);
		expect(title).not.toContain("eval:"); // no duplicate command line
		expect(title).not.toContain('"language"');
	});

	test("edit prompt shows tool name + target file only, not the patch body", async () => {
		process.env.OMP_GUARD_MODE = "heuristic";
		let title = "";
		const capCtx = {
			...ctx,
			ui: { notify: (m: string) => notes.push(m), input: async () => undefined, select: async (t: string) => { title = t; return "Deny"; } },
		};
		const { handler } = harness();
		// An out-of-workspace edit escapes -> prompts. The patch body must NOT appear; only the file path.
		const input = "[/etc/hosts#A1B2]\nPUT 1.=1:\n+127.0.0.1 evil.example.com secret-token-abc123";
		await handler({ toolName: "edit", input: { input } }, capCtx);
		expect(title).toContain("edit: /etc/hosts"); // tool name + target file
		expect(title).not.toContain("PUT 1"); // no patch ops
		expect(title).not.toContain("secret-token-abc123"); // no patch body / content
		expect(title).not.toContain('"input"'); // not the raw JSON args
	});

	test("ask tool is allowed end-to-end (read-tier, never gated)", async () => {
		process.env.OMP_GUARD_MODE = "guardian"; // even in guardian mode
		const { handler } = harness();
		expect(await handler({ toolName: "ask", input: { questions: [] } }, ctx)).toBeUndefined();
	});

	test("multi-root /add-dir directories are treated as in-workspace", async () => {
		process.env.OMP_GUARD_MODE = "heuristic";
		const mrCtx = {
			...ctx,
			sessionManager: { getEntries: () => [], getAdditionalDirectories: () => ["/private/tmp"] },
			ui: { notify: (m: string) => notes.push(m), input: async () => undefined, select: async () => "Deny" },
		};
		const { handler } = harness();
		// A call inside an /add-dir root resolves in-workspace -> allowed without prompting.
		expect(await handler({ toolName: "bash", input: { command: "cd /private/tmp && ls" } }, mrCtx)).toBeUndefined();
	});

	test("omp config tools.approval flows through: an omp-allowed MCP tool is not gated", async () => {
		process.env.OMP_GUARD_MODE = "heuristic";
		const agentDir = fs.mkdtempSync(path.join(os.tmpdir(), "omp-guard-hook-"));
		const prev = process.env.PI_CODING_AGENT_DIR;
		process.env.PI_CODING_AGENT_DIR = agentDir;
		try {
			fs.writeFileSync(
				path.join(agentDir, "config.yml"),
				'tools:\n  approval:\n    mcp__demo_lookup: allow\n    mcp__demo_mutate: deny\n',
			);
			const { handler } = harness();
			// Un-vetted write-tier MCP tool would prompt/deny under heuristic; the omp `allow` clears it.
			expect(await handler({ toolName: "mcp__demo_lookup", input: { q: "x" } }, ctx)).toBeUndefined();
			// And an omp `deny` hard-blocks without any prompt.
			const denied = await handler({ toolName: "mcp__demo_mutate", input: { q: "x" } }, ctx);
			expect(denied?.block).toBe(true);
		} finally {
			if (prev === undefined) delete process.env.PI_CODING_AGENT_DIR;
			else process.env.PI_CODING_AGENT_DIR = prev;
			fs.rmSync(agentDir, { recursive: true, force: true });
		}
	});

	test("skill:// load prompts with a name-forward, allow-first dialog; Allow -> allowed", async () => {
		process.env.OMP_GUARD_MODE = "heuristic";
		let title = "";
		let options: string[] = [];
		const capCtx = {
			...ctx,
			ui: {
				notify: (m: string) => notes.push(m),
				input: async () => undefined,
				select: async (t: string, o: string[]) => {
					title = t;
					options = o;
					return o.find(x => x === "Allow");
				},
			},
		};
		const { handler } = harness();
		const res = await handler({ toolName: "read", input: { path: "skill://obsidian-markdown" } }, capCtx);
		expect(res).toBeUndefined();
		expect(title).toContain("obsidian-markdown");
		expect(title).toContain("skill");
		// Allow leads; no scary "outside the workspace" escape framing, no dir-allow option, and no
		// session-wide "always load" toggle (auto-load is configured via the skillLoad policy map).
		expect(options[0]).toBe("Allow");
		expect(options.some(o => o.startsWith("Allow the directory"))).toBe(false);
		expect(options.some(o => o.startsWith("Always load"))).toBe(false);
	});

	test("skill:// load headless (no UI) + not allow-listed -> fail-safe block (no one to ask)", async () => {
		process.env.OMP_GUARD_MODE = "heuristic";
		const headless = { ...ctx, hasUI: false };
		const { handler } = harness();
		const res = await handler({ toolName: "read", input: { path: "skill://graphify" } }, headless);
		expect(res?.block).toBe(true);
	});

	test("skill:// load: Deny blocks and tells the agent", async () => {
		process.env.OMP_GUARD_MODE = "heuristic";
		const denyCtx = { ...ctx, ui: selectUi("Deny") };
		const { handler } = harness();
		const res = await handler({ toolName: "read", input: { path: "skill://obsidian-markdown" } }, denyCtx);
		expect(res?.block).toBe(true);
		expect(res?.reason).toContain("obsidian-markdown");
	});

	test("filesystem skill-resource read: prompts allow-first, then remembers the skill so later resources auto-allow", async () => {
		process.env.OMP_GUARD_MODE = "heuristic";
		// A real installed-skill layout OUTSIDE the workspace, with a name no user config rule matches.
		const skillRoot = fs.mkdtempSync(path.join(os.tmpdir(), "omp-guard-skillfs-"));
		const skillDir = path.join(skillRoot, "skills", "zz-e2e-fixture-skill");
		fs.mkdirSync(path.join(skillDir, "references"), { recursive: true });
		fs.writeFileSync(path.join(skillDir, "SKILL.md"), "# skill");
		fs.writeFileSync(path.join(skillDir, "references", "a.md"), "# a");
		fs.writeFileSync(path.join(skillDir, "references", "b.md"), "# b");
		try {
			let title = "";
			let options: string[] = [];
			const capCtx = {
				...ctx,
				ui: {
					notify: (m: string) => notes.push(m),
					input: async () => undefined,
					select: async (t: string, o: string[]) => {
						title = t;
						options = o;
						return o.find(x => x === "Allow");
					},
				},
			};
			const { handler } = harness();
			// First resource read: no config rule -> name-forward, allow-first prompt.
			const first = await handler({ toolName: "read", input: { path: path.join(skillDir, "references", "a.md") } }, capCtx);
			expect(first).toBeUndefined();
			expect(title).toContain("zz-e2e-fixture-skill");
			expect(options[0]).toBe("Allow");
			// Second resource read of the SAME skill: auto-allowed, no prompt (loadedSkills).
			title = "";
			const second = await handler({ toolName: "read", input: { path: path.join(skillDir, "references", "b.md") } }, capCtx);
			expect(second).toBeUndefined();
			expect(title).toBe("");
		} finally {
			fs.rmSync(skillRoot, { recursive: true, force: true });
		}
	});

	test("a read of an out-of-workspace dir allowed via omp /add-dir is not gated", async () => {
		process.env.OMP_GUARD_MODE = "heuristic";
		const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "omp-guard-roots-"));
		try {
			fs.writeFileSync(path.join(tmp, "notes.txt"), "hi");
			const rootCtx = {
				...ctx,
				sessionManager: { getEntries: () => [], getAdditionalDirectories: () => [tmp] },
				ui: { notify: (m: string) => notes.push(m), input: async () => undefined, select: async () => "Deny" },
			};
			const { handler } = harness();
			expect(await handler({ toolName: "read", input: { path: path.join(tmp, "notes.txt") } }, rootCtx)).toBeUndefined();
		} finally {
			fs.rmSync(tmp, { recursive: true, force: true });
		}
	});
});

describe("/guard allowed + revoke commands", () => {
	/** A ctx.ui whose select returns whatever `pick` yields; records notifications. */
	function cmdCtx(pick?: (title: string, options: string[]) => string | undefined) {
		const seen: string[] = [];
		return {
			ctx: {
				...ctx,
				ui: {
					notify: (m: string) => seen.push(m),
					input: async () => undefined,
					select: async (title: string, options: string[]) => pick?.(title, options),
				},
			},
			seen,
		};
	}

	/** Approve "allow this exact call" for a bash command, populating the session allow-list. */
	async function allow(handler: Handler, command: string) {
		const sessionCtx = {
			...ctx,
			ui: {
				notify: (m: string) => notes.push(m),
				input: async () => undefined,
				select: async (_t: string, options: string[]) => options.find(o => o.includes("Allow this exact call")),
			},
		};
		await handler({ toolName: "bash", input: { command } }, sessionCtx);
	}

	test("/guard allowed lists entries sorted by insertion (last added at the bottom)", async () => {
		process.env.OMP_GUARD_MODE = "heuristic";
		const { handler, commands } = harness();
		await allow(handler, "cat $(first)");
		await allow(handler, "cat $(second)");
		let shown: string[] = [];
		const { ctx: c } = cmdCtx((_t, options) => {
			shown = options;
			return undefined; // cancel: just capture the list
		});
		await commands.guard!.handler("allowed", c);
		expect(shown).toEqual(["1. bash: cat $(first)", "2. bash: cat $(second)"]);
	});

	test("/guard allowed -> selecting an entry revokes it (re-prompts next time)", async () => {
		process.env.OMP_GUARD_MODE = "heuristic";
		const { handler, commands } = harness();
		await allow(handler, "cat $(keep)");
		// Must return the index-prefixed option string; the handler parses the leading "1." to get the key.
		const { ctx: c } = cmdCtx((_t, _o) => "1. bash: cat $(keep)");
		await commands.guard!.handler("allowed", c);
		// After revoke, the same call is no longer cached -> the guard evaluates it again (deny via no-op UI).
		const res = await handler({ toolName: "bash", input: { command: "cat $(keep)" } }, { ...ctx, ui: { ...ctx.ui, select: async () => "Deny" } });
		expect(res?.block).toBe(true);
	});

	test("/guard revoke <call> removes the exact entry", async () => {
		process.env.OMP_GUARD_MODE = "heuristic";
		const { handler, commands } = harness();
		await allow(handler, "cat $(target)");
		const { ctx: c, seen } = cmdCtx();
		await commands.guard!.handler("revoke bash: cat $(target)", c);
		expect(seen.some(m => m.includes("revoked session allow"))).toBe(true);
		const res = await handler({ toolName: "bash", input: { command: "cat $(target)" } }, { ...ctx, ui: { ...ctx.ui, select: async () => "Deny" } });
		expect(res?.block).toBe(true); // no longer cached
	});

	test("/guard revoke autocomplete offers the current allow-list", async () => {
		process.env.OMP_GUARD_MODE = "heuristic";
		const { handler, commands } = harness();
		await allow(handler, "cat $(alpha)");
		await allow(handler, "cat $(beta)");
		const items = await commands.guard!.getArgumentCompletions!("revoke ");
		expect(items?.map((i: { value: string }) => i.value)).toEqual([
			"revoke bash: cat $(alpha)",
			"revoke bash: cat $(beta)",
		]);
	});
	test("/guard completes subcommand words", async () => {
		const { commands } = harness();
		const items = await commands.guard!.getArgumentCompletions!("all");
		expect(items?.map((i: { value: string }) => i.value)).toContain("allowed");
	});

	test("colliding labels: /guard allowed shows two rows; picking row 2 removes only that entry; /guard revoke removes all matching", async () => {
		process.env.OMP_GUARD_MODE = "heuristic";
		const { handler, commands } = harness();

		// Two bash calls with the same command (same label) but a differing non-preview field
		// so stableStringify produces distinct keys. Both hit the prompt (command substitution
		// makes heuristic uncertain).
		const makeSessionCtx = () => ({
			...ctx,
			ui: {
				notify: (m: string) => notes.push(m),
				input: async () => undefined,
				select: async (_t: string, options: string[]) =>
					options.find(o => o.includes("Allow this exact call")),
			},
		});
		await handler({ toolName: "bash", input: { command: "cat $(collision)" } }, makeSessionCtx());
		await handler({ toolName: "bash", input: { command: "cat $(collision)", extraField: 1 } }, makeSessionCtx());

		// Both should appear as separate entries in /guard allowed.
		let captured: string[] = [];
		const { ctx: c1 } = cmdCtx((_t, options) => { captured = options; return undefined; });
		await commands.guard!.handler("allowed", c1);
		expect(captured).toHaveLength(2);
		expect(captured[0]).toBe("1. bash: cat $(collision)");
		expect(captured[1]).toBe("2. bash: cat $(collision)");

		// Picking row 2 removes only that entry; row 1 (different key) stays cached.
		const { ctx: c2, seen: seen2 } = cmdCtx((_t, options) => options[1]); // pick "2. bash: ..."
		await commands.guard!.handler("allowed", c2);
		expect(seen2.some(m => m.includes("revoked session allow"))).toBe(true);

		// Row 1's call is still cached (auto-allows without prompting).
		let dialogsAfterRevoke = 0;
		const watchCtx = {
			...ctx,
			ui: {
				notify: (m: string) => notes.push(m),
				input: async () => undefined,
				select: async (_t: string, options: string[]) => {
					dialogsAfterRevoke++;
					return options.find(o => o.includes("Allow this exact call"));
				},
			},
		};
		await handler({ toolName: "bash", input: { command: "cat $(collision)" } }, watchCtx);
		expect(dialogsAfterRevoke).toBe(0); // row 1 key still cached

		// Row 2's key is gone: the call re-prompts.
		await handler({ toolName: "bash", input: { command: "cat $(collision)", extraField: 1 } }, watchCtx);
		expect(dialogsAfterRevoke).toBe(1); // row 2 was revoked, re-prompts now

		// /guard revoke <label> removes ALL entries matching that label (here only the 1 remaining).
		const { ctx: c3, seen: seen3 } = cmdCtx();
		await commands.guard!.handler("revoke bash: cat $(collision)", c3);
		expect(seen3.some(m => m.includes("revoked"))).toBe(true);

		// Now both are gone: next call re-prompts.
		let dialogsFinal = 0;
		const finalCtx = {
			...ctx,
			ui: {
				notify: (m: string) => notes.push(m),
				input: async () => undefined,
				select: async () => { dialogsFinal++; return "Deny"; },
			},
		};
		await handler({ toolName: "bash", input: { command: "cat $(collision)" } }, finalCtx);
		expect(dialogsFinal).toBe(1); // last entry was revoked
	});
});

describe("resolvePathPolicy (config paths glob matching)", () => {
	const home = os.homedir();
	const allow = (pat: string) => ({ [pat]: "allow" });
	const deny = (pat: string) => ({ [pat]: "deny" });
	test("exact single-file allow matches only that file", () => {
		expect(resolvePathPolicy(path.join(home, ".omp/agent/git.md"), allow("~/.omp/agent/git.md"))).toBe("allow");
		expect(resolvePathPolicy(path.join(home, ".omp/agent/other.md"), allow("~/.omp/agent/git.md"))).toBeUndefined();
	});
	test("bare directory is NON-recursive: matches the dir itself, not its contents", () => {
		expect(resolvePathPolicy(path.join(home, ".omp/agent"), allow("~/.omp/agent"))).toBe("allow");
		expect(resolvePathPolicy(path.join(home, ".omp/agent/git.md"), allow("~/.omp/agent"))).toBeUndefined();
	});
	test("trailing /* matches contents (including nested, since * spans /)", () => {
		expect(resolvePathPolicy(path.join(home, ".omp/agent/git.md"), allow("~/.omp/agent/*"))).toBe("allow");
		expect(resolvePathPolicy(path.join(home, ".omp/agent/sub/deep.md"), allow("~/.omp/agent/*"))).toBe("allow");
	});
	test("? matches a single character", () => {
		expect(resolvePathPolicy("/var/log/a.txt", allow("/var/log/?.txt"))).toBe("allow");
		expect(resolvePathPolicy("/var/log/ab.txt", allow("/var/log/?.txt"))).toBeUndefined();
	});
	test("deny entry returns deny", () => {
		expect(resolvePathPolicy("/etc/hosts", deny("/etc/hosts"))).toBe("deny");
	});
	test("deny short-circuits a broader allow glob", () => {
		expect(resolvePathPolicy("/etc/hosts", { "/etc/*": "allow", "/etc/hosts": "deny" })).toBe("deny");
	});
	test("no match -> undefined; empty/undefined rules -> undefined", () => {
		expect(resolvePathPolicy("/etc/passwd", allow("~/.omp/*"))).toBeUndefined();
		expect(resolvePathPolicy("/etc/passwd", {})).toBeUndefined();
		expect(resolvePathPolicy("/etc/passwd", undefined)).toBeUndefined();
	});
	test("blank/invalid pattern keys are skipped", () => {
		expect(resolvePathPolicy("/ok/x", { "": "allow", "   ": "allow", "/ok/*": "allow" })).toBe("allow");
	});
	test("/tmp/* matches a real temp dir despite the macOS /private/tmp symlink", () => {
		const dir = fs.mkdtempSync("/tmp/omp-guard-glob-");
		try {
			// The heuristic realpaths bash targets, so the target arrives as /private/tmp/... on macOS.
			// resolvePathPolicy canonicalizes the pattern prefix so /tmp/* still matches.
			expect(resolvePathPolicy(fs.realpathSync(dir), allow("/tmp/*"))).toBe("allow");
			expect(resolvePathPolicy(dir, allow("/tmp/*"))).toBe("allow");
		} finally {
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});
});

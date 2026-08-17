/**
 * End-to-end wiring test for the extension entrypoint: builds the real factory
 * with a fake `pi`/`ctx`, captures the registered `tool_call` handler, and
 * asserts the hook's block/allow contract, read-tier skip, and mode gating —
 * without a live model (guardian modes are covered by the manual in-session
 * test). Mode is forced via `OMP_GUARD_MODE`, which takes precedence over the
 * config file.
 */
import { afterEach, describe, expect, test } from "bun:test";
import permissionGuard from "../src/index";

type ToolCallResult = { block?: boolean; reason?: string } | undefined;
type Handler = (event: { toolName: string; input: unknown }, ctx: unknown) => Promise<ToolCallResult>;

function harness() {
	let handler: Handler | undefined;
	const commands: Record<string, { handler: (a: unknown, c: unknown) => Promise<void> }> = {};
	const pi = {
		logger: { debug: (msg: string, data?: unknown) => logs.push({ msg, data }) },
		setLabel: () => {},
		registerCommand: (name: string, def: { handler: (a: unknown, c: unknown) => Promise<void> }) => {
			commands[name] = def;
		},
		on: (evt: string, h: Handler) => {
			if (evt === "tool_call") handler = h;
		},
		getAllTools: () => [
			{ name: "bash", approval: () => "exec" },
			{ name: "read", approval: () => "read" },
		],
	};
	permissionGuard(pi as unknown as Parameters<typeof permissionGuard>[0]);
	return { handler: handler!, commands };
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

afterEach(() => {
	delete process.env.OMP_GUARD_MODE;
	logs.length = 0;
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

	test("read-tier tool is skipped even in heuristic", async () => {
		process.env.OMP_GUARD_MODE = "heuristic";
		const { handler } = harness();
		expect(await handler({ toolName: "read", input: { path: "/etc/passwd" } }, ctx)).toBeUndefined();
	});

	test("prompt with no selection (cancel) -> blocked", async () => {
		process.env.OMP_GUARD_MODE = "guardian"; // exec bash, no model -> failSafe -> prompt; base ctx select -> undefined -> deny
		const { handler } = harness();
		const res = await handler({ toolName: "bash", input: { command: "echo $(date)" } }, ctx);
		expect(res?.block).toBe(true);
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

	test("eval non-py prompt keeps the command line", async () => {
		process.env.OMP_GUARD_MODE = "heuristic";
		let title = "";
		const capCtx = {
			...ctx,
			ui: { notify: (m: string) => notes.push(m), input: async () => undefined, select: async (t: string) => { title = t; return "Deny"; } },
		};
		const { handler } = harness();
		await handler({ toolName: "eval", input: { language: "js", code: "fetch('x')" } }, capCtx);
		expect(title).toContain("eval:");
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
});

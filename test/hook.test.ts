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
		logger: { debug: () => {} },
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
const ctx = {
	cwd: process.cwd(),
	hasUI: true,
	ui: { confirm: async () => false, notify: (m: string) => notes.push(m) },
	models: { resolve: () => undefined, current: () => undefined, list: () => [] },
	modelRegistry: { getApiKey: async () => undefined },
	sessionManager: {
		getEntries: () => [
			{ type: "message", message: { role: "user", content: "delete the temp files" } },
			{ type: "message", message: { role: "assistant", content: [{ type: "text", text: "ok" }] } },
		],
	},
};

afterEach(() => {
	delete process.env.OMP_GUARD_MODE;
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

	test("heuristic uncertain + confirm=false -> blocked", async () => {
		process.env.OMP_GUARD_MODE = "guardian"; // exec-tier bash, no model -> failSafe -> prompt -> confirm=false -> block
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

	test("proven deny + interactive confirm=true -> allowed (human override)", async () => {
		process.env.OMP_GUARD_MODE = "heuristic";
		const okCtx = { ...ctx, ui: { confirm: async () => true, notify: (m: string) => notes.push(m) } };
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

	test("prompt path passes no timeout to confirm (waits indefinitely)", async () => {
		process.env.OMP_GUARD_MODE = "guardian"; // exec-tier bash, no model -> prompt -> confirm
		let seen: Record<string, unknown> | undefined;
		const spyCtx = {
			...ctx,
			ui: {
				confirm: async (_t: string, _m: string, opts?: Record<string, unknown>) => {
					seen = opts;
					return true;
				},
				notify: (m: string) => notes.push(m),
			},
		};
		const { handler } = harness();
		const res = await handler({ toolName: "bash", input: { command: "echo $(date)" } }, spyCtx);
		expect(seen?.timeout).toBeUndefined(); // no timeout => the dialog blocks until the user answers
		expect(res).toBeUndefined(); // confirm=true (user allowed) -> tool runs
	});

	test("'allow this exact call this session' short-circuits identical later calls", async () => {
		process.env.OMP_GUARD_MODE = "heuristic";
		let dialogCalls = 0;
		const sessionCtx = {
			...ctx,
			ui: {
				confirm: async () => false,
				notify: (m: string) => notes.push(m),
				askDialog: async () => {
					dialogCalls++;
					return { kind: "submit", results: [{ selectedOptions: ["Allow this exact call this session"] }] };
				},
			},
		};
		const { handler } = harness();
		const call = { toolName: "bash", input: { command: "rm -rf /" } };
		expect(await handler(call, sessionCtx)).toBeUndefined(); // user allows for the session
		expect(await handler(call, sessionCtx)).toBeUndefined(); // identical call auto-allowed
		expect(dialogCalls).toBe(1); // prompted only once
	});

	test("deny with custom input forwards the user's own message to the agent", async () => {
		process.env.OMP_GUARD_MODE = "heuristic";
		const denyCtx = {
			...ctx,
			ui: {
				confirm: async () => false,
				notify: (m: string) => notes.push(m),
				askDialog: async () => ({ kind: "submit", results: [{ selectedOptions: [], customInput: "use the sandbox path instead" }] }),
			},
		};
		const { handler } = harness();
		const res = await handler({ toolName: "bash", input: { command: "rm -rf /" } }, denyCtx);
		expect(res?.block).toBe(true);
		expect(res?.reason).toContain("use the sandbox path instead");
	});

	test("a guard-initiated prompt recommends Deny", async () => {
		process.env.OMP_GUARD_MODE = "heuristic";
		let recommended: number | undefined;
		const capCtx = {
			...ctx,
			ui: {
				confirm: async () => false,
				notify: (m: string) => notes.push(m),
				askDialog: async (questions: Array<{ recommended?: number }>) => {
					recommended = questions[0]?.recommended;
					return { kind: "submit", results: [{ selectedOptions: ["Deny"] }] };
				},
			},
		};
		const { handler } = harness();
		await handler({ toolName: "bash", input: { command: "rm -rf /" } }, capCtx);
		expect(recommended).toBe(2); // Deny option index
	});
});

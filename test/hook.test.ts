/**
 * End-to-end wiring test for the extension entrypoint: builds the real factory
 * with a fake `pi`/`ctx`, captures the registered `tool_call` handler, and
 * asserts the hook's block/allow contract, read-tier skip, and mode gating —
 * without a live model (guardian modes are covered by the manual in-session
 * test). Mode is forced via `OMP_GUARD_MODE`, which takes precedence over the
 * config file.
 */
import { afterEach, describe, expect, test } from "bun:test";
import permissionGuard, { confirmDialogTimeoutMs } from "../src/index";

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

	test("/guard status shows mode and both timeouts", async () => {
		const { commands } = harness();
		expect(typeof commands.guard?.handler).toBe("function");
		notes.length = 0;
		await commands.guard!.handler("status", ctx);
		const status = notes.find(n => n.includes("mode"));
		expect(status).toBeDefined();
		expect(status).toContain("confirm dialog");
		expect(status).toContain("host handler cap");
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

	test("prompt path clamps the confirm timeout within the host budget", async () => {
		process.env.OMP_GUARD_MODE = "guardian"; // exec-tier bash, no model -> prompt -> confirm
		let seen: { timeout?: number } | undefined;
		const spyCtx = {
			...ctx,
			ui: {
				confirm: async (_t: string, _m: string, opts?: { timeout?: number }) => {
					seen = opts;
					return true;
				},
				notify: (m: string) => notes.push(m),
			},
		};
		const { handler } = harness();
		await handler({ toolName: "bash", input: { command: "echo $(date)" } }, spyCtx);
		expect(typeof seen?.timeout).toBe("number");
		expect(seen?.timeout).toBeGreaterThan(0);
		// Must never exceed the host's 30s handler budget (minus the 2s safety margin),
		// or the host kills the handler before the dialog can resolve.
		expect(seen?.timeout).toBeLessThanOrEqual(28_000);
	});

	test("confirm timeout forces deny even if the dialog auto-selects allow", async () => {
		process.env.OMP_GUARD_MODE = "guardian"; // exec-tier bash, no model -> prompt -> confirm
		// Mimic the interactive TUI: on timeout it fires onTimeout and then
		// auto-selects the highlighted option ("Yes" -> true).
		const timeoutCtx = {
			...ctx,
			ui: {
				confirm: async (_t: string, _m: string, opts?: { onTimeout?: () => void }) => {
					opts?.onTimeout?.();
					return true;
				},
				notify: (m: string) => notes.push(m),
			},
		};
		const { handler } = harness();
		const res = await handler({ toolName: "bash", input: { command: "echo $(date)" } }, timeoutCtx);
		expect(res?.block).toBe(true);
		expect(res?.reason).toContain("Timed out");
	});
});

describe("confirmDialogTimeoutMs clamp", () => {
	test("returns the configured value when it fits the budget", () => {
		expect(confirmDialogTimeoutMs(20_000, 0)).toBe(20_000);
	});

	test("clamps down to budget minus safety margin", () => {
		expect(confirmDialogTimeoutMs(120_000, 0)).toBe(28_000);
	});

	test("subtracts time already spent in the handler", () => {
		expect(confirmDialogTimeoutMs(120_000, 25_000)).toBe(3_000);
	});

	test("never drops below the floor even when the budget is exhausted", () => {
		expect(confirmDialogTimeoutMs(120_000, 29_500)).toBe(1_000);
	});
});

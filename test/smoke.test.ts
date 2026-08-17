/**
 * Smoke test for the load-bearing logic: the vendored analyzer, the
 * prove-or-block heuristic, the tier resolver, and the orchestrator. Runs with
 * `bun test`; needs no `@oh-my-pi/*` package (guardian is not exercised here —
 * it requires a live model, covered by the manual in-session smoke test).
 */
import { describe, expect, test } from "bun:test";
import { evaluatePermission } from "../src/evaluate";
import { classifyHeuristic } from "../src/heuristic";
import { analyzeBashCommand } from "../src/safety-net/index";
import { getToolTier } from "../src/tier";
import { extractAllApprovalPaths } from "../src/approval-path";

const WS = process.cwd();
const ctx = { workspaceRoot: WS, tier: "exec" as const };

describe("vendored analyzer", () => {
	test("flags rm -rf /", () => {
		expect(analyzeBashCommand("rm -rf /", WS)).not.toBeNull();
	});
	test("passes ls", () => {
		expect(analyzeBashCommand("ls -la", WS)).toBeNull();
	});
});

describe("classifyHeuristic (bash)", () => {
	test("proven-dangerous rm -rf / -> deny", () => {
		expect(classifyHeuristic("bash", { command: "rm -rf /" }, ctx).decision).toBe("deny");
	});
	test("flat in-workspace command -> allow", () => {
		expect(classifyHeuristic("bash", { command: "ls -la" }, ctx).decision).toBe("allow");
	});
	test("in-workspace pipeline -> allow", () => {
		expect(classifyHeuristic("bash", { command: "grep -r foo src && cat README.md" }, ctx).decision).toBe("allow");
	});
	test("write to /etc -> not allow (out-of-workspace target)", () => {
		expect(classifyHeuristic("bash", { command: "touch /etc/omp-test" }, ctx).decision).not.toBe("allow");
	});
	test("command substitution -> uncertain", () => {
		expect(classifyHeuristic("bash", { command: "echo $(whoami)" }, ctx).decision).toBe("uncertain");
	});
	test("sudo rm -> deny (critical pattern)", () => {
		expect(classifyHeuristic("bash", { command: "sudo rm /var/log/x" }, ctx).decision).toBe("deny");
	});
});

describe("classifyHeuristic (other tools)", () => {
	test("unknown exec-tier tool (ssh) -> uncertain", () => {
		expect(classifyHeuristic("ssh", { cmd: "reboot" }, { workspaceRoot: WS, tier: "exec" }).decision).toBe(
			"uncertain",
		);
	});
	test("write inside workspace -> allow", () => {
		expect(
			classifyHeuristic("write", { path: "notes.txt" }, { workspaceRoot: WS, tier: "write" }).decision,
		).toBe("allow");
	});
	test("write to ~/.ssh -> deny", () => {
		expect(
			classifyHeuristic("write", { path: "~/.ssh/authorized_keys" }, { workspaceRoot: WS, tier: "write" }).decision,
		).toBe("deny");
	});
	test("todo tool -> always allow (even at exec tier)", () => {
		expect(classifyHeuristic("todo", { items: ["x"] }, { workspaceRoot: WS, tier: "exec" }).decision).toBe("allow");
	});
	test("edit with [PATH#TAG] header inside workspace -> allow", () => {
		const input = "[src/stream.ts#864C]\nPUT >1:\n+const x = 1;";
		expect(classifyHeuristic("edit", { input }, { workspaceRoot: WS, tier: "write" }).decision).toBe("allow");
	});
	test("edit with [PATH#TAG] header outside workspace -> deny", () => {
		const input = "[/etc/passwd#864C]\nPUT >1:\n+x";
		expect(classifyHeuristic("edit", { input }, { workspaceRoot: WS, tier: "write" }).decision).toBe("deny");
	});
	test("edit MV rename escaping the workspace -> deny", () => {
		const input = "[src/a.ts#864C]\nMV ../../../../../../etc/evil.ts";
		expect(classifyHeuristic("edit", { input }, { workspaceRoot: WS, tier: "write" }).decision).toBe("deny");
	});
	test("eval py code embedding a destructive shell command -> deny", () => {
		const args = { language: "py", title: "cleanup", code: "import os; os.system('rm -rf /tmp/x')" };
		expect(classifyHeuristic("eval", args, { workspaceRoot: WS, tier: "exec" }).decision).toBe("deny");
	});
	test("eval py code with no destructive pattern -> uncertain (unsandboxed)", () => {
		const args = { language: "py", title: "read", code: "print(open('/etc/passwd').read())" };
		expect(classifyHeuristic("eval", args, { workspaceRoot: WS, tier: "exec" }).decision).toBe("uncertain");
	});
	test("eval cells variant is still scanned for destructive code -> deny", () => {
		const args = { cells: [{ code: "git reset --hard HEAD~5" }] };
		expect(classifyHeuristic("eval", args, { workspaceRoot: WS, tier: "exec" }).decision).toBe("deny");
	});
	test("ask tool -> always allow", () => {
		expect(classifyHeuristic("ask", { questions: [] }, { workspaceRoot: WS, tier: "exec" }).decision).toBe("allow");
	});
	test("edit patch-mode rename escaping the workspace -> deny", () => {
		const args = { path: "src/a.ts", edits: [{ op: "update", rename: "../../../../../../etc/evil.ts" }] };
		expect(classifyHeuristic("edit", args, { workspaceRoot: WS, tier: "write" }).decision).toBe("deny");
	});
	test("edit [PATH#TAG] with spaces in path -> allow", () => {
		const input = "[src/my file.ts#864C]\nPUT >1:\n+code";
		expect(classifyHeuristic("edit", { input }, { workspaceRoot: WS, tier: "write" }).decision).toBe("allow");
	});
	test("edit multi-section: first in-workspace, second escaping -> deny", () => {
		const input = "[src/good.ts#864C]\nPUT >1:\n+ok\n\n[/etc/passwd#864C]\nPUT >1:\n+evil";
		expect(classifyHeuristic("edit", { input }, { workspaceRoot: WS, tier: "write" }).decision).toBe("deny");
	});
	test("edit apply-patch Add File outside workspace -> deny", () => {
		const input = "*** Begin Patch\n*** Add File: /etc/shadow\n*** End Patch";
		expect(classifyHeuristic("edit", { input }, { workspaceRoot: WS, tier: "write" }).decision).toBe("deny");
	});
	test("edit apply-patch Move to escape -> deny", () => {
		const input = "*** Begin Patch\n*** Update File: src/a.ts\n*** Move to: ../../etc/evil.ts\n*** End Patch";
		expect(classifyHeuristic("edit", { input }, { workspaceRoot: WS, tier: "write" }).decision).toBe("deny");
	});
	test("edit legacy ¶ header inside workspace -> allow", () => {
		const input = "¶src/good.ts#abc\nPUT >1:\n+code";
		expect(classifyHeuristic("edit", { input }, { workspaceRoot: WS, tier: "write" }).decision).toBe("allow");
	});
	test("edit replace-mode plain path field inside workspace -> allow", () => {
		const args = { path: "src/good.ts", old_string: "x", new_string: "y" };
		expect(classifyHeuristic("edit", args, { workspaceRoot: WS, tier: "write" }).decision).toBe("allow");
	});
	test("edit empty input -> uncertain (no checkable path)", () => {
		expect(classifyHeuristic("edit", { input: "" }, { workspaceRoot: WS, tier: "write" }).decision).toBe("uncertain");
	});
	test("extractAllApprovalPaths: quoted MV dest with # and spaces", () => {
		const paths = extractAllApprovalPaths({ input: '[src/a.ts#864C]\nMV "../files with # hash.ts"' });
		expect(paths).toContain("../files with # hash.ts");
	});
	test("extractAllApprovalPaths: patch-mode rename destination", () => {
		const paths = extractAllApprovalPaths({ path: "src/a.ts", edits: [{ rename: "src/b.ts" }] });
		expect(paths).toContain("src/b.ts");
	});
});

describe("getToolTier", () => {
	test("static fallbacks", () => {
		expect(getToolTier("bash", {}, undefined)).toBe("exec");
		expect(getToolTier("read", {}, undefined)).toBe("read");
		expect(getToolTier("write", {}, undefined)).toBe("write");
		expect(getToolTier("mcp__x__y", {}, undefined)).toBe("write");
		expect(getToolTier("totally_unknown_tool", {}, undefined)).toBe("exec");
		expect(getToolTier("ask", {}, undefined)).toBe("read");
		expect(getToolTier("todo", {}, undefined)).toBe("read");
	});
	test("live registry tier wins", () => {
		const tools = [{ name: "custom", approval: "read" }];
		expect(getToolTier("custom", {}, tools)).toBe("read");
	});
});

describe("evaluatePermission (no guardian)", () => {
	const base = { userPolicies: {}, workspaceRoot: WS, hasUI: true } as const;

	test("heuristic: rm -rf / -> deny", async () => {
		const a = await evaluatePermission({
			toolName: "bash",
			args: { command: "rm -rf /" },
			tier: "exec",
			mode: "heuristic",
			...base,
		});
		expect(a.action).toBe("deny");
	});
	test("heuristic: ls -> allow", async () => {
		const a = await evaluatePermission({
			toolName: "bash",
			args: { command: "ls" },
			tier: "exec",
			mode: "heuristic",
			...base,
		});
		expect(a.action).toBe("allow");
	});
	test("heuristic: uncertain ssh -> deny (no judge)", async () => {
		const a = await evaluatePermission({
			toolName: "ssh",
			args: { cmd: "x" },
			tier: "exec",
			mode: "heuristic",
			...base,
		});
		expect(a.action).toBe("deny");
	});
	test("hybrid: uncertain + no guardian + UI -> prompt (fail safe)", async () => {
		const a = await evaluatePermission({
			toolName: "ssh",
			args: { cmd: "x" },
			tier: "exec",
			mode: "hybrid",
			...base,
		});
		expect(a.action).toBe("prompt");
	});
	test("hybrid: uncertain + no guardian + no UI -> deny (fail safe)", async () => {
		const a = await evaluatePermission({
			toolName: "ssh",
			args: { cmd: "x" },
			tier: "exec",
			mode: "hybrid",
			userPolicies: {},
			workspaceRoot: WS,
			hasUI: false,
		});
		expect(a.action).toBe("deny");
	});
	test("user policy allow bypasses heuristic", async () => {
		const a = await evaluatePermission({
			toolName: "bash",
			args: { command: "rm -rf /" },
			tier: "exec",
			mode: "heuristic",
			userPolicies: { bash: "allow" },
			workspaceRoot: WS,
			hasUI: true,
		});
		expect(a.action).toBe("allow");
	});
});

describe("evaluatePermission (intent-aware escalation)", () => {
	const base = { userPolicies: {}, workspaceRoot: WS, hasUI: true } as const;
	const CRIT = { toolName: "bash", args: { command: "sudo rm /var/log/x" }, tier: "exec" } as const;
	const allowGuardian = { evaluate: async () => ({ decision: "allow" as const }) };
	const denyGuardian = { evaluate: async () => ({ decision: "deny" as const, reason: "not requested" }) };

	test("hybrid: blocked + escalate + guardian allows -> allow", async () => {
		const a = await evaluatePermission({
			...CRIT,
			mode: "hybrid",
			guardian: allowGuardian,
			intent: "please run sudo rm /var/log/x",
			escalateBlocked: true,
			...base,
		});
		expect(a.action).toBe("allow");
	});
	test("hybrid: blocked + escalate + guardian denies -> deny (block stands)", async () => {
		const a = await evaluatePermission({ ...CRIT, mode: "hybrid", guardian: denyGuardian, escalateBlocked: true, ...base });
		expect(a.action).toBe("deny");
	});
	test("hybrid: blocked + escalate + no guardian -> deny (block stands)", async () => {
		const a = await evaluatePermission({ ...CRIT, mode: "hybrid", escalateBlocked: true, ...base });
		expect(a.action).toBe("deny");
	});
	test("hybrid: blocked + escalateBlocked=false -> deny, guardian not consulted", async () => {
		let called = false;
		const spy = {
			evaluate: async () => {
				called = true;
				return { decision: "allow" as const };
			},
		};
		const a = await evaluatePermission({ ...CRIT, mode: "hybrid", guardian: spy, escalateBlocked: false, ...base });
		expect(a.action).toBe("deny");
		expect(called).toBe(false);
	});
	test("escalated block forwards blocked=true + intent to the guardian", async () => {
		let seenBlocked: boolean | undefined;
		let seenIntent: string | undefined;
		const capture = {
			evaluate: async (req: { intent?: string; blocked?: boolean }) => {
				seenBlocked = req.blocked;
				seenIntent = req.intent;
				return { decision: "deny" as const, reason: "x" };
			},
		};
		await evaluatePermission({ ...CRIT, mode: "hybrid", guardian: capture, intent: "wipe it", escalateBlocked: true, ...base });
		expect(seenBlocked).toBe(true);
		expect(seenIntent).toBe("wipe it");
	});
	test("guardian mode forwards intent and allows on guardian allow", async () => {
		let seenIntent: string | undefined = "UNSET";
		const capture = {
			evaluate: async (req: { intent?: string }) => {
				seenIntent = req.intent;
				return { decision: "allow" as const };
			},
		};
		const a = await evaluatePermission({
			toolName: "ssh",
			args: { cmd: "x" },
			tier: "exec",
			mode: "guardian",
			guardian: capture,
			intent: "ssh in",
			...base,
		});
		expect(a.action).toBe("allow");
		expect(seenIntent).toBe("ssh in");
	});
});

describe("evaluatePermission (promptOnBlock human override)", () => {
	const base = { userPolicies: {}, workspaceRoot: WS, hasUI: true } as const;
	const CRIT = { toolName: "bash", args: { command: "rm -rf /" }, tier: "exec" } as const;
	const denyGuardian = { evaluate: async () => ({ decision: "deny" as const, reason: "no" }) };

	test("proven deny + promptOnBlock + UI -> prompt", async () => {
		const a = await evaluatePermission({ ...CRIT, mode: "heuristic", promptOnBlock: true, ...base });
		expect(a.action).toBe("prompt");
	});
	test("proven deny + promptOnBlock + no UI -> deny (headless wall stands)", async () => {
		const a = await evaluatePermission({
			...CRIT,
			mode: "heuristic",
			promptOnBlock: true,
			userPolicies: {},
			workspaceRoot: WS,
			hasUI: false,
		});
		expect(a.action).toBe("deny");
	});
	test("proven deny WITHOUT promptOnBlock + UI -> deny (strict wall)", async () => {
		const a = await evaluatePermission({ ...CRIT, mode: "heuristic", promptOnBlock: false, ...base });
		expect(a.action).toBe("deny");
	});
	test("hybrid: guardian denies the escalation + promptOnBlock -> prompt (override offered)", async () => {
		const a = await evaluatePermission({
			...CRIT,
			mode: "hybrid",
			guardian: denyGuardian,
			escalateBlocked: true,
			promptOnBlock: true,
			...base,
		});
		expect(a.action).toBe("prompt");
	});
	test("user-policy deny stays a hard deny even with promptOnBlock", async () => {
		const a = await evaluatePermission({
			toolName: "bash",
			args: { command: "ls" },
			tier: "exec",
			mode: "hybrid",
			userPolicies: { bash: "deny" },
			workspaceRoot: WS,
			hasUI: true,
			promptOnBlock: true,
		});
		expect(a.action).toBe("deny");
	});
	test("guardian-mode deny surfaces a judged prompt (model produced the ruling)", async () => {
		const a = await evaluatePermission({ ...CRIT, mode: "guardian", guardian: denyGuardian, promptOnBlock: true, ...base });
		expect(a.action === "prompt" && a.judged === true).toBe(true);
	});
	test("heuristic deny prompt is NOT judged (no model ruled)", async () => {
		const a = await evaluatePermission({ ...CRIT, mode: "heuristic", promptOnBlock: true, ...base });
		expect(a.action === "prompt" && !a.judged).toBe(true);
	});
	test("hybrid escalation-decline prompt is NOT judged (heuristic block stands)", async () => {
		const a = await evaluatePermission({ ...CRIT, mode: "hybrid", guardian: denyGuardian, escalateBlocked: true, promptOnBlock: true, ...base });
		expect(a.action === "prompt" && !a.judged).toBe(true);
	});
	test("guardian deny propagates confidence to the prompt action", async () => {
		const conf = { evaluate: async () => ({ decision: "deny" as const, reason: "no", confidence: 0.9 }) };
		const a = await evaluatePermission({ ...CRIT, mode: "guardian", guardian: conf, promptOnBlock: true, ...base });
		expect(a.action === "prompt" && a.confidence).toBe(0.9);
	});
});

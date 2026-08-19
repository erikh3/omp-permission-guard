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
import { classifyReadPath, isSecretReadTarget, matchWorkspaceEscape } from "../src/risky-paths";
import { parseSkillLoad } from "../src/path-utils";

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
	const rctx = { workspaceRoot: WS, tier: "read" as const };
	test("grep with no path -> allow (defaults to workspace)", () => {
		expect(classifyHeuristic("grep", { pattern: "foo" }, rctx).decision).toBe("allow");
	});
	test("grep inside the workspace -> allow", () => {
		expect(classifyHeuristic("grep", { pattern: "foo", path: "src" }, rctx).decision).toBe("allow");
	});
	test("grep outside the workspace -> uncertain", () => {
		expect(classifyHeuristic("grep", { pattern: "x", path: "/etc" }, rctx).decision).toBe("uncertain");
	});
	test("grep of an env file inside the workspace -> deny (secret)", () => {
		const v = classifyHeuristic("grep", { pattern: "KEY", path: ".env" }, rctx);
		expect(v.decision).toBe("deny");
		expect(v.secret).toBe(true);
	});
	test("grep of a private key inside the workspace -> deny (secret)", () => {
		expect(classifyHeuristic("grep", { pattern: "x", path: "config/id_rsa" }, rctx).decision).toBe("deny");
	});
	test("grep with a line-range selector inside the workspace -> allow", () => {
		expect(classifyHeuristic("grep", { pattern: "x", path: "src/index.ts:1-20" }, rctx).decision).toBe("allow");
	});
	test.each([
		"src/index.ts:50",
		"src/index.ts:50-200",
		"src/index.ts:50-",
		"src/index.ts:50+150",
		"src/index.ts:5-16,960-973",
		"src/index.ts:raw",
		"src/index.ts:conflicts",
		"src/index.ts:2-4:raw",
		"src/index.ts:raw:2-4",
	])("grep selector %s is stripped -> in-workspace allow", spec => {
		expect(classifyHeuristic("grep", { pattern: "x", path: spec }, rctx).decision).toBe("allow");
	});
	test.each([".env:1-5", ".env.local:raw", "config/id_rsa:10-20", "creds.secret:2-4:raw"])(
		"grep secret file with a selector %s still gated (selector stripped before secret check)",
		spec => {
			expect(classifyHeuristic("grep", { pattern: "x", path: spec }, rctx).decision).toBe("deny");
		},
	);
	test("grep with hidden:true -> uncertain (deliberate reach)", () => {
		expect(classifyHeuristic("grep", { pattern: "x", path: "src", hidden: true }, rctx).decision).toBe("uncertain");
	});
	test("grep with gitignore:false and path -> uncertain (deliberate reach)", () => {
		expect(classifyHeuristic("grep", { pattern: "x", path: ".", gitignore: false }, rctx).decision).toBe("uncertain");
	});
	test("grep with gitignore:false and absent path -> uncertain (deliberate reach)", () => {
		expect(classifyHeuristic("grep", { pattern: "x", gitignore: false }, rctx).decision).toBe("uncertain");
	});
	test("grep with no flags and in-workspace path -> allow (low-noise contract)", () => {
		expect(classifyHeuristic("grep", { pattern: "x", path: "src" }, rctx).decision).toBe("allow");
	});
	test("grep with no flags and absent path -> allow (low-noise contract)", () => {
		expect(classifyHeuristic("grep", { pattern: "x" }, rctx).decision).toBe("allow");
	});
	test("grep non-selector colon path inside workspace -> allow (colon not stripped)", () => {
		expect(classifyHeuristic("grep", { pattern: "x", path: "src/a:b" }, rctx).decision).toBe("allow");
	});
	test("grep non-selector colon path outside workspace -> uncertain (escape survives colon)", () => {
		expect(classifyHeuristic("grep", { pattern: "x", path: "/etc/x:y" }, rctx).decision).toBe("uncertain");
	});
	test("grep semicolon list with one external root -> uncertain", () => {
		expect(classifyHeuristic("grep", { pattern: "x", path: "src; /etc" }, rctx).decision).toBe("uncertain");
	});
	test("grep paths array all in-workspace -> allow", () => {
		expect(classifyHeuristic("grep", { pattern: "x", paths: ["src", "test"] }, rctx).decision).toBe("allow");
	});
	test("grep of a session-allowed extra root -> allow", () => {
		expect(
			classifyHeuristic("grep", { pattern: "x", path: "/tmp/allowed" }, { ...rctx, extraRoots: ["/tmp/allowed"] }).decision,
		).toBe("allow");
	});
	test("grep session-local artifact:// URL -> allow (session-scoped, cannot escape)", () => {
		expect(classifyHeuristic("grep", { pattern: "x", path: "artifact://22" }, rctx).decision).toBe("allow");
	});
	test("grep session-local agent:// URL -> allow", () => {
		expect(classifyHeuristic("grep", { pattern: "x", path: "agent://Worker" }, rctx).decision).toBe("allow");
	});
	test("grep non-session internal-URL (ssh://) -> uncertain", () => {
		expect(classifyHeuristic("grep", { pattern: "x", path: "ssh://host/etc" }, rctx).decision).toBe("uncertain");
	});
	test("read of a secret file (.env) inside workspace -> deny, marked secret", () => {
		const v = classifyHeuristic("read", { path: ".env" }, rctx);
		expect(v.decision).toBe("deny");
		expect(v.secret).toBe(true);
	});
	test("read of .env.local -> deny (secret)", () => {
		expect(classifyHeuristic("read", { path: "config/.env.local" }, rctx).decision).toBe("deny");
	});
	test("read of .env with a line selector -> deny (selector stripped before secret check)", () => {
		expect(classifyHeuristic("read", { path: ".env:1-5" }, rctx).decision).toBe("deny");
	});
	test("read of a private key (id_rsa) -> deny (secret)", () => {
		expect(classifyHeuristic("read", { path: "id_rsa" }, rctx).decision).toBe("deny");
	});
	test("read of a secret file inside an allowed extra root -> still deny (secret wins over allowlist)", () => {
		const v = classifyHeuristic("read", { path: "/tmp/allowed/.env" }, { ...rctx, extraRoots: ["/tmp/allowed"] });
		expect(v.decision).toBe("deny");
		expect(v.secret).toBe(true);
	});
	test("read of an ordinary in-workspace source file -> allow (no prompt)", () => {
		expect(classifyHeuristic("read", { path: "src/index.ts" }, rctx).decision).toBe("allow");
	});
	test("read with a line selector on an ordinary file -> allow", () => {
		expect(classifyHeuristic("read", { path: "src/index.ts:10-20" }, rctx).decision).toBe("allow");
	});
	test("read escaping the workspace -> uncertain", () => {
		expect(classifyHeuristic("read", { path: "/etc/passwd" }, rctx).decision).toBe("uncertain");
	});
	test("read absent path (workspace root listing) -> allow", () => {
		expect(classifyHeuristic("read", {}, rctx).decision).toBe("allow");
	});
	test("read session-local artifact:// URL -> allow", () => {
		expect(classifyHeuristic("read", { path: "artifact://22" }, rctx).decision).toBe("allow");
	});
	test("read non-session internal-URL (ssh://) -> uncertain", () => {
		expect(classifyHeuristic("read", { path: "ssh://host/etc/passwd" }, rctx).decision).toBe("uncertain");
	});
	test("read of a session-allowed extra root -> allow", () => {
		expect(
			classifyHeuristic("read", { path: "/tmp/allowed/x.txt" }, { ...rctx, extraRoots: ["/tmp/allowed"] }).decision,
		).toBe("allow");
	});
	test("read allowed by an exact paths file entry -> allow", () => {
		expect(
			classifyHeuristic("read", { path: "/etc/hosts" }, { ...rctx, allowedPaths: { "/etc/hosts": "allow" } }).decision,
		).toBe("allow");
	});
	test("read NOT matching a sibling paths entry -> uncertain (per-file, non-recursive)", () => {
		expect(
			classifyHeuristic("read", { path: "/etc/passwd" }, { ...rctx, allowedPaths: { "/etc/hosts": "allow" } }).decision,
		).toBe("uncertain");
	});
	test("read allowed by a paths dir glob (/etc/*) -> allow", () => {
		expect(
			classifyHeuristic("read", { path: "/etc/hosts" }, { ...rctx, allowedPaths: { "/etc/*": "allow" } }).decision,
		).toBe("allow");
	});
	test("read denied by an explicit paths deny entry -> deny", () => {
		expect(
			classifyHeuristic("read", { path: "/etc/hosts" }, { ...rctx, allowedPaths: { "/etc/hosts": "deny" } }).decision,
		).toBe("deny");
	});
	test("paths deny short-circuits a broader allow glob", () => {
		const v = classifyHeuristic("read", { path: "/etc/hosts" }, { ...rctx, allowedPaths: { "/etc/*": "allow", "/etc/hosts": "deny" } });
		expect(v.decision).toBe("deny");
	});
	test("secret file still denied even when covered by a paths allow glob", () => {
		const v = classifyHeuristic("read", { path: "/etc/ssl/private/.env" }, { ...rctx, allowedPaths: { "/etc/*": "allow" } });
		expect(v.decision).toBe("deny");
		expect(v.secret).toBe(true);
	});
	test("grep allowed by a paths dir glob -> allow", () => {
		expect(
			classifyHeuristic("grep", { pattern: "x", path: "/etc/*" }, { workspaceRoot: WS, tier: "read", allowedPaths: { "/etc/*": "allow" } }).decision,
		).toBe("allow");
	});
	test("bash writing under a paths glob (/tmp/*) -> allow (covers the temp-dir case)", () => {
		const dir = require("node:fs").mkdtempSync("/tmp/omp-guard-bash-");
		try {
			expect(
				classifyHeuristic("bash", { command: `mkdir -p ${dir}/plan && touch ${dir}/plan/notes.md` }, { workspaceRoot: WS, tier: "exec", allowedPaths: { "/tmp/*": "allow" } }).decision,
			).toBe("allow");
		} finally {
			require("node:fs").rmSync(dir, { recursive: true, force: true });
		}
	});
	// B1: non-string policy value must not throw (was TypeError: rawPolicy.trim is not a function)
	test("B1 regression: non-string policy value in paths -> gracefully skipped, not a throw", () => {
		expect(() =>
			classifyHeuristic("read", { path: "/etc/hosts" }, { ...rctx, allowedPaths: { "/etc/*": 1 as unknown as string } }),
		).not.toThrow();
		// The invalid entry is skipped -> path not matched -> uncertain (escape)
		expect(
			classifyHeuristic("read", { path: "/etc/hosts" }, { ...rctx, allowedPaths: { "/etc/*": 1 as unknown as string } }).decision,
		).toBe("uncertain");
	});
	// B2: paths deny must block write/edit tools, not just reads
	test("B2 regression: paths deny on an in-workspace write target -> deny (not silently allowed)", () => {
		expect(
			classifyHeuristic("write", { path: "src/sensitive.ts" }, { workspaceRoot: WS, tier: "write", allowedPaths: { "src/sensitive.ts": "deny" } }).decision,
		).toBe("deny");
		expect(
			classifyHeuristic("edit", { input: "[src/sensitive.ts#AAAA]\nPUT >1:\n+x" }, { workspaceRoot: WS, tier: "write", allowedPaths: { "src/sensitive.ts": "deny" } }).decision,
		).toBe("deny");
	});
	// B3: classifyRiskyPath still runs for paths-allow writes; a symlink to a .env file (denylist hit
	// that is NOT a workspace-escape reason) is blocked even with an allow glob. The macOS
	// /private/etc alias gap in SYSTEM_ROOTS is pre-existing and out of scope.
	test("B3 regression: paths-allow write does not bypass .env denylist hit via symlink", () => {
		const osm = require("node:os");
		const fsm = require("node:fs");
		const pathm = require("node:path");
		const linkDir = fsm.mkdtempSync(pathm.join(osm.tmpdir(), "omp-guard-symlink-"));
		try {
			// Create a .env file (denylist) and a symlink to it with a non-.env name inside the allowed dir
			const realEnv = pathm.join(linkDir, ".env");
			const linkPath = pathm.join(linkDir, "config-link");
			fsm.writeFileSync(realEnv, "SECRET=123");
			fsm.symlinkSync(realEnv, linkPath);
			// classifyRiskyPath follows the symlink -> resolves to .env -> denylist hit (not just workspace-escape)
			const v = classifyHeuristic("write", { path: linkPath }, { workspaceRoot: WS, tier: "write", allowedPaths: { [`${linkDir}/*`]: "allow" } });
			expect(v.decision).toBe("deny");
		} finally {
			fsm.rmSync(linkDir, { recursive: true, force: true });
		}
	});
	// C1: garbage/traversal skill URLs must not be tagged as skill loads
	test("C1 regression: skill://.. traversal URL falls through to generic uncertain, not skill rail", () => {
		const v = classifyHeuristic("read", { path: "skill://../etc/passwd" }, { ...rctx });
		expect(v.decision).toBe("uncertain");
		expect(v.skillLoad).toBeUndefined();
	});
	test("C1 regression: empty skill:// name falls through to uncertain, not skill rail", () => {
		const v = classifyHeuristic("read", { path: "skill://" }, { ...rctx });
		expect(v.decision).toBe("uncertain");
		expect(v.skillLoad).toBeUndefined();
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
	test("hub send to a peer (agent messaging) -> allow", () => {
		const args = { op: "send", to: "BridgeEndpoints", message: "status?" };
		expect(classifyHeuristic("hub", args, { workspaceRoot: WS, tier: "exec" }).decision).toBe("allow");
	});
	test("hub wait / list / jobs (coordination + inspection) -> allow", () => {
		for (const op of ["wait", "inbox", "list", "jobs", "ps", "logs", "describe"]) {
			expect(classifyHeuristic("hub", { op }, { workspaceRoot: WS, tier: "exec" }).decision).toBe("allow");
		}
	});
	test("hub wait scoped to a process (name present, not a send) -> allow", () => {
		const args = { op: "wait", name: "difit", for: "exit", timeout: 1800 };
		expect(classifyHeuristic("hub", args, { workspaceRoot: WS, tier: "exec" }).decision).toBe("allow");
	});
	test("hub start (launches an arbitrary process) -> uncertain", () => {
		const args = { op: "start", name: "web", application: "bun", args: ["run", "dev"] };
		expect(classifyHeuristic("hub", args, { workspaceRoot: WS, tier: "exec" }).decision).toBe("uncertain");
	});
	test("hub send writing into a live process (name present) -> uncertain", () => {
		const args = { op: "send", name: "debugger", text: "os.system('rm -rf ~')" };
		expect(classifyHeuristic("hub", args, { workspaceRoot: WS, tier: "exec" }).decision).toBe("uncertain");
	});
	test("hub with no op (unknown shape) -> uncertain", () => {
		expect(classifyHeuristic("hub", {}, { workspaceRoot: WS, tier: "exec" }).decision).toBe("uncertain");
	});
	test("hub with an unknown/future op -> uncertain (allowlist fails closed)", () => {
		const args = { op: "exec_shell", command: "rm -rf /" };
		expect(classifyHeuristic("hub", args, { workspaceRoot: WS, tier: "exec" }).decision).toBe("uncertain");
	});
	test("hub stop (mutates process lifecycle) -> uncertain", () => {
		const args = { op: "stop", name: "web" };
		expect(classifyHeuristic("hub", args, { workspaceRoot: WS, tier: "exec" }).decision).toBe("uncertain");
	});
	test("hub cancel (mutates job lifecycle) -> uncertain", () => {
		const args = { op: "cancel", ids: ["bash_x"] };
		expect(classifyHeuristic("hub", args, { workspaceRoot: WS, tier: "exec" }).decision).toBe("uncertain");
	});
	// restart re-launches an arbitrary retained spec, gated like start
	test("hub restart (re-launches retained spec) -> uncertain", () => {
		const args = { op: "restart", name: "web" };
		expect(classifyHeuristic("hub", args, { workspaceRoot: WS, tier: "exec" }).decision).toBe("uncertain");
	});
	test("hub send with both to and name (process-directed wins, fails closed) -> uncertain", () => {
		const args = { op: "send", to: "Peer", name: "debugger", text: "x" };
		expect(classifyHeuristic("hub", args, { workspaceRoot: WS, tier: "exec" }).decision).toBe("uncertain");
	});
	test("hub send with empty-string name key (name key present -> process-directed) -> uncertain", () => {
		const args = { op: "send", to: "Peer", name: "" };
		expect(classifyHeuristic("hub", args, { workspaceRoot: WS, tier: "exec" }).decision).toBe("uncertain");
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
		expect(getToolTier("ast_grep", {}, undefined)).toBe("read");
	});
	test("live registry approval wins for a non-built-in", () => {
		const tools = [{ name: "custom", approval: "read" as const }];
		expect(getToolTier("custom", {}, tools)).toBe("read");
	});
	test("built-in static tier beats an approval-less registry entry", () => {
		// The real registry (getAllToolInfos) strips `approval`; trusting it would
		// fail-safe every built-in to exec. Static must win so grep/read stay read.
		const registry = [
			{ name: "grep", description: "", parameters: {} },
			{ name: "read", description: "", parameters: {} },
			{ name: "bash", description: "", parameters: {} },
		];
		expect(getToolTier("grep", {}, registry)).toBe("read");
		expect(getToolTier("read", {}, registry)).toBe("read");
		expect(getToolTier("bash", {}, registry)).toBe("exec");
	});
	test("approval-less non-built-in falls through to exec fail-safe", () => {
		const registry = [{ name: "some_device", description: "", parameters: {} }];
		expect(getToolTier("some_device", {}, registry)).toBe("exec");
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
	test("guardian mode: benign hub send -> allow without invoking the judge", async () => {
		const a = await evaluatePermission({
			toolName: "hub",
			args: { op: "send", to: "BridgeEndpoints", message: "status?" },
			tier: "exec",
			mode: "guardian",
			...base,
		});
		expect(a.action).toBe("allow");
	});
	test("guardian mode: hub start still gated (no guardian -> fail safe prompt)", async () => {
		const a = await evaluatePermission({
			toolName: "hub",
			args: { op: "start", name: "web", application: "bun", args: ["run", "dev"] },
			tier: "exec",
			mode: "guardian",
			...base,
		});
		expect(a.action).toBe("prompt");
	});
	test("guardian mode: hub restart now gated (no guardian -> fail safe prompt)", async () => {
		const a = await evaluatePermission({
			toolName: "hub",
			args: { op: "restart", name: "web" },
			tier: "exec",
			mode: "guardian",
			...base,
		});
		expect(a.action).toBe("prompt");
	});
	test("guardian mode: user policy hub:deny overrides guardian hub short-circuit -> deny", async () => {
		const a = await evaluatePermission({
			toolName: "hub",
			args: { op: "send", to: "X", message: "hi" },
			tier: "exec",
			mode: "guardian",
			userPolicies: { hub: "deny" },
			workspaceRoot: WS,
			hasUI: true,
		});
		expect(a.action).toBe("deny");
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

describe("isSecretReadTarget (secret files)", () => {
	test.each([
		".env",
		".env.local",
		".env.production",
		".netrc",
		".pgpass",
		".npmrc",
		".htpasswd",
		"config/id_rsa",
		"keys/id_ed25519",
		"certs/server.pem",
		"certs/client.key",
		"store.keystore",
		"app.jks",
		"my.pfx",
		"vault.p12",
		"app.token",
		"gh.token",
		"x.tokens",
		".token",
		".tokens",
		".tokens.json",
		".token-old",
		"creds.secret",
		"aws-credentials.ini",
		"my-credentials.yaml",
		"a/b/.ssh/known_hosts",
		".envrc",
		"config/.envrc",
		".SSH/known_hosts",
	])("flags secret file %s", p => {
		expect(isSecretReadTarget(p, WS)).toBe(true);
	});

	test.each([
		"src/index.ts",
		"package.json",
		".gitignore",
		"README.md",
		// `token`/`tokens` as ordinary source words must NOT be gated (extension-only match).
		"src/token.ts",
		"lexer/tokens.py",
		"src/token-utils.ts",
		"parser/token_stream.rs",
		"Tokenizer.java",
		"retokenize.js",
		"brokentoken.md",
		// `key`/`secret`/`credential` as substrings without a boundary/extension are fine.
		"src/keyboard.ts",
		"monkey.go",
	])("does not flag ordinary file %s", p => {
		expect(isSecretReadTarget(p, WS)).toBe(false);
	});

	test("normalizes path traversal before the secret check", () => {
		expect(isSecretReadTarget("src/../.env.production", WS)).toBe(true);
		expect(isSecretReadTarget("src/../.env", WS)).toBe(true);
	});

	test("flags a secret regardless of the workspace root (out-of-workspace secret)", () => {
		expect(isSecretReadTarget("/tmp/x/.env", WS)).toBe(true);
	});
});

describe("classifyReadPath (workspace containment)", () => {
	test("allows an ordinary in-workspace read", () => {
		expect(classifyReadPath("src/index.ts", WS)).toBeNull();
	});
	test("flags an out-of-workspace read", () => {
		expect(classifyReadPath("/etc/passwd", WS)).toContain("outside the workspace root");
	});
	test("no longer re-checks secrets (that is isSecretReadTarget's job) -> in-workspace secret is null", () => {
		expect(classifyReadPath(".env", WS)).toBeNull();
	});

	test("matchWorkspaceEscape returns undefined for a secret-file reason", () => {
		expect(matchWorkspaceEscape("read targets a secret or environment file: /x/.env")).toBeUndefined();
	});

	test("matchWorkspaceEscape returns the escaped path from an escape reason", () => {
		expect(matchWorkspaceEscape("grep outside the workspace root: /etc/passwd")).toBe("/etc/passwd");
	});
});

describe("evaluatePermission (grep routing)", () => {
	const base = { userPolicies: {}, workspaceRoot: WS, hasUI: true, escalateBlocked: true, promptOnBlock: true } as const;
	const rTier = "read" as const;
	const allowGuardian = { evaluate: async () => ({ decision: "allow" as const }) };

	test("guardian mode: in-workspace grep -> allow, spy guardian NOT invoked", async () => {
		let called = false;
		const spyGuardian = {
			evaluate: async () => {
				called = true;
				throw new Error("guardian should not be invoked for safe grep");
			},
		};
		const a = await evaluatePermission({
			toolName: "grep",
			args: { pattern: "x", path: "src" },
			tier: rTier,
			mode: "guardian",
			guardian: spyGuardian,
			...base,
		});
		expect(a.action).toBe("allow");
		expect(called).toBe(false);
	});

	test("secret grep is a hard deny in every mode, and the guardian is NEVER consulted", async () => {
		let called = false;
		const spyGuardian = {
			evaluate: async () => {
				called = true;
				return { decision: "allow" as const };
			},
		};
		for (const mode of ["heuristic", "guardian", "hybrid"] as const) {
			const a = await evaluatePermission({
				toolName: "grep",
				args: { pattern: "x", path: ".env" },
				tier: rTier,
				mode,
				guardian: spyGuardian,
				...base,
			});
			expect(a.action).toBe("deny");
		}
		expect(called).toBe(false); // secret reads never escalate, even with an allow-guardian
	});

	test("secret read is a hard deny in every mode, and the guardian is NEVER consulted", async () => {
		let called = false;
		const spyGuardian = {
			evaluate: async () => {
				called = true;
				return { decision: "allow" as const };
			},
		};
		for (const mode of ["heuristic", "guardian", "hybrid"] as const) {
			const a = await evaluatePermission({
				toolName: "read",
				args: { path: ".env" },
				tier: rTier,
				mode,
				guardian: spyGuardian,
				...base,
			});
			expect(a.action).toBe("deny");
		}
		expect(called).toBe(false);
	});

	test("secret read hard-denies even headless (no UI) — never a prompt", async () => {
		const a = await evaluatePermission({
			toolName: "read",
			args: { path: "config/id_rsa" },
			tier: rTier,
			mode: "hybrid",
			guardian: allowGuardian,
			userPolicies: {},
			workspaceRoot: WS,
			hasUI: true,
			promptOnBlock: true,
			escalateBlocked: true,
		});
		expect(a.action).toBe("deny"); // promptOnBlock does not soften a secret deny
	});
});

describe("evaluatePermission (secret beats userPolicy allow/prompt)", () => {
	const rTier = "read" as const;
	const allowGuardian = { evaluate: async () => ({ decision: "allow" as const }) };

	// (a) userPolicy:allow cannot open a secret file via read or grep — any mode.
	test.each(["heuristic", "guardian", "hybrid"] as const)(
		"%s mode: read .env with userPolicy read:allow -> deny",
		async mode => {
			const a = await evaluatePermission({
				toolName: "read",
				args: { path: ".env" },
				tier: rTier,
				mode,
				userPolicies: { read: "allow" },
				workspaceRoot: WS,
				hasUI: true,
				promptOnBlock: true,
				guardian: allowGuardian,
			});
			expect(a.action).toBe("deny");
		},
	);

	test.each(["heuristic", "guardian", "hybrid"] as const)(
		"%s mode: grep .env with userPolicy grep:allow -> deny",
		async mode => {
			const a = await evaluatePermission({
				toolName: "grep",
				args: { pattern: "AWS_SECRET", path: ".env" },
				tier: rTier,
				mode,
				userPolicies: { grep: "allow" },
				workspaceRoot: WS,
				hasUI: true,
				promptOnBlock: true,
				guardian: allowGuardian,
			});
			expect(a.action).toBe("deny");
		},
	);

	test.each(["heuristic", "guardian", "hybrid"] as const)(
		"%s mode: read .env with userPolicy read:prompt -> deny (not prompted)",
		async mode => {
			const a = await evaluatePermission({
				toolName: "read",
				args: { path: ".env" },
				tier: rTier,
				mode,
				userPolicies: { read: "prompt" },
				workspaceRoot: WS,
				hasUI: true,
				promptOnBlock: true,
				guardian: allowGuardian,
			});
			expect(a.action).toBe("deny");
		},
	);
});

describe("evaluatePermission (guardian mode: non-secret escape escalation)", () => {
	// (b) Guardian mode: a non-secret workspace escape is escalated to the guardian
	// (blocked===false) — the guardian decides allow/deny, NOT the heuristic alone.
	test("guardian mode: non-secret /etc/hosts read -> guardian invoked with blocked=false, returns allow", async () => {
		let capturedBlocked: boolean | undefined;
		const captureGuardian = {
			evaluate: async (req: { blocked?: boolean }) => {
				capturedBlocked = req.blocked;
				return { decision: "allow" as const };
			},
		};
		const a = await evaluatePermission({
			toolName: "read",
			args: { path: "/etc/hosts" },
			tier: "read" as const,
			mode: "guardian",
			userPolicies: {},
			workspaceRoot: WS,
			hasUI: true,
			promptOnBlock: true,
			escalateBlocked: true,
			guardian: captureGuardian,
		});
		expect(a.action).toBe("allow");
		expect(capturedBlocked).toBe(false);
	});

	test("guardian mode: non-secret /etc grep -> guardian invoked with blocked=false, returns allow", async () => {
		let capturedBlocked: boolean | undefined;
		const captureGuardian = {
			evaluate: async (req: { blocked?: boolean }) => {
				capturedBlocked = req.blocked;
				return { decision: "allow" as const };
			},
		};
		const a = await evaluatePermission({
			toolName: "grep",
			args: { pattern: "localhost", path: "/etc" },
			tier: "read" as const,
			mode: "guardian",
			userPolicies: {},
			workspaceRoot: WS,
			hasUI: true,
			promptOnBlock: true,
			escalateBlocked: true,
			guardian: captureGuardian,
		});
		expect(a.action).toBe("allow");
		expect(capturedBlocked).toBe(false);
	});
});

describe("evaluatePermission (secret hard-deny: headless and UI cases)", () => {
	const rTier = "read" as const;
	const allowGuardian = { evaluate: async () => ({ decision: "allow" as const }) };

	// (c) Headless secret: hasUI:false must still hard-deny.
	test("secret read hard-denies when hasUI=false (headless)", async () => {
		const a = await evaluatePermission({
			toolName: "read",
			args: { path: "config/id_rsa" },
			tier: rTier,
			mode: "hybrid",
			guardian: allowGuardian,
			userPolicies: {},
			workspaceRoot: WS,
			hasUI: false,
			promptOnBlock: true,
			escalateBlocked: true,
		});
		expect(a.action).toBe("deny");
	});

	// promptOnBlock + UI also cannot soften a secret deny.
	test("secret read hard-denies even with promptOnBlock + UI — never a prompt", async () => {
		const a = await evaluatePermission({
			toolName: "read",
			args: { path: "config/id_rsa" },
			tier: rTier,
			mode: "hybrid",
			guardian: allowGuardian,
			userPolicies: {},
			workspaceRoot: WS,
			hasUI: true,
			promptOnBlock: true,
			escalateBlocked: true,
		});
		expect(a.action).toBe("deny");
	});
});

describe("isSecretReadTarget (.aws and .gnupg dir segments)", () => {
	// (d) New secret directory segments must be gated.
	test("flags .aws/config as secret", () => {
		expect(isSecretReadTarget(".aws/config", WS)).toBe(true);
	});
	test("flags .aws/credentials as secret", () => {
		expect(isSecretReadTarget(".aws/credentials", WS)).toBe(true);
	});
	test("flags .gnupg/gpg.conf as secret", () => {
		expect(isSecretReadTarget(".gnupg/gpg.conf", WS)).toBe(true);
	});
	test("flags .AWS/config (case-insensitive) as secret", () => {
		expect(isSecretReadTarget(".AWS/config", WS)).toBe(true);
	});
	test("does not flag an ordinary src file as secret", () => {
		expect(isSecretReadTarget("src/config.ts", WS)).toBe(false);
	});
});

describe("parseSkillLoad", () => {
	test("skill:// URL -> skill kind + name", () => {
		expect(parseSkillLoad("skill://obsidian-markdown")).toEqual({ kind: "skill", name: "obsidian-markdown" });
	});
	test("rule:// URL -> rule kind + name", () => {
		expect(parseSkillLoad("rule://ts-set-map")).toEqual({ kind: "rule", name: "ts-set-map" });
	});
	test("skill:// with a subpath keeps only the name segment", () => {
		expect(parseSkillLoad("skill://graphify/SKILL.md")).toEqual({ kind: "skill", name: "graphify" });
	});
	test("skill:// with a selector strips it", () => {
		expect(parseSkillLoad("skill://catch-up:1-20")).toEqual({ kind: "skill", name: "catch-up" });
	});
	test("non-skill internal URL -> undefined", () => {
		expect(parseSkillLoad("ssh://host/etc")).toBeUndefined();
	});
	test("plain filesystem path -> undefined", () => {
		expect(parseSkillLoad("src/index.ts")).toBeUndefined();
	});
});

describe("classifyHeuristic (skill/rule loads)", () => {
	const rctx = { workspaceRoot: WS, tier: "read" as const };
	test("read skill:// -> uncertain, tagged skillLoad", () => {
		const v = classifyHeuristic("read", { path: "skill://obsidian-markdown" }, rctx);
		expect(v.decision).toBe("uncertain");
		expect(v.skillLoad).toEqual({ kind: "skill", name: "obsidian-markdown" });
	});
	test("read rule:// -> tagged skillLoad", () => {
		expect(classifyHeuristic("read", { path: "rule://ts-set-map" }, rctx).skillLoad).toEqual({
			kind: "rule",
			name: "ts-set-map",
		});
	});
	test("other internal URLs (ssh://) carry no skillLoad tag", () => {
		expect(classifyHeuristic("read", { path: "ssh://host/x" }, rctx).skillLoad).toBeUndefined();
	});
});

describe("evaluatePermission (skill-load rail)", () => {
	const base = { userPolicies: {}, workspaceRoot: WS } as const;
	const skillArgs = { toolName: "read", args: { path: "skill://obsidian-markdown" }, tier: "read" as const } as const;

	test("no rules + UI -> allow-leaning prompt naming the skill", async () => {
		for (const mode of ["heuristic", "guardian", "hybrid"] as const) {
			const a = await evaluatePermission({ ...skillArgs, mode, hasUI: true, ...base });
			expect(a.action).toBe("prompt");
			expect(a.action === "prompt" && a.recommend).toBe("allow");
			expect(a.action === "prompt" && a.skillLoad?.name).toBe("obsidian-markdown");
		}
	});
	test("exact-name allow rule -> allow (no prompt)", async () => {
		const a = await evaluatePermission({ ...skillArgs, mode: "hybrid", hasUI: true, skillLoadRules: { "obsidian-markdown": "allow" }, ...base });
		expect(a.action).toBe("allow");
	});
	test("wildcard '*' allow rule -> allow any skill", async () => {
		const a = await evaluatePermission({ ...skillArgs, mode: "hybrid", hasUI: true, skillLoadRules: { "*": "allow" }, ...base });
		expect(a.action).toBe("allow");
	});
	test("prefix glob 'obsidian-*' allow rule -> allow a matching skill", async () => {
		const a = await evaluatePermission({ ...skillArgs, mode: "hybrid", hasUI: true, skillLoadRules: { "obsidian-*": "allow" }, ...base });
		expect(a.action).toBe("allow");
	});
	test("prefix glob that does NOT match -> still prompts", async () => {
		const a = await evaluatePermission({ ...skillArgs, mode: "hybrid", hasUI: true, skillLoadRules: { "work-*": "allow" }, ...base });
		expect(a.action).toBe("prompt");
	});
	test("explicit deny rule -> deny (never prompts)", async () => {
		const a = await evaluatePermission({ ...skillArgs, mode: "hybrid", hasUI: true, skillLoadRules: { "obsidian-markdown": "deny" }, ...base });
		expect(a.action).toBe("deny");
	});
	test("deny match wins over an overlapping allow match", async () => {
		const a = await evaluatePermission({ ...skillArgs, mode: "hybrid", hasUI: true, skillLoadRules: { "*": "allow", "obsidian-*": "deny" }, ...base });
		expect(a.action).toBe("deny");
	});
	test("explicit prompt rule -> prompts (does not auto-allow)", async () => {
		const a = await evaluatePermission({ ...skillArgs, mode: "hybrid", hasUI: true, skillLoadRules: { "*": "prompt" }, ...base });
		expect(a.action).toBe("prompt");
	});
	test("headless (no UI) + no matching allow -> fail-safe deny", async () => {
		const a = await evaluatePermission({ ...skillArgs, mode: "hybrid", hasUI: false, ...base });
		expect(a.action).toBe("deny");
	});
	test("headless (no UI) + matching allow rule -> allow (no prompt needed)", async () => {
		const a = await evaluatePermission({ ...skillArgs, mode: "hybrid", hasUI: false, skillLoadRules: { "obsidian-*": "allow" }, ...base });
		expect(a.action).toBe("allow");
	});
	test("a real workspace escape (non-skill) is NOT diverted to the skill rail", async () => {
		const a = await evaluatePermission({
			toolName: "read",
			args: { path: "ssh://host/etc/passwd" },
			tier: "read",
			mode: "heuristic",
			hasUI: true,
			promptOnBlock: true,
			...base,
		});
		expect(a.action === "prompt" && a.skillLoad).toBeUndefined();
		expect(a.action === "prompt" && a.recommend).toBe("deny");
	});
});

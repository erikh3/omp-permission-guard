/**
 * Unit tests for the Guardian's candidate-model iteration and retry policy.
 * Drives {@link GuardianJudge} with an injected `completeSimple` so no live
 * model is needed. Covers the hardening added for extension-registered
 * providers whose API the guardian's isolated pi-ai can't map: skip such a
 * candidate immediately (no wasted retries) and fall back to the next usable
 * model, while still retrying genuine transient failures on a usable model.
 */
import { describe, expect, test } from "bun:test";
import type { Api, AssistantMessage, Model } from "@oh-my-pi/pi-ai";
import { type CompleteSimpleFn, type GuardianDeps, GuardianJudge } from "../src/guardian";

const UNMAPPABLE = "Unhandled API in mapOptionsForApi: sap-aicore-orchestration";

function model(provider: string, id: string, api: string): Model<Api> {
	return { provider, id, api, name: id, reasoning: false, cost: { input: 1 } } as unknown as Model<Api>;
}

function allowVerdict(): AssistantMessage {
	return {
		stopReason: "toolUse",
		content: [{ type: "toolCall", name: "verdict", arguments: { decision: "allow" } }],
	} as unknown as AssistantMessage;
}

function denyVerdict(reason: string): AssistantMessage {
	return {
		stopReason: "toolUse",
		content: [{ type: "toolCall", name: "verdict", arguments: { decision: "deny", reason } }],
	} as unknown as AssistantMessage;
}

const REQ = { toolName: "bash", args: { command: "echo hi" } } as const;

function makeJudge(
	models: Model<Api>[],
	completeSimple: CompleteSimpleFn,
	opts?: { maxAttempts?: number },
): GuardianJudge {
	const deps: GuardianDeps = {
		resolveModels: () => models,
		getApiKey: async () => "test-key",
		completeSimple,
	};
	// baseBackoffMs: 0 keeps transient-retry tests instant.
	return new GuardianJudge(deps, { maxAttempts: opts?.maxAttempts ?? 3, baseBackoffMs: 0 });
}

describe("GuardianJudge candidate iteration", () => {
	test("skips an unmappable candidate and judges with the next mappable one", async () => {
		const calls: string[] = [];
		const completeSimple: CompleteSimpleFn = async m => {
			calls.push(m.provider);
			if (m.provider === "sap-aicore") throw new Error(UNMAPPABLE);
			return allowVerdict();
		};
		const judge = makeJudge(
			[model("sap-aicore", "haiku", "sap-aicore-orchestration"), model("hai-proxy", "haiku", "anthropic-messages")],
			completeSimple,
		);

		const verdict = await judge.evaluate(REQ);

		expect(verdict.decision).toBe("allow");
		// Unmappable model tried exactly once (no retry), then the mappable fallback.
		expect(calls).toEqual(["sap-aicore", "hai-proxy"]);
	});

	test("returns error when every candidate API is unmappable (no retries burned)", async () => {
		const calls: string[] = [];
		const completeSimple: CompleteSimpleFn = async m => {
			calls.push(`${m.provider}/${m.id}`);
			throw new Error(UNMAPPABLE);
		};
		const judge = makeJudge(
			[model("sap-aicore", "haiku", "sap-aicore-orchestration"), model("sap-aicore", "sonnet", "sap-aicore-orchestration")],
			completeSimple,
		);

		const verdict = await judge.evaluate(REQ);

		expect(verdict.decision).toBe("error");
		// Each unmappable candidate attempted exactly once — no wasted retry budget.
		expect(calls).toEqual(["sap-aicore/haiku", "sap-aicore/sonnet"]);
	});

	test("retries transient failures on a mappable model, then succeeds", async () => {
		let attempts = 0;
		const completeSimple: CompleteSimpleFn = async () => {
			attempts++;
			if (attempts < 3) throw new Error("temporary network blip");
			return allowVerdict();
		};
		const judge = makeJudge([model("hai-proxy", "haiku", "anthropic-messages")], completeSimple, { maxAttempts: 3 });

		const verdict = await judge.evaluate(REQ);

		expect(verdict.decision).toBe("allow");
		expect(attempts).toBe(3);
	});

	test("does not cascade to further models after a mappable model exhausts retries", async () => {
		const calls: string[] = [];
		const completeSimple: CompleteSimpleFn = async m => {
			calls.push(m.provider);
			throw new Error("temporary network blip"); // transient, never recovers
		};
		const judge = makeJudge(
			[model("hai-proxy", "haiku", "anthropic-messages"), model("openai", "gpt", "openai-completions")],
			completeSimple,
			{ maxAttempts: 2 },
		);

		const verdict = await judge.evaluate(REQ);

		expect(verdict.decision).toBe("error");
		// First (mappable) model retried maxAttempts times; the second model is NOT tried.
		expect(calls).toEqual(["hai-proxy", "hai-proxy"]);
	});

	test("passes through a parsed deny verdict", async () => {
		const judge = makeJudge([model("hai-proxy", "haiku", "anthropic-messages")], async () => denyVerdict("looks dangerous"));

		const verdict = await judge.evaluate(REQ);

		expect(verdict.decision).toBe("deny");
		if (verdict.decision === "deny") expect(verdict.reason).toBe("looks dangerous");
	});

	test("returns error when there are no candidate models", async () => {
		const judge = makeJudge([], async () => allowVerdict());
		expect((await judge.evaluate(REQ)).decision).toBe("error");
	});
});

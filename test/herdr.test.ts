/**
 * Unit tests for the optional herdr integration: the `herdr:blocked` bus emit
 * and the display-only `pane.report_metadata` request builder. Both must be hard
 * no-ops outside a herdr pane and must never throw into the approval flow.
 */
import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import {
	blockedSummary,
	clearBlockedMetadata,
	emitBlocked,
	HERDR_BLOCKED_EVENT,
	HERDR_METADATA_SOURCE,
	type HerdrEventBus,
	metadataRequest,
	reportBlockedMetadata,
} from "../src/herdr";

const HERDR_ENV_KEYS = ["HERDR_ENV", "HERDR_PANE_ID", "HERDR_SOCKET_PATH", "HERDR_BIN_PATH"] as const;
const saved: Record<string, string | undefined> = {};

beforeEach(() => {
	for (const k of HERDR_ENV_KEYS) {
		saved[k] = process.env[k];
		delete process.env[k];
	}
});

afterEach(() => {
	for (const k of HERDR_ENV_KEYS) {
		if (saved[k] === undefined) delete process.env[k];
		else process.env[k] = saved[k];
	}
});

/** A bus that records every emit; optionally throws to prove failures are swallowed. */
function recordingBus(throwOnEmit = false): { bus: HerdrEventBus; calls: { channel: string; data: unknown }[] } {
	const calls: { channel: string; data: unknown }[] = [];
	return {
		calls,
		bus: {
			emit(channel, data) {
				calls.push({ channel, data });
				if (throwOnEmit) throw new Error("listener blew up");
			},
		},
	};
}

function enterHerdrPane() {
	process.env.HERDR_ENV = "1";
	process.env.HERDR_PANE_ID = "w1:p1";
	process.env.HERDR_SOCKET_PATH = "/tmp/herdr-test.sock";
}

describe("emitBlocked", () => {
	test("emits an active toggle with the label", () => {
		const { bus, calls } = recordingBus();
		emitBlocked(bus, true, "could not prove safe");
		expect(calls).toEqual([{ channel: HERDR_BLOCKED_EVENT, data: { active: true, label: "could not prove safe" } }]);
	});

	test("inactive toggle carries no label", () => {
		const { bus, calls } = recordingBus();
		emitBlocked(bus, false);
		expect(calls).toEqual([{ channel: HERDR_BLOCKED_EVENT, data: { active: false } }]);
	});

	test("undefined bus (herdr not installed) is a no-op", () => {
		expect(() => emitBlocked(undefined, true, "x")).not.toThrow();
	});

	test("a throwing listener never propagates into the approval flow", () => {
		const { bus } = recordingBus(true);
		expect(() => emitBlocked(bus, true, "x")).not.toThrow();
	});
});

describe("metadataRequest env-gating", () => {
	test("returns undefined outside a herdr pane", () => {
		expect(metadataRequest({ summary: null })).toBeUndefined();
	});

	test("returns undefined when HERDR_ENV is unset even if other vars present", () => {
		process.env.HERDR_PANE_ID = "w1:p1";
		process.env.HERDR_SOCKET_PATH = "/tmp/herdr-test.sock";
		expect(metadataRequest({ summary: "x" })).toBeUndefined();
	});

	test("returns undefined when the pane id or socket path is missing", () => {
		process.env.HERDR_ENV = "1";
		process.env.HERDR_SOCKET_PATH = "/tmp/herdr-test.sock";
		expect(metadataRequest({ summary: "x" })).toBeUndefined();
	});

	test("does NOT depend on HERDR_BIN_PATH (only socket path is required)", () => {
		process.env.HERDR_ENV = "1";
		process.env.HERDR_PANE_ID = "w1:p1";
		process.env.HERDR_SOCKET_PATH = "/tmp/herdr-test.sock";
		// HERDR_BIN_PATH intentionally left unset.
		expect(metadataRequest({ summary: "x" })).toBeDefined();
	});

	test("inside a herdr pane, builds a pane.report_metadata request with a strictly increasing seq", () => {
		enterHerdrPane();
		const first = metadataRequest({ summary: "awaiting approval: bash" }) as {
			method: string;
			params: { pane_id: string; source: string; seq: number; tokens: Record<string, string | null> };
		};
		const second = metadataRequest({ summary: null }) as typeof first;

		expect(first.method).toBe("pane.report_metadata");
		expect(first.params.pane_id).toBe("w1:p1");
		expect(first.params.source).toBe(HERDR_METADATA_SOURCE);
		expect(first.params.tokens).toEqual({ summary: "awaiting approval: bash" });
		// A null token value is the documented "clear this token" signal.
		expect(second.params.tokens).toEqual({ summary: null });
		expect(second.params.seq).toBeGreaterThan(first.params.seq);
	});

	test("enriched summary token carries tool + detail so herdr names the awaited call", () => {
		// blockedSummary composes what reportBlockedMetadata writes: the tool name
		// plus the compact args preview, so the sidebar/notch names the call even
		// when herdr's scraped dialog body is empty or truncated.
		expect(blockedSummary("grep", 'pattern "foo" in src')).toBe('\u23f8 grep \u00b7 pattern "foo" in src');
		// No detail (or blank) falls back to the tool name alone.
		expect(blockedSummary("bash")).toBe("\u23f8 bash");
		expect(blockedSummary("edit", "   ")).toBe("\u23f8 edit");
	});
});

describe("report/clear metadata side-effect helpers", () => {
	test("are no-ops (do not throw) outside a herdr pane", () => {
		expect(() => reportBlockedMetadata("bash")).not.toThrow();
		expect(() => clearBlockedMetadata()).not.toThrow();
	});
});

/**
 * Optional integration with the herdr terminal multiplexer.
 *
 * When the guard opens an approval dialog it pauses the agent, but nothing in
 * OMP's tool_call flow fires the events herdr watches for its "blocked" state
 * (`tool_approval_requested` / the `ask` tool). Without a signal, herdr's OMP
 * lifecycle extension keeps the pane in `working` while the user is actually
 * being asked a question. This module surfaces the pause two ways, both hard
 * no-ops outside herdr:
 *
 *   1. **Lifecycle state (`emitBlocked`)** — emits a `herdr:blocked` event on the
 *      shared extension bus. herdr's bundled `herdr-omp-agent-state.ts` already
 *      listens for exactly this event and ref-counts it into `blocked`, reported
 *      through the SAME `herdr:omp` source as its lifecycle authority. There is
 *      therefore no second state source for herdr to arbitrate. When herdr is not
 *      installed the event has no listener and the emit is a silent no-op.
 *
 *   2. **Display metadata (`reportBlockedMetadata` / `clearBlockedMetadata`)** —
 *      sends a `pane.report_metadata` request over herdr's unix socket to set a
 *      display-only `summary` token, so a sidebar row templated with `$summary`
 *      shows what the pane is waiting on. This never authors lifecycle state; it
 *      is cosmetic. We talk to the socket directly (rather than shelling the
 *      `herdr` CLI) because a pane only reliably inherits `HERDR_SOCKET_PATH`;
 *      `HERDR_BIN_PATH` is frequently empty. Gated on `HERDR_ENV`, so it is a
 *      no-op outside a herdr pane.
 */
import net from "node:net";

/** Event name herdr's OMP integration subscribes to; payload `{ active, label? }`. */
export const HERDR_BLOCKED_EVENT = "herdr:blocked";

/** Stable, unique reporter id for our display-only metadata writes. */
export const HERDR_METADATA_SOURCE = "custom:permission-guard";

/** herdr socket method that sets display-only pane metadata (never lifecycle state). */
const REPORT_METADATA_METHOD = "pane.report_metadata";

/** The subset of the shared extension `EventBus` we depend on. */
export interface HerdrEventBus {
	emit(channel: string, data: unknown): void;
}

/**
 * Emit the ref-counted `herdr:blocked` toggle. `active: true` when a dialog opens,
 * `active: false` when it closes; herdr balances the two. Best-effort: a missing
 * bus or a throwing listener never propagates into the guard's approval flow.
 */
export function emitBlocked(events: HerdrEventBus | undefined, active: boolean, label?: string): void {
	if (!events) return;
	try {
		events.emit(HERDR_BLOCKED_EVENT, active ? { active: true, label } : { active: false });
	} catch {
		// herdr signalling is advisory; swallow so a broken listener cannot block approvals.
	}
}

/** Resolved herdr pane socket context, present only inside a herdr pane. */
interface HerdrSocketEnv {
	endpoint: string;
	paneId: string;
}

/**
 * The `HERDR_*` variables needed to reach the pane's herdr socket. Returns
 * `undefined` (making every metadata call a no-op) unless herdr is active and
 * both the socket path and pane id are known. A pane reliably inherits
 * `HERDR_SOCKET_PATH`; `HERDR_BIN_PATH` is often empty, so we do not depend on it.
 */
function herdrSocketEnv(): HerdrSocketEnv | undefined {
	if (process.env.HERDR_ENV !== "1") return undefined;
	const paneId = process.env.HERDR_PANE_ID;
	const socketPath = process.env.HERDR_SOCKET_PATH;
	if (!paneId || !socketPath) return undefined;
	// Windows named pipes are addressed differently from unix domain sockets.
	const endpoint =
		process.platform === "win32" ? `\\\\.\\pipe\\${socketPath}` : socketPath;
	return { endpoint, paneId };
}

// herdr tracks the last-accepted seq PER SOURCE, and that record survives our
// process (agent restarts, reloads). A per-process counter starting at 0 would
// be shadowed by a higher seq from a previous run, so every report — including
// the clear — would be silently dropped as stale, leaving a stuck token. Seed
// with epoch-ms so seqs are monotonic across restarts. Milliseconds also leave
// headroom for many increments between any two process starts.
let metadataSeq = Date.now();

/**
 * Build the `pane.report_metadata` JSON-RPC request for a set of token writes, or
 * `undefined` when not running inside a herdr pane. A `null` token value clears
 * that token. Split from the socket write so the env-gating and payload shape are
 * unit-testable without opening a connection.
 */
export function metadataRequest(tokens: Record<string, string | null>): Record<string, unknown> | undefined {
	const env = herdrSocketEnv();
	if (!env) return undefined;
	// A strictly increasing seq lets herdr drop out-of-order writes when concurrent
	// tool calls each open and close a dialog; stale seqs from this source are ignored.
	metadataSeq += 1;
	return {
		id: `${HERDR_METADATA_SOURCE}:${Date.now()}:${Math.random().toString(36).slice(2)}`,
		method: REPORT_METADATA_METHOD,
		params: {
			pane_id: env.paneId,
			source: HERDR_METADATA_SOURCE,
			seq: metadataSeq,
			tokens,
		},
	};
}

/** Fire-and-forget newline-delimited JSON write to the herdr socket; never blocks or throws. */
function sendMetadata(tokens: Record<string, string | null>): void {
	const env = herdrSocketEnv();
	const request = metadataRequest(tokens);
	if (!env || !request) return;
	try {
		const socket = net.createConnection(env.endpoint);
		const finish = () => socket.destroy();
		socket.on("error", finish);
		socket.on("connect", () => {
			socket.write(`${JSON.stringify(request)}\n`);
		});
		// herdr replies with a single JSON line; we do not need it. Close on first
		// response, on end, or after a short timeout so the socket never lingers.
		socket.on("data", finish);
		socket.on("end", finish);
		const timeout = setTimeout(finish, 1000);
		timeout.unref?.();
	} catch {
		// Display-only; a failed connection must never affect the approval flow.
	}
}

/**
 * Set the display-only `summary` token to a compact "paused on you" marker.
 * Sidebar space is tight and truncates, so lead with the U+23F8 pause glyph and
 * the tool name only — the full reason and args are in the dialog itself, one
 * click away on the agent row.
 */
export function reportBlockedMetadata(toolName: string): void {
	sendMetadata({ summary: `\u23f8 ${toolName}` });
}

/** Clear the `summary` token once the dialog resolves. */
export function clearBlockedMetadata(): void {
	sendMetadata({ summary: null });
}

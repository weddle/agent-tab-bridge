import crypto from "node:crypto";
export const TASK_SESSION_CAPABILITIES = ["cdp"] as const;
export type TaskSessionCapability = (typeof TASK_SESSION_CAPABILITIES)[number];
export type TaskSessionState = "pending" | "active" | "revoked";
export const MAX_REVOKED_TASK_SESSION_TOMBSTONES = 64;

export const MAX_TASK_SESSION_TTL_MS = 24 * 60 * 60_000;
export type TaskSession = Readonly<{ id: string; controllerPrincipalId: string; displayControllerName: string; taskLabel: string; requestedCapabilities: readonly TaskSessionCapability[]; createdAt: number; expiresAt: number | null; state: TaskSessionState }>;
export type TaskSessionRelay = Readonly<{ pairingUrl: string; cdpUrl: string; close: () => Promise<void> }>;
export type OpenTaskSessionInput = Readonly<{ controllerPrincipalId: string; controllerName: string; taskLabel: string; capabilities: readonly string[]; ttlMs?: number }>;
export type SessionApproval = Readonly<{ session: TaskSession; pairingUrl: string }>;
export type SessionLifecycleEvent = Readonly<{ type: "pending"; session: TaskSession }> | Readonly<{ type: "active"; session: TaskSession; cdpUrl: string }> | Readonly<{ type: "revoked"; session: TaskSession; reason: string }>;
export type TaskSessionManagerOptions = Readonly<{ startRelay: () => Promise<TaskSessionRelay>; now?: () => number; setTimer?: (callback: () => void, delayMs: number) => NodeJS.Timeout; clearTimer?: (timer: NodeJS.Timeout | null) => void; idFactory?: () => string; onEvent?: (event: SessionLifecycleEvent) => void }>;
type Stored = { session: TaskSession; relay: TaskSessionRelay | null; approval: Promise<SessionApproval> | null; ready: boolean; timer: NodeJS.Timeout | null; revoking: Promise<TaskSession> | null };
export class TaskSessionError extends Error { constructor(readonly code: "invalidSession" | "unsupportedCapability" | "invalidTtl" | "notPending" | "notActive" | "notFound", message: string) { super(message); this.name = "TaskSessionError"; } }
const clone = (session: TaskSession): TaskSession => ({ ...session, requestedCapabilities: [...session.requestedCapabilities] });
const changed = (session: TaskSession, state: TaskSessionState): TaskSession => ({ ...session, state, requestedCapabilities: [...session.requestedCapabilities] });
function display(value: string, field: string): string { const result = value.trim().slice(0, 128); if (!result) throw new TaskSessionError("invalidSession", `${field} must not be empty`); return result; }
/** Isolated sessions: a pending session never creates or owns a relay. */
export class TaskSessionManager {
  private readonly stored = new Map<string, Stored>();
  private readonly now: () => number; private readonly ids: () => string;
  private readonly setTimer: (callback: () => void, delayMs: number) => NodeJS.Timeout;
  private readonly clearTimer: (timer: NodeJS.Timeout | null) => void;
  constructor(private readonly options: TaskSessionManagerOptions) { this.now = options.now ?? Date.now; this.ids = options.idFactory ?? crypto.randomUUID; this.setTimer = options.setTimer ?? ((callback, delay) => setTimeout(callback, delay)); this.clearTimer = options.clearTimer ?? ((timer) => clearTimeout(timer ?? undefined)); }
  open(input: OpenTaskSessionInput): TaskSession {
    const capabilities = [...new Set(input.capabilities)]; if (!capabilities.length || capabilities.some((capability) => capability !== "cdp")) throw new TaskSessionError("unsupportedCapability", "only the cdp capability is supported");
    const ttl = input.ttlMs;
    if (ttl !== undefined && (!Number.isSafeInteger(ttl) || ttl <= 0 || ttl > MAX_TASK_SESSION_TTL_MS)) throw new TaskSessionError("invalidTtl", "invalid session TTL");
    const now = this.now();
    const session: TaskSession = {
      id: this.ids(),
      controllerPrincipalId: display(input.controllerPrincipalId, "controller principal ID"),
      displayControllerName: display(input.controllerName, "controller name"),
      taskLabel: display(input.taskLabel, "task label"),
      requestedCapabilities: capabilities as TaskSessionCapability[],
      createdAt: now,
      expiresAt: ttl === undefined ? null : now + ttl,
      state: "pending",
    };
    if (this.stored.has(session.id)) throw new TaskSessionError("invalidSession", "session ID collision");
    const stored: Stored = { session, relay: null, approval: null, ready: false, timer: null, revoking: null };
    if (ttl !== undefined) {
      stored.timer = this.setTimer(() => { void this.revoke(session.id, "ttlExpired").catch(() => {}); }, ttl);
      stored.timer.unref?.();
    }
    this.stored.set(session.id, stored);
    this.emit({ type: "pending", session: clone(session) });
    return clone(session);
  }
  approve(id: string): Promise<SessionApproval> {
    const stored = this.require(id); if (stored.session.state !== "pending") { if (stored.approval) return stored.approval; throw new TaskSessionError("notPending", "session is not pending"); }
    stored.session = changed(stored.session, "active");
    stored.approval = (async () => { try { const relay = await this.options.startRelay(); if (stored.session.state === "revoked") { await relay.close(); throw new TaskSessionError("notActive", "session was revoked"); } stored.relay = relay; return { session: clone(stored.session), pairingUrl: relay.pairingUrl }; } catch (error) { await this.revoke(id, "relayStartFailed"); throw error; } })();
    return stored.approval;
  }
  relayReady(id: string): TaskSession { const stored = this.require(id); if (stored.session.state !== "active" || !stored.relay) throw new TaskSessionError("notActive", "session relay is not active"); if (!stored.ready) { stored.ready = true; this.emit({ type: "active", session: clone(stored.session), cdpUrl: stored.relay.cdpUrl }); } return clone(stored.session); }
  async relayFailed(id: string, reason = "relayFailed"): Promise<TaskSession> { return await this.revoke(id, reason); }
  async revoke(id: string, reason = "revoked"): Promise<TaskSession> { const stored = this.require(id); if (stored.revoking) return await stored.revoking; if (stored.session.state === "revoked") return clone(stored.session); stored.session = changed(stored.session, "revoked"); stored.ready = false; this.clearTimer(stored.timer); stored.timer = null; const relay = stored.relay; stored.relay = null; stored.revoking = (async () => { this.emit({ type: "revoked", session: clone(stored.session), reason }); try { if (relay) await relay.close(); } finally { this.compactRevoked(); } return clone(stored.session); })(); return await stored.revoking; }

  private compactRevoked(): void { const revoked = [...this.stored.entries()].filter(([, stored]) => stored.session.state === "revoked"); revoked.sort(([, left], [, right]) => left.session.createdAt - right.session.createdAt); while (revoked.length > MAX_REVOKED_TASK_SESSION_TOMBSTONES) { const oldest = revoked.shift(); if (oldest) this.stored.delete(oldest[0]); } }

  async revokeAll(reason = "hostClosing"): Promise<void> { await Promise.allSettled([...this.stored.keys()].map(async (id) => await this.revoke(id, reason))); }
  async sweepExpired(): Promise<void> { const now = this.now(); await Promise.all([...this.stored.values()].filter(({ session }) => session.state !== "revoked" && session.expiresAt !== null && session.expiresAt <= now).map(async ({ session }) => await this.revoke(session.id, "ttlExpired"))); }
  get(id: string): TaskSession | undefined { const stored = this.stored.get(id); return stored ? clone(stored.session) : undefined; }
  snapshot(): TaskSession[] { return [...this.stored.values()].filter(({ session }) => session.state !== "revoked").map(({ session }) => clone(session)); }
  cdpUrl(id: string): string | undefined { const stored = this.stored.get(id); return stored?.ready && stored.session.state === "active" ? stored.relay?.cdpUrl : undefined; }
  private require(id: string): Stored { const stored = this.stored.get(id); if (!stored) throw new TaskSessionError("notFound", "session was not found"); return stored; }
  private emit(event: SessionLifecycleEvent): void { try { this.options.onEvent?.(event); } catch {} }
}

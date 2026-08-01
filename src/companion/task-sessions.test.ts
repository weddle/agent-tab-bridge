import { describe, expect, it, vi } from "vitest";
import { TaskSessionManager } from "./task-sessions.js";

type FakeRelay = {
  pairingUrl: string;
  cdpUrl: string;
  close: () => Promise<void>;
};
function makeRelayFactory() {
  const relays: FakeRelay[] = [];
  const startRelay = vi.fn(async () => {
    const index = relays.length + 1;
    const relay: FakeRelay = {
      pairingUrl: `ws://127.0.0.1/extension/${index}`,
      cdpUrl: `ws://127.0.0.1/cdp/${index}`,
      close: vi.fn(async () => undefined),
    };
    relays.push(relay);
    return relay;
  });
  return { relays, startRelay };
}

describe("TaskSessionManager integration contract", () => {
  it("orders pending, approval, relay readiness, and active visibility", async () => {
    let now = 10_000;
    const events: Array<{ type: string; session?: { id: string }; cdpUrl?: string }> = [];
    const { relays, startRelay } = makeRelayFactory();
    const manager = new TaskSessionManager({
      startRelay,
      now: () => now,
      idFactory: () => "session-1",
      onEvent: (event) => events.push(event),
    });

    const pending = manager.open({
      controllerPrincipalId: "controller-1",
      controllerName: "Unverified display name",
      taskLabel: "read docs",
      capabilities: ["cdp"],
      ttlMs: 5_000,
    });
    expect(pending).toMatchObject({ id: "session-1", state: "pending" });
    expect(events.map(({ type }) => type)).toEqual(["pending"]);
    expect(startRelay).not.toHaveBeenCalled();
    expect(manager.cdpUrl("session-1")).toBeUndefined();

    const approved = await manager.approve("session-1");
    expect(approved).toMatchObject({ session: { id: "session-1", state: "active" }, pairingUrl: relays[0]?.pairingUrl });
    expect(startRelay).toHaveBeenCalledTimes(1);
    expect(events.map(({ type }) => type)).toEqual(["pending"]);
    expect(manager.cdpUrl("session-1")).toBeUndefined();

    expect(manager.relayReady("session-1")).toMatchObject({ id: "session-1", state: "active" });
    expect(events.map(({ type }) => type)).toEqual(["pending", "active"]);
    expect(events[1]).toMatchObject({ type: "active", session: { id: "session-1" }, cdpUrl: relays[0]?.cdpUrl });
    expect(manager.cdpUrl("session-1")).toBe(relays[0]?.cdpUrl);
  });
  it("suspends active sessions for a same-endpoint relay recovery", async () => {
    const events: string[] = [];
    const { relays, startRelay } = makeRelayFactory();
    const manager = new TaskSessionManager({ startRelay, idFactory: () => "session-recovery", onEvent: (event) => events.push(event.type) });
    const pending = manager.open({ controllerPrincipalId: "controller-1", controllerName: "CLI", taskLabel: "recover", capabilities: ["cdp"], stableSessionKey: "recover-key" });
    await manager.approve(pending.id);
    manager.relayReady(pending.id);
    expect(manager.suspend()).toMatchObject([{ id: pending.id, state: "reconnecting" }]);
    expect(manager.snapshot()).toMatchObject([{ id: pending.id, state: "reconnecting" }]);
    expect(manager.cdpUrl(pending.id)).toBeUndefined();
    expect(manager.open({ controllerPrincipalId: "controller-1", controllerName: "CLI", taskLabel: "recover", capabilities: ["cdp"], stableSessionKey: "recover-key" })).toMatchObject({ id: pending.id, state: "reconnecting" });
    manager.relayReady(pending.id);
    expect(manager.get(pending.id)).toMatchObject({ state: "active" });
    expect(manager.cdpUrl(pending.id)).toBe(relays[0]?.cdpUrl);
    expect(events).toEqual(["pending", "active", "reconnecting", "active"]);
  });

  it("creates an indefinite session without an expiry timer", async () => {
    let now = 10_000;
    const setTimer = vi.fn();
    const { startRelay } = makeRelayFactory();
    const manager = new TaskSessionManager({ startRelay, now: () => now, setTimer });
    const session = manager.open({
      controllerPrincipalId: "controller-1",
      controllerName: "CLI",
      taskLabel: "indefinite",
      capabilities: ["cdp"],
    });
    expect(session.expiresAt).toBeNull();
    expect(setTimer).not.toHaveBeenCalled();

    now += 24 * 60 * 60 * 1_000;
    await manager.sweepExpired();
    expect(manager.get(session.id)).toMatchObject({ state: "pending", expiresAt: null });
  });

  it("keeps concurrent session relays and URLs independent", async () => {
    const { relays, startRelay } = makeRelayFactory();
    const manager = new TaskSessionManager({ startRelay, idFactory: (() => { let n = 0; return () => `session-${++n}`; })() });
    const first = manager.open({ controllerPrincipalId: "c1", controllerName: "one", taskLabel: "one", capabilities: ["cdp"], ttlMs: 10_000 });
    const second = manager.open({ controllerPrincipalId: "c2", controllerName: "two", taskLabel: "two", capabilities: ["cdp"], ttlMs: 10_000 });

    const [firstApproved, secondApproved] = await Promise.all([manager.approve(first.id), manager.approve(second.id)]);
    expect(relays).toHaveLength(2);
    expect(firstApproved.pairingUrl).not.toBe(secondApproved.pairingUrl);
    manager.relayReady(first.id);
    manager.relayReady(second.id);
    expect(manager.cdpUrl(first.id)).toBe(relays[0]?.cdpUrl);
    expect(manager.cdpUrl(second.id)).toBe(relays[1]?.cdpUrl);
  });

  it("revokes on TTL expiry or relay failure and closes each relay once", async () => {
    let now = 100;
    const events: Array<{ type: string; reason?: string }> = [];
    const { relays, startRelay } = makeRelayFactory();
    const manager = new TaskSessionManager({ startRelay, now: () => now, onEvent: (event) => events.push(event) });
    const expiring = manager.open({ controllerPrincipalId: "c1", controllerName: "one", taskLabel: "one", capabilities: ["cdp"], ttlMs: 20 });
    await manager.approve(expiring.id);
    now = 121;
    await manager.sweepExpired();
    expect(events.at(-1)).toMatchObject({ type: "revoked", reason: "ttlExpired" });
    await manager.revoke(expiring.id, "explicit");
    expect(relays[0]?.close).toHaveBeenCalledTimes(1);

    const disconnected = manager.open({ controllerPrincipalId: "c2", controllerName: "two", taskLabel: "two", capabilities: ["cdp"], ttlMs: 20 });
    await manager.approve(disconnected.id);
    await manager.relayFailed(disconnected.id, "relay-failed");
    expect(events.at(-1)).toMatchObject({ type: "revoked", reason: "relay-failed" });
    await manager.relayFailed(disconnected.id, "relay-failed");
    expect(relays[1]?.close).toHaveBeenCalledTimes(1);
  });
  it("reuses only an active named session with the same controller, label, and capabilities", async () => {
    const { relays, startRelay } = makeRelayFactory();
    const manager = new TaskSessionManager({ startRelay, idFactory: (() => { let next = 0; return () => `session-${++next}`; })() });
    const first = manager.open({ controllerPrincipalId: "controller-1", controllerName: "CLI", taskLabel: "Research", capabilities: ["cdp"], stableSessionKey: "research" });
    await manager.approve(first.id);
    manager.relayReady(first.id);
    expect(manager.snapshot()[0]).not.toHaveProperty("stableSessionKey");

    const reused = manager.open({ controllerPrincipalId: "controller-1", controllerName: "CLI", taskLabel: "Research", capabilities: ["cdp"], stableSessionKey: "research" });
    expect(reused.id).toBe(first.id);
    expect(manager.cdpUrl(reused.id)).toBe(relays[0]?.cdpUrl);
    expect(startRelay).toHaveBeenCalledTimes(1);
    expect(() => manager.open({ controllerPrincipalId: "controller-1", controllerName: "CLI", taskLabel: "Different task", capabilities: ["cdp"], stableSessionKey: "research" })).toThrow(/different session authority/);
    expect(() => manager.open({ controllerPrincipalId: "controller-1", controllerName: "CLI", taskLabel: "Research", capabilities: ["cdp", "cdp"], stableSessionKey: "research" })).toThrow(/only the cdp capability/);

    const anotherController = manager.open({ controllerPrincipalId: "controller-2", controllerName: "CLI", taskLabel: "Research", capabilities: ["cdp"], stableSessionKey: "research" });
    expect(anotherController).toMatchObject({ id: "session-2", state: "pending" });
    await expect(manager.revokeNamed("controller-1", "research")).resolves.toMatchObject({ id: first.id, state: "revoked" });
    expect(manager.open({ controllerPrincipalId: "controller-1", controllerName: "CLI", taskLabel: "Research", capabilities: ["cdp"], stableSessionKey: "research" })).toMatchObject({ id: "session-3", state: "pending" });
  });
  it("applies only monotonic access upgrades to active sessions", async () => {
    const events: Array<{ type: string; accessRequest?: { id: string }; access?: { level: string } }> = [];
    const { startRelay } = makeRelayFactory();
    const manager = new TaskSessionManager({ startRelay, onEvent: (event) => events.push(event) });
    const session = manager.open({
      controllerPrincipalId: "controller-1",
      controllerName: "CLI",
      taskLabel: "scoped research",
      capabilities: ["cdp"],
      access: { level: "selectedTabs", tabIds: [7], domains: [] },
      stableSessionKey: "scoped",
    });
    await manager.approve(session.id);
    manager.relayReady(session.id);

    const delta = { kind: "domains", tabIds: [], domains: ["example.com"] } as const;
    const pending = manager.previewAccessUpgrade("controller-1", "scoped", delta);
    expect(pending.access).toEqual({ level: "domains", tabIds: [7], domains: ["example.com"] });
    const updated = manager.applyAccessUpgrade(session.id, delta, pending.access);
    expect(updated.access).toEqual({ level: "domains", tabIds: [7], domains: ["example.com"] });
    expect(events.at(-1)?.type).toBe("active");
    expect(() => manager.previewAccessUpgrade("controller-1", "scoped", { kind: "tabs", tabIds: [7], domains: [] })).toThrow(/does not add authority/);
  });
  it("bounds revoked tombstones while keeping recent revoke idempotence", async () => {
    let next = 0;
    const manager = new TaskSessionManager({ startRelay: async () => ({ pairingUrl: "ws://127.0.0.1/pair", cdpUrl: "ws://127.0.0.1/cdp", close: async () => undefined }), idFactory: () => `session-${++next}` });
    for (let index = 0; index < 70; index += 1) {
      const session = manager.open({ controllerPrincipalId: "controller", controllerName: "CLI", taskLabel: `task-${index}`, capabilities: ["cdp"], ttlMs: 10_000 });
      await manager.revoke(session.id, "explicit");
    }
    expect(manager.snapshot()).toEqual([]);
    expect(manager.get("session-1")).toBeUndefined();
    await expect(manager.revoke("session-70", "again")).resolves.toMatchObject({ state: "revoked" });
  });
});

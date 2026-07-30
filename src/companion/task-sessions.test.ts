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

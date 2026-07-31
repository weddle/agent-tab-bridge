import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createBrokerClient } from "./broker-client.js";
import { startBrokerServer } from "./broker.js";
import { TaskSessionManager } from "./task-sessions.js";

const directories: string[] = [];
afterEach(async () => { await Promise.all(directories.splice(0).map(async (directory) => await rm(directory, { recursive: true, force: true }))); });

describe("BrokerServer socket ownership", () => {
  it("fails closed rather than unlinking a live broker socket", async () => {
    const directory = await mkdtemp(join(tmpdir(), "atb-broker-")); directories.push(directory);
    const sessions = new TaskSessionManager({ startRelay: async () => ({ pairingUrl: "ws://127.0.0.1/extension#token", cdpUrl: "ws://127.0.0.1/cdp?token=token", close: async () => undefined }) });
    const options = { socketPath: join(directory, "broker.sock"), token: "a".repeat(32), sessions, isTrusted: () => false, controller: () => null };
    const first = await startBrokerServer(options);
    await expect(startBrokerServer(options)).rejects.toThrow("already running");
    await first.close();
  });
  it("reuses a named approved session across separate broker clients and closes it by stable key", async () => {
    const directory = await mkdtemp(join(tmpdir(), "atb-broker-")); directories.push(directory);
    const sessions = new TaskSessionManager({
      idFactory: () => "named-session",
      startRelay: async () => ({ pairingUrl: "ws://127.0.0.1/extension#token", cdpUrl: "ws://127.0.0.1/cdp?token=token", close: async () => undefined }),
    });
    const token = "a".repeat(32);
    const broker = await startBrokerServer({
      socketPath: join(directory, "broker.sock"),
      token,
      sessions,
      isTrusted: () => true,
      controller: () => ({ principalId: "controller-1", displayName: "CLI" }),
      requestAccess: async (_principalId, _stableSessionKey, delta) => ({
        id: "access-1",
        sessionId: "named-session",
        delta,
        requestedAccess: { level: "domains", tabIds: [], domains: ["example.com"] },
        createdAt: Date.now(),
      }),
    });
    try {
      const first = createBrokerClient({ socketPath: broker.socketPath, token });
      const opened = await first.request("openSession", { taskLabel: "Research", requestedCapabilities: ["cdp"], stableSessionKey: "research" }) as { session: { id: string } };
      await first.close();
      await sessions.approve(opened.session.id);
      sessions.relayReady(opened.session.id);

      const later = createBrokerClient({ socketPath: broker.socketPath, token });
      await expect(later.request("openSession", { taskLabel: "Research", requestedCapabilities: ["cdp"], stableSessionKey: "research" })).resolves.toMatchObject({
        session: { id: opened.session.id },
        cdpUrl: "ws://127.0.0.1/cdp?token=token",
      });
      await later.close();
      expect(sessions.get(opened.session.id)).toMatchObject({ state: "active" });

      const accessClient = createBrokerClient({ socketPath: broker.socketPath, token });
      await expect(accessClient.request("requestAccess", {
        stableSessionKey: "research",
        accessDelta: { kind: "domains", tabIds: [], domains: ["example.com"] },
      })).resolves.toMatchObject({
        accessRequest: {
          id: "access-1",
          sessionId: opened.session.id,
          requestedAccess: { level: "domains", domains: ["example.com"] },
        },
      });
      await accessClient.close();

      const conflicting = createBrokerClient({ socketPath: broker.socketPath, token });
      await expect(conflicting.request("openSession", { taskLabel: "Different task", requestedCapabilities: ["cdp"], stableSessionKey: "research" })).rejects.toThrow(/different session authority/);
      await conflicting.close();

      const closer = createBrokerClient({ socketPath: broker.socketPath, token });
      await expect(closer.request("closeSession", { stableSessionKey: "research" })).resolves.toMatchObject({ session: { id: opened.session.id, state: "revoked" } });
      await closer.close();
    } finally {
      await broker.close();
    }
  });
});

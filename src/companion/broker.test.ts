import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { createConnection, createServer } from "node:net";
import { setTimeout as delay } from "node:timers/promises";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createBrokerClient } from "./broker-client.js";
import { startBrokerServer } from "./broker.js";
import { createProfile } from "./profiles.js";
import { generateIdentity } from "./identity.js";
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
  it("waits for a closing server to release the socket path before rebinding", async () => {
    const directory = await mkdtemp(join(tmpdir(), "atb-broker-")); directories.push(directory);
    const socketPath = join(directory, "broker.sock");
    const closingServer = createServer();
    await new Promise<void>((resolve, reject) => {
      closingServer.once("error", reject);
      closingServer.listen(socketPath, () => { closingServer.off("error", reject); resolve(); });
    });
    const heldConnection = createConnection(socketPath);
    await new Promise<void>((resolve, reject) => {
      heldConnection.once("connect", resolve);
      heldConnection.once("error", reject);
    });
    const closing = new Promise<void>((resolve) => closingServer.close(() => resolve()));
    const sessions = new TaskSessionManager({ startRelay: async () => ({ pairingUrl: "ws://127.0.0.1/extension#token", cdpUrl: "ws://127.0.0.1/cdp?token=token", close: async () => undefined }) });
    const replacementPromise = startBrokerServer({ socketPath, token: "a".repeat(32), sessions, isTrusted: () => false, controller: () => null });
    await delay(25);
    heldConnection.destroy();
    await closing;
    const replacement = await replacementPromise;
    try {
      const client = createBrokerClient({ socketPath, token: "a".repeat(32) });
      await expect(client.request("status")).resolves.toMatchObject({ trusted: false });
      await client.close();
    } finally {
      await replacement.close();
    }
  });
  it("reuses a named approved session across separate broker clients and closes it by stable key", async () => {
    const directory = await mkdtemp(join(tmpdir(), "atb-broker-")); directories.push(directory);
    const sessions = new TaskSessionManager({
      idFactory: () => "named-session",
      startRelay: async () => ({ pairingUrl: "ws://127.0.0.1/extension#token", cdpUrl: "ws://127.0.0.1/cdp?token=token", close: async () => undefined }),
    });
    const token = "a".repeat(32);
    const tabRequests: Array<{ sessionId: string | undefined; scope: "all" | "session" }> = [];
    const claims: Array<{ sessionId: string; tabId: number }> = [];
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
      listTabs: async (sessionId, scope) => {
        tabRequests.push({ sessionId, scope });
        return [];
      },
      claimTab: async (sessionId, tabId) => {
        claims.push({ sessionId, tabId });
        return { tabId, title: "Example", url: "https://example.com/", ownership: "currentSession", claimability: "alreadyShared" };
      },
    });
    try {
      const first = createBrokerClient({ socketPath: broker.socketPath, token });
      const opened = await first.request("openSession", { taskLabel: "Research", requestedCapabilities: ["cdp"], stableSessionKey: "research" }) as { session: { id: string } };
      await first.close();
      const url = createBrokerClient({ socketPath: broker.socketPath, token });
      await expect(url.request("sessionUrl", { stableSessionKey: "research" })).rejects.toThrow(/not found|not ready/);
      await url.close();
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

      const inventoryClient = createBrokerClient({ socketPath: broker.socketPath, token });
      await expect(inventoryClient.request("listTabs", { stableSessionKey: "research", scope: "all" })).resolves.toEqual([]);
      await expect(inventoryClient.request("listTabs", { stableSessionKey: "research", scope: "session" })).resolves.toEqual([]);
      await expect(inventoryClient.request("claimTab", { stableSessionKey: "research", tabId: 42 })).resolves.toMatchObject({
        tab: { tabId: 42, ownership: "currentSession", claimability: "alreadyShared" },
      });
      expect(tabRequests).toEqual([
        { sessionId: opened.session.id, scope: "all" },
        { sessionId: opened.session.id, scope: "session" },
      ]);
      expect(claims).toEqual([{ sessionId: opened.session.id, tabId: 42 }]);
      await inventoryClient.close();
      const urlClient = createBrokerClient({ socketPath: broker.socketPath, token });
      await expect(urlClient.request("sessionUrl", { stableSessionKey: "research" })).resolves.toMatchObject({ cdpUrl: "ws://127.0.0.1/cdp?token=token", session: { id: opened.session.id, state: "active" } });
      await expect(urlClient.request("sessionUrl", { stableSessionKey: "other-key" })).rejects.toThrow(/not found/);
      await urlClient.close();

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
  it("authenticates profile clients by challenge-response and scopes sessions to the profile principal", async () => {
    const directory = await mkdtemp(join(tmpdir(), "atb-broker-")); directories.push(directory);
    const profile = await createProfile("hermes-research", { directory });
    const enrolled = new Map([[profile.name, { principalId: profile.principalId, displayName: profile.name, publicKeySpki: profile.publicKeySpki }]]);
    const sessions = new TaskSessionManager({
      idFactory: () => "profile-session",
      startRelay: async () => ({ pairingUrl: "ws://127.0.0.1/extension#token", cdpUrl: "ws://127.0.0.1/cdp?token=token", close: async () => undefined }),
    });
    const token = "a".repeat(32);
    const broker = await startBrokerServer({
      socketPath: join(directory, "broker.sock"),
      token,
      sessions,
      isTrusted: () => true,
      controller: () => ({ principalId: "controller-token", displayName: "CLI" }),
      profile: (name) => enrolled.get(name) ?? null,
    });
    try {
      const client = createBrokerClient({ socketPath: broker.socketPath, profile: { name: profile.name, privateKeyPkcs8: profile.privateKeyPkcs8 } });
      const opened = await client.request("openSession", { taskLabel: "Research", requestedCapabilities: ["cdp"], stableSessionKey: "research" }) as { session: { id: string; controllerPrincipalId: string; displayControllerName: string } };
      expect(opened.session.controllerPrincipalId).toBe(profile.principalId);
      expect(opened.session.displayControllerName).toBe(profile.name);
      await sessions.approve(opened.session.id);
      sessions.relayReady(opened.session.id);
      await expect(client.request("sessionUrl", { stableSessionKey: "research" })).resolves.toMatchObject({ cdpUrl: "ws://127.0.0.1/cdp?token=token" });
      await client.close();

      // The token-authenticated principal must not see the profile's named session.
      const tokenClient = createBrokerClient({ socketPath: broker.socketPath, token });
      await expect(tokenClient.request("sessionUrl", { stableSessionKey: "research" })).rejects.toThrow(/not found/);
      await tokenClient.close();

      const unknown = createBrokerClient({ socketPath: broker.socketPath, profile: { name: "unknown", privateKeyPkcs8: profile.privateKeyPkcs8 } });
      await expect(unknown.request("status")).rejects.toThrow(/authentication failed/);
      await unknown.close().catch(() => undefined);

      const impostor = generateIdentity("controller");
      const wrongKey = createBrokerClient({ socketPath: broker.socketPath, profile: { name: profile.name, privateKeyPkcs8: impostor.privateKeyPkcs8 } });
      await expect(wrongKey.request("status")).rejects.toThrow(/authentication failed/);
      await wrongKey.close().catch(() => undefined);
    } finally {
      await broker.close();
    }
  });
});

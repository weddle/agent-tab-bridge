import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
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
});

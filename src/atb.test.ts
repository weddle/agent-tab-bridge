import type { ChildProcess } from "node:child_process";
import { EventEmitter } from "node:events";
import { describe, expect, it, vi } from "vitest";
import { main, parseCliArgs, runAgentCommand, type BrokerClient } from "./atb.js";
import { extensionOriginFromManifest } from "./companion/manifest.js";
describe("atb CLI session boundary", () => {
  it("parses validated run options and rejects removed or unknown public options", () => {
    expect(parseCliArgs(["run", "--label", "review tabs", "--ttl-ms", "5000", "--", "agent", "--task"])).toEqual({
      kind: "run",
      label: "review tabs",
      ttlMs: 5000,
      argv: ["agent", "--task"],
    });
    expect(() => parseCliArgs(["run", "--label", "--", "agent"])).toThrow(/--label requires a value/);
    expect(() => parseCliArgs(["run", "--ttl-ms", "1.5", "--", "agent"])).toThrow(/positive integer/);
    expect(() => parseCliArgs(["run", "--unknown", "value", "--", "agent"])).toThrow(/unknown run option/);
    expect(() => parseCliArgs(["install", "--state-directory", "/tmp/atb"])).toThrow(/unknown install option/);
    expect(() => parseCliArgs(["nativeHost"])).toThrow(/unknown command/);
  });

  it("resolves the packaged extension manifest independently of cwd", async () => {
    const originalCwd = process.cwd();
    try {
      const expected = await extensionOriginFromManifest();
      process.chdir("/");
      await expect(extensionOriginFromManifest()).resolves.toBe(expected);
    } finally {
      process.chdir(originalCwd);
    }
  });

  it("parses run commands without accepting a copied pairing capability", () => {
    expect(parseCliArgs(["run", "--", "agent", "--task"])).toEqual({
      kind: "run",
      argv: ["agent", "--task"],
    });
    expect(() => parseCliArgs(["run", "--pairing", "secret"])).toThrow();
  });

  it("injects only the child environment after active readiness and does not write protocol to stdout", async () => {
    const events = new Set<(event: { event: string; sessionId: string; cdpUrl: string }) => void>();
    const requests: Array<{ command: string; params: Record<string, unknown> }> = [];
    const broker: BrokerClient = {
      onEvent(listener) {
        events.add(listener as (event: { event: string; sessionId: string; cdpUrl: string }) => void);
        return () => events.delete(listener as (event: { event: string; sessionId: string; cdpUrl: string }) => void);
      },

      async request(command, params = {}) {
        requests.push({ command, params });
        if (command === "openSession") {
          queueMicrotask(() => {
            for (const listener of events) listener({ event: "active", sessionId: "session-1", cdpUrl: "ws://127.0.0.1:4567/cdp?token=ephemeral" });
          });
          return { sessionId: "session-1" };
        }
        return {};
      },
      async close() {},
    };

    const child = new EventEmitter() as unknown as ChildProcess;
    const spawn = vi.fn((_command: string, _args: readonly string[] = [], options?: { env?: NodeJS.ProcessEnv; stdio?: string }) => {
      expect(options?.stdio).toBe("inherit");
      expect(options?.env).toMatchObject({ KEEP_THIS: "yes", BROWSER_CDP_URL: "ws://127.0.0.1:4567/cdp?token=ephemeral" });
      expect(options?.env).not.toHaveProperty("ATB_BROKER_TOKEN");
      queueMicrotask(() => (child as unknown as EventEmitter).emit("exit", 0, null));
      return child;
    });
    const stdoutWrite = vi.spyOn(process.stdout, "write").mockImplementation(() => true);

    try {
      await expect(runAgentCommand(["agent", "--task"], { broker, spawn, processEnv: { KEEP_THIS: "yes" } })).resolves.toBe(0);
      expect(spawn).toHaveBeenCalledTimes(1);
      expect(requests.map(({ command }) => command)).toEqual(["openSession", "revokeSession"]);
      expect(requests[0]).toEqual({
        command: "openSession",
        params: { taskLabel: "agent", requestedCapabilities: ["cdp"] },
      });
      expect(stdoutWrite).not.toHaveBeenCalled();
    } finally {
      stdoutWrite.mockRestore();
    }
  });
  it("forwards parsed run options through main", async () => {
    const requests: Array<{ command: string; params: Record<string, unknown> }> = [];
    const broker: BrokerClient = {
      async request(command, params = {}) {
        requests.push({ command, params });
        if (command === "openSession") return { sessionId: "main-session", cdpUrl: "ws://127.0.0.1:4567/cdp?token=ephemeral" };
        return {};
      },
      async close() {},
    };
    const child = new EventEmitter() as unknown as ChildProcess;
    const spawn = vi.fn(() => {
      queueMicrotask(() => (child as unknown as EventEmitter).emit("exit", 0, null));
      return child;
    });
    await expect(main(["run", "--label", "from-main", "--ttl-ms", "2000", "--", "agent"], {
      broker,
      spawn,
      processEnv: {},
    })).resolves.toBe(0);
    expect(requests[0]).toEqual({
      command: "openSession",
      params: { taskLabel: "from-main", requestedCapabilities: ["cdp"], ttlMs: 2000 },
    });
  });
});

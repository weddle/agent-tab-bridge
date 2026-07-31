import type { ChildProcess } from "node:child_process";
import { EventEmitter } from "node:events";
import { describe, expect, it, vi } from "vitest";
import { closeAgentSession, main, parseCliArgs, requestAgentAccess, runAgentCommand, type BrokerClient } from "./atb.js";
import { extensionOriginFromManifest } from "./companion/manifest.js";
describe("atb CLI session boundary", () => {
  it("parses validated run options and rejects removed or unknown public options", () => {
    expect(parseCliArgs(["run", "--session", "review-2026", "--label", "review tabs", "--ttl-ms", "5000", "--", "agent", "--task"])).toEqual({
      kind: "run",
      stableSessionKey: "review-2026",
      label: "review tabs",
      ttlMs: 5000,
      argv: ["agent", "--task"],
      access: { level: "selectedTabs", tabIds: [], domains: [] },
    });
    expect(parseCliArgs(["close", "--session", "review-2026"])).toEqual({ kind: "close", stableSessionKey: "review-2026" });
    expect(parseCliArgs(["request-access", "--session", "review-2026", "--domain", "*.Example.com"])).toEqual({
      kind: "requestAccess",
      stableSessionKey: "review-2026",
      delta: { kind: "domains", tabIds: [], domains: ["example.com"] },
    });
    expect(() => parseCliArgs(["request-access", "--session", "review-2026"])).toThrow(/exactly one/);
    expect(() => parseCliArgs(["request-access", "--session", "review-2026", "--tab", "1", "--full-access"])).toThrow(/exactly one/);
    expect(parseCliArgs(["run", "--domain", "*.Example.com", "--domain", "docs.example.com", "--", "agent"])).toMatchObject({
      kind: "run",
      access: { level: "domains", tabIds: [], domains: ["docs.example.com", "example.com"] },
    });
    expect(parseCliArgs(["run", "--full-access", "--", "agent"])).toMatchObject({
      kind: "run",
      access: { level: "full", tabIds: [], domains: [] },
    });
    expect(() => parseCliArgs(["run", "--tab", "7", "--domain", "example.com", "--", "agent"])).toThrow(/mutually exclusive/);
    expect(() => parseCliArgs(["run", "--label", "--", "agent"])).toThrow(/--label requires a value/);
    expect(() => parseCliArgs(["run", "--session", "not/a-key", "--", "agent"])).toThrow(/session key/);
    expect(() => parseCliArgs(["close", "--session", "not/a-key"])).toThrow(/session key/);
    expect(() => parseCliArgs(["run", "--session", "research", "--", "agent"])).toThrow(/requires a non-empty --label/);
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
      access: { level: "selectedTabs", tabIds: [], domains: [] },
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
        params: { taskLabel: "agent", requestedCapabilities: ["cdp"], access: { level: "selectedTabs", tabIds: [], domains: [] } },
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
      params: { taskLabel: "from-main", requestedCapabilities: ["cdp"], access: { level: "selectedTabs", tabIds: [], domains: [] }, ttlMs: 2000 },
    });
  });
  it("leaves named sessions open after a child exits and closes them only explicitly", async () => {
    const requests: Array<{ command: string; params: Record<string, unknown> }> = [];
    const broker: BrokerClient = {
      async request(command, params = {}) {
        requests.push({ command, params });
        if (command === "openSession") return { session: { id: "named-session" }, cdpUrl: "ws://127.0.0.1:4567/cdp?token=ephemeral" };
        return {};
      },
      async close() {},
    };
    const child = new EventEmitter() as unknown as ChildProcess;
    const spawn = vi.fn(() => {
      queueMicrotask(() => (child as unknown as EventEmitter).emit("exit", 0, null));
      return child;
    });

    await expect(runAgentCommand(["agent"], { broker, spawn, processEnv: {} }, { stableSessionKey: "research", label: "Research" })).resolves.toBe(0);
    await expect(closeAgentSession("research", { broker })).resolves.toBe(0);
    expect(requests).toEqual([
      { command: "openSession", params: { taskLabel: "Research", requestedCapabilities: ["cdp"], access: { level: "selectedTabs", tabIds: [], domains: [] }, stableSessionKey: "research" } },
      { command: "closeSession", params: { stableSessionKey: "research" } },
    ]);
  });
  it("waits for explicit approval of an incremental access request", async () => {
    const listeners = new Set<(event: Record<string, unknown>) => void>();
    const broker: BrokerClient = {
      onEvent(listener) {
        listeners.add(listener);
        return () => listeners.delete(listener);
      },
      async request(command, params = {}) {
        expect(command).toBe("requestAccess");
        expect(params).toEqual({
          stableSessionKey: "research",
          accessDelta: { kind: "domains", tabIds: [], domains: ["example.com"] },
        });
        queueMicrotask(() => {
          for (const listener of listeners) {
            listener({ event: "accessUpdated", sessionId: "session-1", accessRequestId: "access-1" });
          }
        });
        return { accessRequest: { id: "access-1", sessionId: "session-1" } };
      },
      async close() {},
    };
    await expect(requestAgentAccess(
      "research",
      { kind: "domains", tabIds: [], domains: ["example.com"] },
      { broker },
    )).resolves.toBe(0);
  });
});

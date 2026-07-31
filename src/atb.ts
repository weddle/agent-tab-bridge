#!/usr/bin/env node

import { spawn as nodeSpawn, type ChildProcess } from "node:child_process";
import { constants as osConstants } from "node:os";
import { constants as fsConstants } from "node:fs";
import { access } from "node:fs/promises";
import { createCompanionBrokerClient } from "./companion/broker-client.js";
import { runNativeMessagingHost } from "./companion/native-host.js";
import path from "node:path";
import { extensionOriginFromManifest, installNativeManifests, nativeManifestStatus, uninstallNativeManifests, DEFAULT_NATIVE_HOST_NAME } from "./companion/manifest.js";
import { ensureApplicationSupportDirectory, CompanionStateStore } from "./companion/state.js";
import { createBrokerSecret, IdentityStore } from "./companion/identity.js";

export type CliCommand =
  | { kind: "install"; extensionManifest?: string; executable?: string; home?: string }
  | { kind: "uninstall"; extensionManifest?: string; executable?: string; home?: string }
  | { kind: "status"; extensionManifest?: string; executable?: string; home?: string }
  | { kind: "run"; argv: string[]; label?: string; ttlMs?: number }
  | { kind: "nativeHost" };

function requiredOptionValue(option: string, value: string | undefined): string {
  if (!value || value.startsWith("--")) throw new Error(`${option} requires a value`);
  return value;
}

export function parseCliArgs(argv: readonly string[]): CliCommand {
  if (argv.length === 0) return { kind: "nativeHost" };
  const [first, ...rest] = argv;
  if (first === "run") {
    const separator = rest.indexOf("--");
    if (separator < 0 || separator === rest.length - 1) throw new Error("usage: atb run [--label <text>] [--ttl-ms <integer>] -- <command> [args...]");
    let label: string | undefined;
    let ttlMs: number | undefined;
    for (let index = 0; index < separator; index += 1) {
      const value = rest[index];
      if (value === "--label") {
        label = requiredOptionValue(value, rest[++index]);
      } else if (value === "--ttl-ms") {
        const raw = requiredOptionValue(value, rest[++index]);
        if (!/^\d+$/.test(raw)) throw new Error("--ttl-ms requires a positive integer");
        const parsed = Number(raw);
        if (!Number.isSafeInteger(parsed) || parsed < 1) throw new Error("--ttl-ms requires a positive integer");
        ttlMs = parsed;
      } else {
        throw new Error(`unknown run option: ${value}`);
      }
    }
    return { kind: "run", argv: rest.slice(separator + 1), ...(label === undefined ? {} : { label }), ...(ttlMs === undefined ? {} : { ttlMs }) };
  }
  if (first === "native-host") return { kind: "nativeHost" };
  if (first === "install" || first === "uninstall" || first === "status") {
    let extensionManifest: string | undefined;
    let executable: string | undefined;
    let home: string | undefined;
    for (let index = 0; index < rest.length; index += 1) {
      const value = rest[index];
      if (value === "--extension-manifest" || value === "--executable" || value === "--home") {
        const next = requiredOptionValue(value, rest[++index]);
        if (value === "--extension-manifest") extensionManifest = next;
        else if (value === "--executable") executable = next;
        else home = next;
      } else throw new Error(`unknown ${first} option: ${value}`);
    }
    return { kind: first, extensionManifest, executable, home };
  }
  // Native Messaging launches with no user subcommand. Never treat a supplied
  // extension origin as a user command if a browser passes one through argv.
  if (first.startsWith("chrome-extension://")) return { kind: "nativeHost" };
  throw new Error(`unknown command: ${first}`);
}

export type BrokerEvent = {
  event?: string;
  type?: string;
  sessionId?: string;
  id?: string;
  cdpUrl?: string;
  [key: string]: unknown;
};
export type BrokerClient = {
  request(command: string, params?: Record<string, unknown>): Promise<unknown>;
  onEvent?(listener: (event: BrokerEvent) => void): (() => void) | void;
  close?(): Promise<void> | void;
};
export type ChildLike = Pick<ChildProcess, "once" | "on" | "kill">;
export type RunDeps = { broker: BrokerClient; spawn?: typeof nodeSpawn; processEnv?: NodeJS.ProcessEnv; signalSource?: NodeJS.Process };

const MAX_LABEL_LENGTH = 256;
function boundedLabel(argv: readonly string[], explicit?: string): string {
  return (explicit?.trim() || path.basename(argv[0] ?? "agent")).slice(0, MAX_LABEL_LENGTH);
}
function eventName(event: BrokerEvent): string { return String(event.event ?? event.type ?? "").toLowerCase(); }
function eventSessionId(event: BrokerEvent): string | undefined {
  const id = event.sessionId ?? event.id;
  return typeof id === "string" ? id : undefined;
}
function eventCdpUrl(event: BrokerEvent): string | undefined { return typeof event.cdpUrl === "string" && event.cdpUrl ? event.cdpUrl : undefined; }
async function revokeQuietly(broker: BrokerClient, sessionId: string): Promise<void> {
  try { await broker.request("revokeSession", { sessionId }); } catch { /* preserve child status */ }
}
function childExit(child: ChildLike): Promise<{ code: number | null; signal: NodeJS.Signals | null }> {
  return new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", (code: number | null, signal: NodeJS.Signals | null) => resolve({ code, signal }));
  });
}
function signalNumber(signal: NodeJS.Signals): number {
  return osConstants.signals[signal] ?? 1;
}

/** Run one approved session and revoke it on every child, broker, or signal path. */
export async function runAgentCommand(argv: readonly string[], deps: RunDeps, options: { label?: string; ttlMs?: number } = {}): Promise<number> {
  if (!argv.length) throw new Error("run command must not be empty");
  const ttlMs = options.ttlMs === undefined
    ? undefined
    : Math.max(1_000, Math.min(options.ttlMs, 24 * 60 * 60 * 1000));
  let sessionId: string | undefined;
  let removeEvent: (() => void) | undefined;
  const activeBeforeSessionId = new Map<string, string>();
  try {
    const active = new Promise<string>((resolve, reject) => {
      const onEvent = (event: BrokerEvent) => {
        const name = eventName(event);
        const id = eventSessionId(event);
        if (sessionId && id && id !== sessionId) return;
        if (!sessionId && id) {
          const earlyUrl = eventCdpUrl(event);
          if (earlyUrl && name === "active") activeBeforeSessionId.set(id, earlyUrl);
          return;
        }
        if (name === "active") {
          const cdpUrl = eventCdpUrl(event);
          if (cdpUrl) resolve(cdpUrl);
        } else if (name === "revoked" || name === "hostclosing") reject(new Error("browser session was revoked"));
      };
      removeEvent = deps.broker.onEvent?.(onEvent) ?? undefined;
    });
    const result = await deps.broker.request("openSession", {
      taskLabel: boundedLabel(argv, options.label),
      requestedCapabilities: ["cdp"],
      ...(ttlMs === undefined ? {} : { ttlMs }),
    });
    if (result && typeof result === "object") {
      const record = result as Record<string, unknown>;
      const session = record.session && typeof record.session === "object" ? record.session as Record<string, unknown> : record;
      sessionId = typeof session.id === "string" ? session.id : typeof session.sessionId === "string" ? session.sessionId : undefined;
      const earlyCdpUrl = sessionId ? activeBeforeSessionId.get(sessionId) : undefined;
      const immediate = typeof record.cdpUrl === "string" ? record.cdpUrl : earlyCdpUrl;
      if (immediate) {
        removeEvent?.(); removeEvent = undefined;
        return await runChildWithUrl(argv, immediate, deps, sessionId);
      }
    }
    if (!sessionId) throw new Error("broker did not return a session id");
    const cdpUrl = await active;
    removeEvent?.(); removeEvent = undefined;
    return await runChildWithUrl(argv, cdpUrl, deps, sessionId);
  } finally {
    removeEvent?.();
    if (sessionId) await revokeQuietly(deps.broker, sessionId);
    await deps.broker.close?.();
  }
}

async function runChildWithUrl(argv: readonly string[], cdpUrl: string, deps: RunDeps, sessionId?: string): Promise<number> {
  if (!/^ws:\/\/(127\.0\.0\.1|localhost):\d+\//.test(cdpUrl)) throw new Error("broker returned an invalid CDP URL");
  const child = (deps.spawn ?? nodeSpawn)(argv[0], argv.slice(1), { env: { ...(deps.processEnv ?? process.env), BROWSER_CDP_URL: cdpUrl }, stdio: "inherit" });
  const source = deps.signalSource ?? process;
  const signals: NodeJS.Signals[] = ["SIGINT", "SIGTERM", "SIGHUP"];
  const forward = (signal: NodeJS.Signals) => { try { child.kill(signal); } catch { /* child already exited */ } };
  const signalHandlers = signals.map((signal) => [signal, () => forward(signal)] as const);
  for (const [signal, handler] of signalHandlers) source.on(signal, handler);
  const removeBrokerEvent = deps.broker.onEvent?.((event) => {
    const id = eventSessionId(event);
    if (id && sessionId && id !== sessionId) return;
    if (eventName(event) === "revoked" || eventName(event) === "hostclosing") forward("SIGTERM");
  }) ?? undefined;
  try {
    const result = await childExit(child);
    return result.code ?? (result.signal ? 128 + signalNumber(result.signal) : 1);
  } finally {
    removeBrokerEvent?.();
    for (const [signal, handler] of signalHandlers) source.off(signal, handler);
  }
}

export type AtbMainDeps = Partial<RunDeps> & { nativeHost?: () => Promise<void>; stdout?: NodeJS.WriteStream; stateDirectory?: string };
export async function main(argv = process.argv.slice(2), deps: AtbMainDeps = {}): Promise<number> {
  const command = parseCliArgs(argv);
  if (command.kind === "nativeHost") {
    await (deps.nativeHost ?? runNativeMessagingHost)();
    return 0;
  }
  if (command.kind === "run") {
    const broker = deps.broker ?? await createCompanionBrokerClient({ directory: deps.stateDirectory });
    return runAgentCommand(command.argv, { ...deps, broker } as RunDeps, { label: command.label, ttlMs: command.ttlMs });
  }
  const extensionOrigin = await extensionOriginFromManifest(command.extensionManifest);
  const executablePath = path.resolve(command.executable ?? process.argv[1] ?? process.execPath);
  const params = { executablePath, runtimePath: process.execPath, extensionOrigin, hostName: DEFAULT_NATIVE_HOST_NAME, home: command.home };
  const stdout = deps.stdout ?? process.stdout;
  if (command.kind === "install") {
    await access(executablePath, fsConstants.X_OK);
    const supportOptions = deps.stateDirectory ? { directory: deps.stateDirectory } : {};
    await new IdentityStore("companion", supportOptions).loadOrCreate();
    const stateStore = new CompanionStateStore(supportOptions);
    const state = await stateStore.load();
    if (!state.brokerSecret) {
      await stateStore.save({ ...state, brokerSecret: createBrokerSecret() });
    }
    const paths = await installNativeManifests(params);
    Object.values(paths).forEach((value) => stdout.write(`${value}\n`));
    return 0;
  }
  if (command.kind === "uninstall") {
    const result = await uninstallNativeManifests(params);
    result.removed.forEach((value) => stdout.write(`${value}\n`));
    return 0;
  }
  const status = await nativeManifestStatus(params);
  for (const browser of ["brave", "chrome"] as const) {
    const item = status[browser];
    stdout.write(`${browser}\t${item.installed && item.matches ? "installed" : "not-installed"}\t${item.path}\n`);
  }
  return 0;
}

if (import.meta.url === `file://${process.argv[1]}`) main().then((code) => { process.exitCode = code; }).catch((error: unknown) => { process.stderr.write(`${error instanceof Error ? error.message : "Agent Tab Bridge failed"}\n`); process.exitCode = 1; });

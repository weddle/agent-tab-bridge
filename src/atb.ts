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
import { MAX_TASK_LABEL_LENGTH } from "./companion/native-protocol.js";
import { assertStableSessionKey } from "./companion/stable-session-key.js";
import { normalizeDomain, normalizeSessionAccess, normalizeSessionAccessDelta, type SessionAccess, type SessionAccessDelta } from "./companion/session-access.js";

export type CliCommand =
  | { kind: "install"; extensionManifest?: string; executable?: string; home?: string }
  | { kind: "uninstall"; extensionManifest?: string; executable?: string; home?: string }
  | { kind: "status"; extensionManifest?: string; executable?: string; home?: string }
  | { kind: "run"; argv: string[]; label?: string; ttlMs?: number; stableSessionKey?: string; access: SessionAccess }
  | { kind: "open"; label: string; ttlMs?: number; stableSessionKey: string; access: SessionAccess }
  | { kind: "url"; stableSessionKey: string }
  | { kind: "tabs"; stableSessionKey?: string; scope: "all" | "session" }
  | { kind: "claimTab"; stableSessionKey: string; tabId: number }
  | { kind: "requestAccess"; stableSessionKey: string; delta: SessionAccessDelta }
  | { kind: "close"; stableSessionKey: string }
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
    if (separator < 0 || separator === rest.length - 1) throw new Error("usage: atb run [--session <stable-key>] [--label <text>] [--ttl-ms <integer>] [--tab <id> ... | --domain <host> ... | --full-access] -- <command> [args...]");
    let label: string | undefined;
    let ttlMs: number | undefined;
    let stableSessionKey: string | undefined;
    const tabIds = [];
    const domains = [];
    let fullAccess = false;
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
      } else if (value === "--session") {
        if (stableSessionKey !== undefined) throw new Error("--session may be specified only once");
        stableSessionKey = assertStableSessionKey(requiredOptionValue(value, rest[++index]));
      } else if (value === "--tab") {
        const raw = requiredOptionValue(value, rest[++index]);
        if (!/^\d+$/.test(raw) || !Number.isSafeInteger(Number(raw))) throw new Error("--tab requires a non-negative integer tab ID");
        tabIds.push(Number(raw));
      } else if (value === "--domain") {
        domains.push(normalizeDomain(requiredOptionValue(value, rest[++index])));
      } else if (value === "--full-access") {
        if (fullAccess) throw new Error("--full-access may be specified only once");
        fullAccess = true;
      } else {
        throw new Error(`unknown run option: ${value}`);
      }
    }
    if (stableSessionKey !== undefined && !label?.trim()) throw new Error("--session requires a non-empty --label");
    const accessModes = Number(tabIds.length > 0) + Number(domains.length > 0) + Number(fullAccess);
    if (accessModes > 1) throw new Error("--tab, --domain, and --full-access are mutually exclusive");
    const access = normalizeSessionAccess(fullAccess ? { level: "full", tabIds: [], domains: [] } : domains.length ? { level: "domains", tabIds: [], domains } : { level: "selectedTabs", tabIds, domains: [] });
    return { kind: "run", argv: rest.slice(separator + 1), access, ...(label === undefined ? {} : { label }), ...(ttlMs === undefined ? {} : { ttlMs }), ...(stableSessionKey === undefined ? {} : { stableSessionKey }) };
  }
  if (first === "request-access") {
    let stableSessionKey;
    const tabIds = [];
    const domains = [];
    let fullAccess = false;
    for (let index = 0; index < rest.length; index += 1) {
      const value = rest[index];
      if (value === "--session") {
        if (stableSessionKey !== undefined) throw new Error("--session may be specified only once");
        stableSessionKey = assertStableSessionKey(requiredOptionValue(value, rest[++index]));
      } else if (value === "--tab") {
        const raw = requiredOptionValue(value, rest[++index]);
        if (!/^\d+$/.test(raw) || !Number.isSafeInteger(Number(raw))) throw new Error("--tab requires a non-negative integer tab ID");
        tabIds.push(Number(raw));
      } else if (value === "--domain") {
        domains.push(normalizeDomain(requiredOptionValue(value, rest[++index])));
      } else if (value === "--full-access") {
        if (fullAccess) throw new Error("--full-access may be specified only once");
        fullAccess = true;
      } else {
        throw new Error(`unknown request-access option: ${value}`);
      }
    }
    if (stableSessionKey === undefined) throw new Error("request-access requires --session <stable-key>");
    const modes = Number(tabIds.length > 0) + Number(domains.length > 0) + Number(fullAccess);
    if (modes !== 1) throw new Error("request-access requires exactly one of --tab, --domain, or --full-access");
    const delta = normalizeSessionAccessDelta(fullAccess ? { kind: "full", tabIds: [], domains: [] } : domains.length ? { kind: "domains", tabIds: [], domains } : { kind: "tabs", tabIds, domains: [] });
    return { kind: "requestAccess", stableSessionKey, delta };
  }
  if (first === "open") {
    let label: string | undefined;
    let ttlMs: number | undefined;
    let stableSessionKey: string | undefined;
    const tabIds = [];
    const domains = [];
    let fullAccess = false;
    for (let index = 0; index < rest.length; index += 1) {
      const value = rest[index];
      if (value === "--label") {
        label = requiredOptionValue(value, rest[++index]);
      } else if (value === "--ttl-ms") {
        const raw = requiredOptionValue(value, rest[++index]);
        if (!/^\d+$/.test(raw)) throw new Error("--ttl-ms requires a positive integer");
        const parsed = Number(raw);
        if (!Number.isSafeInteger(parsed) || parsed < 1) throw new Error("--ttl-ms requires a positive integer");
        ttlMs = parsed;
      } else if (value === "--session") {
        if (stableSessionKey !== undefined) throw new Error("--session may be specified only once");
        stableSessionKey = assertStableSessionKey(requiredOptionValue(value, rest[++index]));
      } else if (value === "--tab") {
        const raw = requiredOptionValue(value, rest[++index]);
        if (!/^\d+$/.test(raw) || !Number.isSafeInteger(Number(raw))) throw new Error("--tab requires a non-negative integer tab ID");
        tabIds.push(Number(raw));
      } else if (value === "--domain") {
        domains.push(normalizeDomain(requiredOptionValue(value, rest[++index])));
      } else if (value === "--full-access") {
        if (fullAccess) throw new Error("--full-access may be specified only once");
        fullAccess = true;
      } else {
        throw new Error(`unknown open option: ${value}`);
      }
    }
    if (stableSessionKey === undefined) throw new Error("open requires --session <stable-key>");
    if (!label?.trim()) throw new Error("open requires a non-empty --label");
    const accessModes = Number(tabIds.length > 0) + Number(domains.length > 0) + Number(fullAccess);
    if (accessModes > 1) throw new Error("--tab, --domain, and --full-access are mutually exclusive");
    const access = normalizeSessionAccess(fullAccess ? { level: "full", tabIds: [], domains: [] } : domains.length ? { level: "domains", tabIds: [], domains } : { level: "selectedTabs", tabIds, domains: [] });
    return { kind: "open", label, stableSessionKey, access, ...(ttlMs === undefined ? {} : { ttlMs }) };
  }
  if (first === "url") {
    if (rest.length !== 2 || rest[0] !== "--session") throw new Error("usage: atb url --session <stable-key>");
    return { kind: "url", stableSessionKey: assertStableSessionKey(requiredOptionValue("--session", rest[1])) };
  }
  if (first === "tabs") {
    let stableSessionKey;
    let scope = "all" as "all" | "session";
    for (let index = 0; index < rest.length; index += 1) {
      const value = rest[index];
      if (value === "--session") {
        if (stableSessionKey !== undefined) throw new Error("--session may be specified only once");
        stableSessionKey = assertStableSessionKey(requiredOptionValue(value, rest[++index]));
      } else if (value === "--scope") {
        const requested = requiredOptionValue(value, rest[++index]);
        if (requested !== "all" && requested !== "session") throw new Error("--scope must be all or session");
        scope = requested;
      } else throw new Error(`unknown tabs option: ${value}`);
    }
    if (scope === "session" && stableSessionKey === undefined) throw new Error("--scope session requires --session <stable-key>");
    return { kind: "tabs", scope, ...(stableSessionKey === undefined ? {} : { stableSessionKey }) };
  }
  if (first === "claim-tab") {
    if (rest.length !== 4 || rest[0] !== "--session" || rest[2] !== "--tab") throw new Error("usage: atb claim-tab --session <stable-key> --tab <id>");
    const raw = requiredOptionValue("--tab", rest[3]);
    if (!/^\d+$/.test(raw) || !Number.isSafeInteger(Number(raw))) throw new Error("--tab requires a non-negative integer tab ID");
    return { kind: "claimTab", stableSessionKey: assertStableSessionKey(requiredOptionValue("--session", rest[1])), tabId: Number(raw) };
  }
  if (first === "close") {
    if (rest.length !== 2 || rest[0] !== "--session") throw new Error("usage: atb close --session <stable-key>");
    return { kind: "close", stableSessionKey: assertStableSessionKey(requiredOptionValue("--session", rest[1])) };
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

const MAX_LABEL_LENGTH = MAX_TASK_LABEL_LENGTH;
function boundedLabel(argv: readonly string[], explicit?: string): string {
  const label = explicit?.trim() || path.basename(argv[0] ?? "agent");
  if (label.length > MAX_LABEL_LENGTH) throw new Error(`label must be at most ${MAX_LABEL_LENGTH} characters`);
  return label;
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

/** Run one approved session; unnamed sessions are revoked when their child exits. */
export async function runAgentCommand(argv: readonly string[], deps: RunDeps, options: { label?: string; ttlMs?: number; stableSessionKey?: string; access?: SessionAccess } = {}): Promise<number> {
  if (options.stableSessionKey !== undefined) {
    assertStableSessionKey(options.stableSessionKey);
    if (!options.label?.trim()) throw new Error("--session requires a non-empty --label");
  }
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
      access: normalizeSessionAccess(options.access),
      ...(ttlMs === undefined ? {} : { ttlMs }),
      ...(options.stableSessionKey === undefined ? {} : { stableSessionKey: options.stableSessionKey }),
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
    if (sessionId && options.stableSessionKey === undefined) await revokeQuietly(deps.broker, sessionId);
    await deps.broker.close?.();
  }
}
export async function requestAgentAccess(stableSessionKey: string, delta: SessionAccessDelta, deps: Pick<RunDeps, "broker">): Promise<number> {
  assertStableSessionKey(stableSessionKey);
  let accessRequestId: string | undefined;
  let sessionId: string | undefined;
  let removeEvent: (() => void) | undefined;
  const early = new Map<string, { name: string; reason: unknown }>();
  const outcome = Promise.withResolvers<number>();
  try {
    const onEvent = (event: BrokerEvent) => {
      const name = eventName(event);
      const requestId = typeof event.accessRequestId === "string" ? event.accessRequestId : undefined;
      const eventSession = eventSessionId(event);
      if (name === "hostclosing" || (name === "revoked" && sessionId !== undefined && eventSession === sessionId)) {
        outcome.reject(new Error(name === "hostclosing" ? "companion host closed while access approval was pending" : "session closed while access approval was pending"));
        return;
      }
      if (sessionId && eventSession && eventSession !== sessionId) return;
      if (!accessRequestId && requestId) {
        early.set(requestId, { name, reason: event.reason });
        return;
      }
      if (requestId !== accessRequestId) return;
      if (name === "accessupdated") outcome.resolve(0);
      else if (name === "accessdeclined") outcome.reject(new Error(typeof event.reason === "string" ? event.reason : "access upgrade was declined"));
    };
    removeEvent = deps.broker.onEvent?.(onEvent) ?? undefined;
    const result = await deps.broker.request("requestAccess", { stableSessionKey, accessDelta: normalizeSessionAccessDelta(delta) });
    const record = result && typeof result === "object" ? result as Record<string, unknown> : null;
    const request = record?.accessRequest && typeof record.accessRequest === "object" ? record.accessRequest as Record<string, unknown> : null;
    accessRequestId = typeof request?.id === "string" ? request.id : undefined;
    sessionId = typeof request?.sessionId === "string" ? request.sessionId : undefined;
    if (!accessRequestId || !sessionId) throw new Error("broker did not return an access request");
    const immediate = early.get(accessRequestId);
    if (immediate?.name === "accessupdated") return 0;
    if (immediate?.name === "accessdeclined") throw new Error(typeof immediate.reason === "string" ? immediate.reason : "access upgrade was declined");
    return await outcome.promise;
  } finally {
    removeEvent?.();
    await deps.broker.close?.();
  }
}

export async function closeAgentSession(stableSessionKey: string, deps: Pick<RunDeps, "broker">): Promise<number> {
  assertStableSessionKey(stableSessionKey);
  try {
    await deps.broker.request("closeSession", { stableSessionKey });
    return 0;
  } finally {
    await deps.broker.close?.();
  }
}

const LOOPBACK_RELAY_URL = /^ws:\/\/(127\.0\.0\.1|localhost):\d+\//;

/** Open or reuse a named approved session without launching a child process. */
export async function openAgentSession(options: { label: string; ttlMs?: number; stableSessionKey: string; access?: SessionAccess }, deps: Pick<RunDeps, "broker"> & { stdout?: NodeJS.WriteStream }): Promise<number> {
  assertStableSessionKey(options.stableSessionKey);
  if (!options.label.trim()) throw new Error("open requires a non-empty --label");
  const ttlMs = options.ttlMs === undefined
    ? undefined
    : Math.max(1_000, Math.min(options.ttlMs, 24 * 60 * 60 * 1000));
  let sessionId: string | undefined;
  let removeEvent: (() => void) | undefined;
  const activeBeforeSessionId = new Set<string>();
  try {
    const active = new Promise<void>((resolve, reject) => {
      const onEvent = (event: BrokerEvent) => {
        const name = eventName(event);
        const id = eventSessionId(event);
        if (sessionId && id && id !== sessionId) return;
        if (!sessionId && id) {
          if (name === "active") activeBeforeSessionId.add(id);
          return;
        }
        if (name === "active") resolve();
        else if (name === "revoked" || name === "hostclosing") reject(new Error("browser session was revoked"));
      };
      removeEvent = deps.broker.onEvent?.(onEvent) ?? undefined;
    });
    const result = await deps.broker.request("openSession", {
      taskLabel: options.label.trim().slice(0, MAX_LABEL_LENGTH),
      requestedCapabilities: ["cdp"],
      access: normalizeSessionAccess(options.access),
      stableSessionKey: options.stableSessionKey,
      ...(ttlMs === undefined ? {} : { ttlMs }),
    });
    let immediate = false;
    if (result && typeof result === "object") {
      const record = result as Record<string, unknown>;
      const session = record.session && typeof record.session === "object" ? record.session as Record<string, unknown> : record;
      sessionId = typeof session.id === "string" ? session.id : typeof session.sessionId === "string" ? session.sessionId : undefined;
      immediate = typeof record.cdpUrl === "string" || session.state === "active" || (sessionId !== undefined && activeBeforeSessionId.has(sessionId));
    }
    if (!sessionId) throw new Error("broker did not return a session id");
    if (!immediate) await active;
    removeEvent?.(); removeEvent = undefined;
    (deps.stdout ?? process.stdout).write(`session ${options.stableSessionKey} active\n`);
    return 0;
  } finally {
    removeEvent?.();
    await deps.broker.close?.();
  }
}

/** Print the live relay URL for a named approved session. The URL is ephemeral and never persisted by atb. */
export async function printAgentSessionUrl(stableSessionKey: string, deps: Pick<RunDeps, "broker"> & { stdout?: NodeJS.WriteStream }): Promise<number> {
  assertStableSessionKey(stableSessionKey);
  try {
    const result = await deps.broker.request("sessionUrl", { stableSessionKey });
    const record = result && typeof result === "object" ? result as Record<string, unknown> : null;
    const cdpUrl = typeof record?.cdpUrl === "string" ? record.cdpUrl : undefined;
    if (!cdpUrl || !LOOPBACK_RELAY_URL.test(cdpUrl)) throw new Error("broker did not return a loopback session URL");
    (deps.stdout ?? process.stdout).write(`${cdpUrl}\n`);
    return 0;
  } finally {
    await deps.broker.close?.();
  }
}

async function runChildWithUrl(argv: readonly string[], cdpUrl: string, deps: RunDeps, sessionId?: string): Promise<number> {
  if (!LOOPBACK_RELAY_URL.test(cdpUrl)) throw new Error("broker returned an invalid CDP URL");
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
    return runAgentCommand(command.argv, { ...deps, broker } as RunDeps, { label: command.label, ttlMs: command.ttlMs, stableSessionKey: command.stableSessionKey, access: command.access });
  }
  if (command.kind === "open") {
    const broker = deps.broker ?? await createCompanionBrokerClient({ directory: deps.stateDirectory });
    return openAgentSession({ label: command.label, stableSessionKey: command.stableSessionKey, access: command.access, ...(command.ttlMs === undefined ? {} : { ttlMs: command.ttlMs }) }, { broker, ...(deps.stdout === undefined ? {} : { stdout: deps.stdout }) });
  }
  if (command.kind === "url") {
    const broker = deps.broker ?? await createCompanionBrokerClient({ directory: deps.stateDirectory });
    return printAgentSessionUrl(command.stableSessionKey, { broker, ...(deps.stdout === undefined ? {} : { stdout: deps.stdout }) });
  }
  if (command.kind === "requestAccess") {
    const broker = deps.broker ?? await createCompanionBrokerClient({ directory: deps.stateDirectory });
    return requestAgentAccess(command.stableSessionKey, command.delta, { broker });
  }
  if (command.kind === "tabs") {
    const broker = deps.broker ?? await createCompanionBrokerClient({ directory: deps.stateDirectory });
    try {
      const tabs = await broker.request("listTabs", { scope: command.scope, ...(command.stableSessionKey === undefined ? {} : { stableSessionKey: command.stableSessionKey }) });
      (deps.stdout ?? process.stdout).write(`${JSON.stringify(tabs, null, 2)}\n`);
      return 0;
    } finally {
      await broker.close?.();
    }
  }
  if (command.kind === "claimTab") {
    const broker = deps.broker ?? await createCompanionBrokerClient({ directory: deps.stateDirectory });
    try {
      const result = await broker.request("claimTab", { stableSessionKey: command.stableSessionKey, tabId: command.tabId });
      (deps.stdout ?? process.stdout).write(`${JSON.stringify(result, null, 2)}\n`);
      return 0;
    } finally {
      await broker.close?.();
    }
  }
  if (command.kind === "close") {
    const broker = deps.broker ?? await createCompanionBrokerClient({ directory: deps.stateDirectory });
    return closeAgentSession(command.stableSessionKey, { broker });
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

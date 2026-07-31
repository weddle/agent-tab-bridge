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
import { createProfile, listProfiles, loadProfile, PROFILE_NAME_PATTERN } from "./companion/profiles.js";
import { normalizeDomain, normalizeSessionAccess, normalizeSessionAccessDelta, type SessionAccess, type SessionAccessDelta } from "./companion/session-access.js";

export type CliCommand =
  | { kind: "install"; extensionManifest?: string; executable?: string; home?: string }
  | { kind: "uninstall"; extensionManifest?: string; executable?: string; home?: string }
  | { kind: "status"; extensionManifest?: string; executable?: string; home?: string }
  | { kind: "run"; argv: string[]; label?: string; ttlMs?: number; stableSessionKey?: string; access: SessionAccess; profile?: string }
  | { kind: "open"; label: string; ttlMs?: number; stableSessionKey: string; access: SessionAccess; profile?: string }
  | { kind: "url"; stableSessionKey: string; profile?: string }
  | { kind: "tabs"; stableSessionKey?: string; scope: "all" | "session"; profile?: string }
  | { kind: "claimTab"; stableSessionKey: string; tabId: number; profile?: string }
  | { kind: "requestAccess"; stableSessionKey: string; delta: SessionAccessDelta; profile?: string }
  | { kind: "close"; stableSessionKey: string; profile?: string }
  | { kind: "profileCreate"; name: string }
  | { kind: "profileEnroll"; name: string }
  | { kind: "profileList" }
  | { kind: "nativeHost" };

function requiredOptionValue(option: string, value: string | undefined): string {
  if (!value || value.startsWith("--")) throw new Error(`${option} requires a value`);
  return value;
}

function onlyOnce(current: string | undefined, option: string): void {
  if (current !== undefined) throw new Error(`${option} may be specified only once`);
}

function assertProfileOption(name: string): string {
  if (!PROFILE_NAME_PATTERN.test(name)) throw new Error("--profile must be 1-64 characters of letters, digits, dot, underscore, or hyphen");
  return name;
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
    let profile: string | undefined;
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
      } else if (value === "--profile") {
        onlyOnce(profile, value);
        profile = assertProfileOption(requiredOptionValue(value, rest[++index]));
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
    return { kind: "run", argv: rest.slice(separator + 1), access, ...(label === undefined ? {} : { label }), ...(ttlMs === undefined ? {} : { ttlMs }), ...(stableSessionKey === undefined ? {} : { stableSessionKey }), ...(profile === undefined ? {} : { profile }) };
  }
  if (first === "request-access") {
    let stableSessionKey;
    let profile: string | undefined;
    const tabIds = [];
    const domains = [];
    let fullAccess = false;
    for (let index = 0; index < rest.length; index += 1) {
      const value = rest[index];
      if (value === "--session") {
        if (stableSessionKey !== undefined) throw new Error("--session may be specified only once");
        stableSessionKey = assertStableSessionKey(requiredOptionValue(value, rest[++index]));
      } else if (value === "--profile") {
        onlyOnce(profile, value);
        profile = assertProfileOption(requiredOptionValue(value, rest[++index]));
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
    return { kind: "requestAccess", stableSessionKey, delta, ...(profile === undefined ? {} : { profile }) };
  }
  if (first === "open") {
    let label: string | undefined;
    let ttlMs: number | undefined;
    let stableSessionKey: string | undefined;
    let profile: string | undefined;
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
      } else if (value === "--profile") {
        onlyOnce(profile, value);
        profile = assertProfileOption(requiredOptionValue(value, rest[++index]));
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
    return { kind: "open", label, stableSessionKey, access, ...(ttlMs === undefined ? {} : { ttlMs }), ...(profile === undefined ? {} : { profile }) };
  }
  if (first === "url") {
    let stableSessionKey: string | undefined;
    let profile: string | undefined;
    for (let index = 0; index < rest.length; index += 1) {
      const value = rest[index];
      if (value === "--session") {
        onlyOnce(stableSessionKey, value);
        stableSessionKey = assertStableSessionKey(requiredOptionValue(value, rest[++index]));
      } else if (value === "--profile") {
        onlyOnce(profile, value);
        profile = assertProfileOption(requiredOptionValue(value, rest[++index]));
      } else throw new Error(`unknown url option: ${value}`);
    }
    if (stableSessionKey === undefined) throw new Error("usage: atb url --session <stable-key> [--profile <name>]");
    return { kind: "url", stableSessionKey, ...(profile === undefined ? {} : { profile }) };
  }
  if (first === "profile") {
    const [action, ...args] = rest;
    if (action === "create") {
      if (args.length !== 1) throw new Error("usage: atb profile create <name>");
      return { kind: "profileCreate", name: assertProfileOption(args[0]) };
    }
    if (action === "enroll") {
      if (args.length !== 1) throw new Error("usage: atb profile enroll <name>");
      return { kind: "profileEnroll", name: assertProfileOption(args[0]) };
    }
    if (action === "list") {
      if (args.length !== 0) throw new Error("usage: atb profile list");
      return { kind: "profileList" };
    }
    throw new Error("usage: atb profile <create|enroll|list>");
  }
  if (first === "tabs") {
    let stableSessionKey;
    let profile: string | undefined;
    let scope = "all" as "all" | "session";
    for (let index = 0; index < rest.length; index += 1) {
      const value = rest[index];
      if (value === "--session") {
        if (stableSessionKey !== undefined) throw new Error("--session may be specified only once");
        stableSessionKey = assertStableSessionKey(requiredOptionValue(value, rest[++index]));
      } else if (value === "--profile") {
        onlyOnce(profile, value);
        profile = assertProfileOption(requiredOptionValue(value, rest[++index]));
      } else if (value === "--scope") {
        const requested = requiredOptionValue(value, rest[++index]);
        if (requested !== "all" && requested !== "session") throw new Error("--scope must be all or session");
        scope = requested;
      } else throw new Error(`unknown tabs option: ${value}`);
    }
    if (scope === "session" && stableSessionKey === undefined) throw new Error("--scope session requires --session <stable-key>");
    return { kind: "tabs", scope, ...(stableSessionKey === undefined ? {} : { stableSessionKey }), ...(profile === undefined ? {} : { profile }) };
  }
  if (first === "claim-tab") {
    let stableSessionKey: string | undefined;
    let profile: string | undefined;
    let tabId: number | undefined;
    for (let index = 0; index < rest.length; index += 1) {
      const value = rest[index];
      if (value === "--session") {
        onlyOnce(stableSessionKey, value);
        stableSessionKey = assertStableSessionKey(requiredOptionValue(value, rest[++index]));
      } else if (value === "--tab") {
        const raw = requiredOptionValue(value, rest[++index]);
        if (!/^\d+$/.test(raw) || !Number.isSafeInteger(Number(raw))) throw new Error("--tab requires a non-negative integer tab ID");
        tabId = Number(raw);
      } else if (value === "--profile") {
        onlyOnce(profile, value);
        profile = assertProfileOption(requiredOptionValue(value, rest[++index]));
      } else throw new Error(`unknown claim-tab option: ${value}`);
    }
    if (stableSessionKey === undefined || tabId === undefined) throw new Error("usage: atb claim-tab --session <stable-key> --tab <id> [--profile <name>]");
    return { kind: "claimTab", stableSessionKey, tabId, ...(profile === undefined ? {} : { profile }) };
  }
  if (first === "close") {
    let stableSessionKey: string | undefined;
    let profile: string | undefined;
    for (let index = 0; index < rest.length; index += 1) {
      const value = rest[index];
      if (value === "--session") {
        onlyOnce(stableSessionKey, value);
        stableSessionKey = assertStableSessionKey(requiredOptionValue(value, rest[++index]));
      } else if (value === "--profile") {
        onlyOnce(profile, value);
        profile = assertProfileOption(requiredOptionValue(value, rest[++index]));
      } else throw new Error(`unknown close option: ${value}`);
    }
    if (stableSessionKey === undefined) throw new Error("usage: atb close --session <stable-key> [--profile <name>]");
    return { kind: "close", stableSessionKey, ...(profile === undefined ? {} : { profile }) };
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

/** Request enrollment for a local profile key; the user confirms the printed code in the popup. */
export async function enrollAgentProfile(name: string, deps: Pick<RunDeps, "broker"> & { stdout?: NodeJS.WriteStream; directory?: string }): Promise<number> {
  const record = await loadProfile(name, deps.directory === undefined ? {} : { directory: deps.directory });
  let removeEvent: (() => void) | undefined;
  const outcome = Promise.withResolvers<number>();
  let enrollmentId: string | undefined;
  const early = new Map<string, string>();
  try {
    const onEvent = (event: BrokerEvent) => {
      const kind = eventName(event);
      const id = typeof event.enrollmentId === "string" ? event.enrollmentId : undefined;
      if (kind === "hostclosing") { outcome.reject(new Error("companion host closed while enrollment was pending")); return; }
      if (kind !== "profileenrolled" && kind !== "enrolldeclined") return;
      if (!id) return;
      if (!enrollmentId) { early.set(id, kind); return; }
      if (id !== enrollmentId) return;
      if (kind === "profileenrolled") outcome.resolve(0);
      else outcome.reject(new Error(typeof event.reason === "string" ? event.reason : "enrollment was declined"));
    };
    removeEvent = deps.broker.onEvent?.(onEvent) ?? undefined;
    const result = await deps.broker.request("enrollProfile", { profileName: record.name, publicKeySpki: record.publicKeySpki });
    const record2 = result && typeof result === "object" ? result as Record<string, unknown> : null;
    const enrollment = record2?.enrollment && typeof record2.enrollment === "object" ? record2.enrollment as Record<string, unknown> : null;
    enrollmentId = typeof enrollment?.enrollmentId === "string" ? enrollment.enrollmentId : undefined;
    const code = typeof enrollment?.code === "string" ? enrollment.code : undefined;
    if (!enrollmentId || !code) throw new Error("broker did not return an enrollment code");
    const stdout = deps.stdout ?? process.stdout;
    stdout.write(`Pairing code: ${code}\n`);
    stdout.write(`Show this code to the user. To approve, open the Agent Tab Bridge popup in the paired browser and enter the code for profile "${record.name}" (${record.principalId}). The code expires in 2 minutes.\n`);
    const seen = early.get(enrollmentId);
    if (seen === "enrolldeclined") throw new Error("enrollment was declined");
    if (seen !== "profileenrolled") await outcome.promise;
    stdout.write(`profile ${record.name} enrolled\n`);
    return 0;
  } finally {
    removeEvent?.();
    await deps.broker.close?.();
  }
}

export type AtbMainDeps = Partial<RunDeps> & { nativeHost?: () => Promise<void>; stdout?: NodeJS.WriteStream; stateDirectory?: string };
export async function main(argv = process.argv.slice(2), deps: AtbMainDeps = {}): Promise<number> {
  const command = parseCliArgs(argv);
  const directoryOption = deps.stateDirectory === undefined ? {} : { directory: deps.stateDirectory };
  const brokerFor = async (profile?: string) => deps.broker ?? await createCompanionBrokerClient({ ...(deps.stateDirectory === undefined ? {} : { directory: deps.stateDirectory }), ...(profile === undefined ? {} : { profile }) });
  if (command.kind === "nativeHost") {
    await (deps.nativeHost ?? runNativeMessagingHost)();
    return 0;
  }
  if (command.kind === "profileCreate") {
    const record = await createProfile(command.name, directoryOption);
    (deps.stdout ?? process.stdout).write(`created profile ${record.name}\nfingerprint ${record.principalId}\n`);
    return 0;
  }
  if (command.kind === "profileEnroll") {
    const broker = await brokerFor(undefined);
    return enrollAgentProfile(command.name, { broker, ...(deps.stdout === undefined ? {} : { stdout: deps.stdout }), ...(deps.stateDirectory === undefined ? {} : { directory: deps.stateDirectory }) });
  }
  if (command.kind === "profileList") {
    const profiles = await listProfiles(directoryOption);
    const stdout = deps.stdout ?? process.stdout;
    for (const profile of profiles) stdout.write(`${profile.name}\t${profile.principalId}\n`);
    return 0;
  }
  if (command.kind === "run") {
    const broker = await brokerFor(command.profile);
    return runAgentCommand(command.argv, { ...deps, broker } as RunDeps, { label: command.label, ttlMs: command.ttlMs, stableSessionKey: command.stableSessionKey, access: command.access });
  }
  if (command.kind === "open") {
    const broker = await brokerFor(command.profile);
    return openAgentSession({ label: command.label, stableSessionKey: command.stableSessionKey, access: command.access, ...(command.ttlMs === undefined ? {} : { ttlMs: command.ttlMs }) }, { broker, ...(deps.stdout === undefined ? {} : { stdout: deps.stdout }) });
  }
  if (command.kind === "url") {
    const broker = await brokerFor(command.profile);
    return printAgentSessionUrl(command.stableSessionKey, { broker, ...(deps.stdout === undefined ? {} : { stdout: deps.stdout }) });
  }
  if (command.kind === "requestAccess") {
    const broker = await brokerFor(command.profile);
    return requestAgentAccess(command.stableSessionKey, command.delta, { broker });
  }
  if (command.kind === "tabs") {
    const broker = await brokerFor(command.profile);
    try {
      const tabs = await broker.request("listTabs", { scope: command.scope, ...(command.stableSessionKey === undefined ? {} : { stableSessionKey: command.stableSessionKey }) });
      (deps.stdout ?? process.stdout).write(`${JSON.stringify(tabs, null, 2)}\n`);
      return 0;
    } finally {
      await broker.close?.();
    }
  }
  if (command.kind === "claimTab") {
    const broker = await brokerFor(command.profile);
    try {
      const result = await broker.request("claimTab", { stableSessionKey: command.stableSessionKey, tabId: command.tabId });
      (deps.stdout ?? process.stdout).write(`${JSON.stringify(result, null, 2)}\n`);
      return 0;
    } finally {
      await broker.close?.();
    }
  }
  if (command.kind === "close") {
    const broker = await brokerFor(command.profile);
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

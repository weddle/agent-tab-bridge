import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { signTranscript, verifyTranscript } from "./identity.js";
import { AUTH_V2_MAX_CLOCK_SKEW_MS, canonicalAuthV2Transcript, createAuthV2EphemeralPublicKey, createAuthV2Nonce, isAuthV2RequestedAuthority, isAuthV2Transcript, type AuthV2RequestedAuthority, type AuthV2Transcript } from "./auth-v2.js";
import { PROFILE_NAME_PATTERN } from "./profiles.js";
import { chmod, lstat, rm } from "node:fs/promises";
import { createConnection, createServer, type Server, type Socket } from "node:net";
import { join } from "node:path";
import { applicationSupportDirectory, type ApplicationSupportOptions } from "./state.js";
import { TaskSessionError, type TaskSession, type TaskSessionManager } from "./task-sessions.js";
import { isStableSessionKey } from "./stable-session-key.js";
import { isSessionAccess, isSessionAccessDelta, normalizeSessionAccess, type SessionAccess, type SessionAccessDelta } from "./session-access.js";
import type { AccessUpgradeRecord } from "./native-protocol.js";
import { isRoutedBrokerAddress, type RoutedBrokerAddress } from "../hub/routing.js";
import type { RouteProvenance } from "./endpoint-contracts.js";
import { setTimeout as delay } from "node:timers/promises";

export const BROKER_MAX_LINE_BYTES = 1024 * 1024;
export type BrokerCommand = "status" | "listTabs" | "claimTab" | "openSession" | "sessionUrl" | "requestAccess" | "revokeSession" | "closeSession" | "enrollProfile";
export type BrokerCommandRequest = Readonly<{ id: string; command: BrokerCommand; taskLabel?: string; requestedCapabilities?: string[]; access?: SessionAccess; accessDelta?: SessionAccessDelta; ttlMs?: number; stableSessionKey?: string; sessionId?: string; scope?: "all" | "session"; tabId?: number; reason?: string; profileName?: string; publicKeySpki?: string }>;
export type BrokerAuthOk = Readonly<{ type: "authOk" }>;
export type BrokerResponse = Readonly<{ id: string; ok: true; result: unknown }> | Readonly<{ id: string; ok: false; error: { code: string; message: string } }>;
export type BrokerEvent = Readonly<{ event: "pending" | "active" | "reconnecting" | "revoked" | "accessPending" | "accessUpdated" | "accessDeclined" | "hostClosing" | "profileEnrolled" | "enrollDeclined"; sessionId?: string; session?: TaskSession; accessRequest?: AccessUpgradeRecord; accessRequestId?: string; cdpUrl?: string; reason?: string; enrollmentId?: string; profileName?: string }>;
export type BrokerProfileResolver = (name: string) => Promise<Readonly<{ principalId: string; displayName: string; publicKeySpki: string }> | null> | Readonly<{ principalId: string; displayName: string; publicKeySpki: string }> | null;
export interface BrokerRouteContext { readonly hubId: string; readonly routeId: string; readonly streamId: string; readonly address: RoutedBrokerAddress; }
export type BrokerAuthContext = (route: BrokerRouteContext | undefined) => Readonly<{ machineId: string; machinePublicKeySpki: string; machinePrivateKeyPkcs8: string; endpointId: string }> | null;
export type BrokerServerOptions = Readonly<{ socketPath?: string; token: string; sessions: TaskSessionManager; isTrusted: () => boolean; controller: () => Readonly<{ principalId: string; displayName: string }> | null; profile?: BrokerProfileResolver; authContext?: BrokerAuthContext; routeFor?: (context: BrokerRouteContext, controllerPrincipalId: string, authority: AuthV2RequestedAuthority) => RouteProvenance; enrollProfile?: (profileName: string, publicKeySpki: string) => Promise<Readonly<{ enrollmentId: string; code: string; expiresAt: number }>>; status?: () => Record<string, unknown>; listTabs?: (sessionId: string | undefined, scope: "all" | "session") => Promise<unknown>; claimTab?: (sessionId: string, tabId: number) => Promise<unknown>; requestAccess?: (controllerPrincipalId: string, stableSessionKey: string, delta: SessionAccessDelta) => Promise<AccessUpgradeRecord> | AccessUpgradeRecord }>;
export function defaultBrokerSocketPath(paths: ApplicationSupportOptions = {}): string { return join(applicationSupportDirectory(paths), "broker.sock"); }
const object = (value: unknown): value is Record<string, unknown> => !!value && typeof value === "object" && !Array.isArray(value);
const id = (value: unknown): value is string => typeof value === "string" && value.length > 0 && value.length <= 128 && /^[A-Za-z0-9._:-]+$/.test(value);
function matches(expected: string, actual: unknown): boolean { if (typeof actual !== "string") return false; const a = Buffer.from(expected), b = Buffer.from(actual), p = Buffer.alloc(a.length); b.copy(p, 0, 0, Math.min(a.length, b.length)); return a.length === b.length && timingSafeEqual(a, p); }
function requestedAuthority(command: BrokerCommand, request: BrokerCommandRequest): AuthV2RequestedAuthority {
  let scope: SessionAccess | null = null;
  if (command === "openSession") {
    try { scope = normalizeSessionAccess(request.access); } catch { /* command validation reports malformed access */ }
  }
  return { scope, ttlMs: command === "openSession" && Number.isSafeInteger(request.ttlMs) && request.ttlMs! > 0 ? request.ttlMs! : null, stableSessionKey: typeof request.stableSessionKey === "string" ? request.stableSessionKey : null };
}
function sameAuthority(left: AuthV2RequestedAuthority, right: AuthV2RequestedAuthority): boolean {
  return left.ttlMs === right.ttlMs && left.stableSessionKey === right.stableSessionKey && JSON.stringify(left.scope) === JSON.stringify(right.scope);
}
function isBrokerRouteContext(value: unknown): value is BrokerRouteContext {
  if (!object(value)) return false;
  return Object.keys(value).length === 4 && typeof value.hubId === "string" && /^sha256\/[A-Za-z0-9+/=_-]{1,249}$/.test(value.hubId) && typeof value.routeId === "string" && /^[A-Za-z0-9._:-]{1,256}$/.test(value.routeId) && typeof value.streamId === "string" && /^[A-Za-z0-9._:-]{1,256}$/.test(value.streamId) && isRoutedBrokerAddress(value.address);
}
function routeProof(secret: Buffer, context: BrokerRouteContext): string {
  return createHmac("sha256", secret).update(JSON.stringify({ hubId: context.hubId, routeId: context.routeId, streamId: context.streamId, address: { machineId: context.address.machineId, endpointId: context.address.endpointId, principalId: context.address.principalId, stableSessionKey: context.address.stableSessionKey } })).digest("base64url");
}
function code(error: unknown): string { return error instanceof TaskSessionError ? error.code : "invalidRequest"; }
function message(error: unknown): string { return error instanceof Error ? error.message : "invalid broker request"; }
const SOCKET_CLOSE_GRACE_MS = 1_000;
const SOCKET_CLOSE_POLL_MS = 10;

async function socketAcceptsConnections(socketPath: string): Promise<boolean> {
  return await new Promise<boolean>((resolve, reject) => {
    const probe = createConnection(socketPath);
    probe.once("connect", () => { probe.destroy(); resolve(true); });
    probe.once("error", (error) => {
      probe.destroy();
      if ((error as NodeJS.ErrnoException).code === "ECONNREFUSED" || (error as NodeJS.ErrnoException).code === "ENOENT") resolve(false);
      else reject(error);
    });
  });
}
async function prepareSocketPath(socketPath: string): Promise<void> {
  try {
    if (!(await lstat(socketPath)).isSocket()) throw new Error("broker socket path exists and is not a socket");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
    throw error;
  }
  if (await socketAcceptsConnections(socketPath)) {
    throw new Error("Agent Tab Bridge broker is already running");
  }

  // A closing Unix server stops accepting before Node removes its socket path.
  // Wait for that cleanup instead of unlinking early: binding a replacement
  // during this window lets the old server remove the replacement's pathname.
  const deadline = Date.now() + SOCKET_CLOSE_GRACE_MS;
  while (Date.now() < deadline) {
    try {
      await lstat(socketPath);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
      throw error;
    }
    await delay(SOCKET_CLOSE_POLL_MS);
  }

  // A crashed process can leave a genuinely stale pathname. Re-probe before
  // removing it so a broker that appeared during the grace period wins.
  if (await socketAcceptsConnections(socketPath)) {
    throw new Error("Agent Tab Bridge broker is already running");
  }
  await rm(socketPath);
}

/** User-only NDJSON broker, retained only while the browser native host lives. */
export class BrokerServer {
  readonly socketPath: string;
  private readonly clients = new Set<Socket>();
  private readonly principals = new Map<Socket, Readonly<{ principalId: string; displayName: string }>>();
  private readonly sessionOwners = new Map<string, { sockets: Set<Socket>; revokeOnDisconnect: boolean }>();
  private readonly profileAuthorities = new Map<Socket, AuthV2RequestedAuthority>();
  private readonly usedAuthTranscripts = new Map<string, number>();
  private readonly pendingEvents = new Map<string, BrokerEvent[]>();

  private readonly connections = new Set<Socket>();
  private readonly routedContextSecret = randomBytes(32);
  private closed = false;
  private constructor(private readonly server: Server, private readonly options: BrokerServerOptions, socketPath: string) { this.socketPath = socketPath; }
  get connectionCount(): number { return this.connections.size; }
  get clientCount(): number { return this.clients.size; }
  static async start(options: BrokerServerOptions): Promise<BrokerServer> {
    if (options.token.length < 32) throw new Error("broker token is missing or too short");
    const socketPath = options.socketPath ?? defaultBrokerSocketPath();
    await prepareSocketPath(socketPath);
    let broker: BrokerServer;
    const server = createServer((socket) => broker.accept(socket));
    broker = new BrokerServer(server, options, socketPath);
    await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(socketPath, () => { server.off("error", reject); resolve(); }); });
    await chmod(socketPath, 0o600);
    return broker;
  }
  publish(event: BrokerEvent): void {
    if (this.closed) return;
    if (!event.sessionId) { const line = JSON.stringify(event) + "\n"; for (const socket of this.clients) if (!socket.destroyed) socket.write(line); return; }
    const owners = this.sessionOwners.get(event.sessionId);
    if (!owners) { if (event.event === "pending" || event.event === "accessPending") { const pending = this.pendingEvents.get(event.sessionId) ?? []; pending.push(event); this.pendingEvents.set(event.sessionId, pending); } return; }
    for (const socket of owners.sockets) if (!socket.destroyed && this.clients.has(socket)) socket.write(JSON.stringify(event) + "\n");
  }
  /** Gives an in-process edge bridge an unpersisted context proof; it is never sent to a hub. */
  authorizeRoutedContext(context: BrokerRouteContext): Readonly<{ type: "routedContext"; context: BrokerRouteContext; proof: string }> {
    if (!isBrokerRouteContext(context)) throw new TypeError("invalid routed broker context");
    const copy = structuredClone(context);
    return { type: "routedContext", context: copy, proof: routeProof(this.routedContextSecret, copy) };
  }
  async enrollProfile(profileName: string, publicKeySpki: string): Promise<Readonly<{ enrollmentId: string; code: string; expiresAt: number }>> {
    if (!this.options.isTrusted()) throw new TaskSessionError("invalidSession", "browser extension is not trusted");
    if (!this.options.enrollProfile) throw new TaskSessionError("invalidSession", "profile enrollment is unavailable");
    if (!PROFILE_NAME_PATTERN.test(profileName) || !publicKeySpki || publicKeySpki.length > 8192) throw new TaskSessionError("invalidSession", "profile enrollment is invalid");
    return await this.options.enrollProfile(profileName, publicKeySpki);
  }


  async close(): Promise<void> {
    if (this.closed) return; this.closed = true;
    for (const socket of this.connections) { socket.end('{"event":"hostClosing"}\n'); socket.destroy(); }
    this.clients.clear(); this.connections.clear(); this.sessionOwners.clear(); this.pendingEvents.clear(); await new Promise<void>((resolve) => this.server.close(() => resolve())); await rm(this.socketPath, { force: true });
  }
  private bindSessionOwner(sessionId: string, socket: Socket, revokeOnDisconnect: boolean): void {
    const owners = this.sessionOwners.get(sessionId) ?? { sockets: new Set<Socket>(), revokeOnDisconnect };
    owners.sockets.add(socket);
    this.sessionOwners.set(sessionId, owners);
    const pending = this.pendingEvents.get(sessionId);
    if (pending) { this.pendingEvents.delete(sessionId); for (const event of pending) if (!socket.destroyed) socket.write(JSON.stringify(event) + "\n"); }
  }

  private accept(socket: Socket): void {
    if (this.closed) { socket.destroy(); return; }
    this.connections.add(socket); let input = Buffer.alloc(0), authenticated = false; let routed: BrokerRouteContext | undefined; const requestIds = new Set<string>();
    let challenge: { transcript: AuthV2Transcript; profile: Readonly<{ principalId: string; displayName: string; publicKeySpki: string }> } | null = null;
    let authBusy = false;
    const unauthorized = () => { socket.end('{"type":"error","error":{"code":"unauthorized","message":"authentication failed"}}\n'); };
    socket.on("error", () => {}); socket.on("close", () => {
      this.clients.delete(socket);
      this.connections.delete(socket);
      this.principals.delete(socket);
      this.profileAuthorities.delete(socket);
      const revokeOnDisconnect: string[] = [];
      for (const [sessionId, owners] of this.sessionOwners) {
        if (!owners.sockets.delete(socket)) continue;
        if (owners.sockets.size !== 0) continue;
        this.sessionOwners.delete(sessionId);
        if (owners.revokeOnDisconnect) revokeOnDisconnect.push(sessionId);
      }
      void Promise.allSettled(revokeOnDisconnect.map(async (sessionId) => await this.options.sessions.revoke(sessionId, "controllerDisconnected")));
    });
    socket.on("data", (chunk: Buffer) => {
      input = input.length ? Buffer.concat([input, chunk]) : Buffer.from(chunk);
      if (input.length > BROKER_MAX_LINE_BYTES) { socket.destroy(); return; }
      while (true) {
        const end = input.indexOf(0x0a); if (end < 0) return;
        const line = input.subarray(0, end); input = input.subarray(end + 1);
        if (!line.length || line.length > BROKER_MAX_LINE_BYTES) { socket.destroy(); return; }
        let value: unknown; try { value = JSON.parse(line.toString("utf8")); } catch { socket.destroy(); return; }
        if (!authenticated) {
          if (object(value) && value.type === "routedContext" && !routed && isBrokerRouteContext(value.context) && matches(routeProof(this.routedContextSecret, value.context), value.proof)) {
            routed = structuredClone(value.context); continue;
          }
          if (authBusy) { socket.destroy(); return; }
          if (object(value) && value.type === "auth" && matches(this.options.token, value.token)) {
            authenticated = true; this.clients.add(socket); socket.write('{"type":"authOk"}\n'); continue;
          }
          if (object(value) && value.type === "authHello" && typeof value.profile === "string" && PROFILE_NAME_PATTERN.test(value.profile) && typeof value.controllerNonce === "string" && typeof value.controllerEphemeralPublicKey === "string" && isAuthV2RequestedAuthority(value.authority) && this.options.profile && this.options.authContext) {
            const hello = value as { profile: string; controllerNonce: string; controllerEphemeralPublicKey: string; authority: AuthV2RequestedAuthority };
            const name = hello.profile;
            authBusy = true;
            void (async () => {
              try {
                const [profile, context] = await Promise.all([this.options.profile!(name), Promise.resolve(this.options.authContext!(routed))]);
                if (!profile || !context || socket.destroyed || (routed !== undefined && (routed.address.machineId !== context.machineId || routed.address.endpointId !== context.endpointId || routed.address.principalId !== profile.principalId || routed.address.stableSessionKey !== hello.authority.stableSessionKey))) { unauthorized(); return; }
                const expiresAt = Date.now() + AUTH_V2_MAX_CLOCK_SKEW_MS;
                const transcript: AuthV2Transcript = {
                  protocolVersion: 2,
                  cipherSuite: "P-256/SHA-256",
                  controller: { principalId: profile.principalId, publicKeySpki: profile.publicKeySpki, role: "controller" },
                  edge: { machineId: context.machineId, principalId: context.machineId, publicKeySpki: context.machinePublicKeySpki, role: "edge" },
                  endpointId: context.endpointId,
                  controllerEphemeralPublicKey: hello.controllerEphemeralPublicKey,
                  edgeEphemeralPublicKey: createAuthV2EphemeralPublicKey(),
                  controllerNonce: hello.controllerNonce,
                  edgeNonce: createAuthV2Nonce(),
                  authority: hello.authority,
                  expiresAt,
                  hubId: routed?.hubId ?? null,
                  routeId: routed?.routeId ?? null,
                  streamId: routed?.streamId ?? null,
                };
                const transcriptBytes = canonicalAuthV2Transcript(transcript);
                challenge = { transcript, profile };
                socket.write(`${JSON.stringify({ type: "authChallenge", transcript, signature: signTranscript(context.machinePrivateKeyPkcs8, transcriptBytes) })}\n`);
              } catch { unauthorized(); } finally { authBusy = false; }
            })();
            continue;
          }
          if (object(value) && value.type === "authProof" && challenge && typeof value.signature === "string" && isAuthV2Transcript(value.transcript)) {
            try {
              const transcriptBytes = canonicalAuthV2Transcript(value.transcript);
              const expectedBytes = canonicalAuthV2Transcript(challenge.transcript);
              const transcriptHash = createHash("sha256").update(transcriptBytes).digest("base64url");
              if (Date.now() > challenge.transcript.expiresAt || !timingSafeEqual(transcriptBytes, expectedBytes) || this.usedAuthTranscripts.has(transcriptHash) || !verifyTranscript(challenge.profile.publicKeySpki, transcriptBytes, value.signature)) { unauthorized(); return; }
              this.usedAuthTranscripts.set(transcriptHash, challenge.transcript.expiresAt);
              for (const [used, expiresAt] of this.usedAuthTranscripts) if (expiresAt < Date.now()) this.usedAuthTranscripts.delete(used);
              this.principals.set(socket, { principalId: challenge.profile.principalId, displayName: challenge.profile.displayName });
              this.profileAuthorities.set(socket, challenge.transcript.authority);
              challenge = null;
              authenticated = true; this.clients.add(socket); socket.write('{"type":"authOk"}\n'); continue;
            } catch { unauthorized(); return; }
          }
          unauthorized(); return;
        }
        void this.command(socket, value, requestIds, routed);
      }
    });
  }
  private async command(socket: Socket, value: unknown, requestIds: Set<string>, routed: BrokerRouteContext | undefined): Promise<void> {
    if (!object(value) || !id(value.id) || (value.command !== "status" && value.command !== "listTabs" && value.command !== "claimTab" && value.command !== "openSession" && value.command !== "sessionUrl" && value.command !== "requestAccess" && value.command !== "revokeSession" && value.command !== "closeSession" && value.command !== "enrollProfile")) { socket.write('{"id":"","ok":false,"error":{"code":"invalidRequest","message":"invalid broker command"}}\n'); return; }
    const request = value as BrokerCommandRequest;
    if (requestIds.has(request.id)) { socket.write(JSON.stringify({ id: request.id, ok: false, error: { code: "replayedRequest", message: "request ID was already used" } } satisfies BrokerResponse) + "\n"); return; }
    const authority = this.profileAuthorities.get(socket);
    if (authority && request.command === "openSession" && !sameAuthority(authority, requestedAuthority(request.command, request))) {
      socket.write(JSON.stringify({ id: request.id, ok: false, error: { code: "unauthorized", message: "command authority does not match the signed profile auth transcript" } } satisfies BrokerResponse) + "\n");
      return;
    }
    const connectionController = () => this.principals.get(socket) ?? this.options.controller();
    try {
      let result: unknown;
      if (request.command === "status") {
        result = { trusted: this.options.isTrusted(), sessions: this.options.sessions.snapshot(), ...(this.options.status?.() ?? {}) };
      } else if (request.command === "listTabs") {
        if (!this.options.isTrusted()) throw new TaskSessionError("invalidSession", "browser extension is not trusted");
        if (!this.options.listTabs) throw new TaskSessionError("invalidSession", "tab enumeration is unavailable");
        if (request.scope !== "all" && request.scope !== "session") throw new TaskSessionError("invalidSession", "tab scope must be all or session");
        const controller = request.stableSessionKey === undefined ? null : connectionController();
        if (request.stableSessionKey !== undefined && (!controller || !isStableSessionKey(request.stableSessionKey))) throw new TaskSessionError("invalidSession", "stableSessionKey is invalid");
        if (request.scope === "session" && request.stableSessionKey === undefined) throw new TaskSessionError("invalidSession", "session scope requires stableSessionKey");
        const session = controller && request.stableSessionKey ? this.options.sessions.getNamed(controller.principalId, request.stableSessionKey) : undefined;
        result = await this.options.listTabs(session?.id, request.scope);
      } else if (request.command === "claimTab") {
        if (!this.options.isTrusted()) throw new TaskSessionError("invalidSession", "browser extension is not trusted");
        const controller = connectionController(); if (!controller) throw new TaskSessionError("invalidSession", "browser identity is unavailable");
        if (!isStableSessionKey(request.stableSessionKey)) throw new TaskSessionError("invalidSession", "stableSessionKey is required");
        if (!Number.isSafeInteger(request.tabId) || request.tabId! < 0) throw new TaskSessionError("invalidSession", "tabId is invalid");
        if (!this.options.claimTab) throw new TaskSessionError("invalidSession", "tab claiming is unavailable");
        const session = this.options.sessions.getNamed(controller.principalId, request.stableSessionKey);
        result = { tab: await this.options.claimTab(session.id, request.tabId!) };
      } else if (request.command === "openSession") {
        if (!this.options.isTrusted()) throw new TaskSessionError("invalidSession", "browser extension is not trusted");
        const controller = connectionController(); if (!controller) throw new TaskSessionError("invalidSession", "browser identity is unavailable");
        if (typeof request.taskLabel !== "string" || !Array.isArray(request.requestedCapabilities)) throw new TaskSessionError("invalidSession", "taskLabel and requestedCapabilities are required");
        if (request.stableSessionKey !== undefined && !isStableSessionKey(request.stableSessionKey)) throw new TaskSessionError("invalidSession", "stableSessionKey is invalid");
        const route = routed === undefined ? undefined : this.options.routeFor?.(routed, controller.principalId, authority ?? requestedAuthority(request.command, request));
        if (routed !== undefined && !route) throw new TaskSessionError("invalidSession", "routed session context is unavailable");
        const session = this.options.sessions.open({ controllerPrincipalId: controller.principalId, controllerName: controller.displayName, taskLabel: request.taskLabel, capabilities: request.requestedCapabilities, access: request.access, ttlMs: request.ttlMs, ...(request.stableSessionKey === undefined ? {} : { stableSessionKey: request.stableSessionKey }), ...(route === undefined ? {} : { route }) });
        this.bindSessionOwner(session.id, socket, request.stableSessionKey === undefined);
        const cdpUrl = this.options.sessions.cdpUrl(session.id);
        result = { session, ...(cdpUrl === undefined ? {} : { cdpUrl }) };
      } else if (request.command === "sessionUrl") {
        if (!this.options.isTrusted()) throw new TaskSessionError("invalidSession", "browser extension is not trusted");
        const controller = connectionController(); if (!controller) throw new TaskSessionError("invalidSession", "browser identity is unavailable");
        if (!isStableSessionKey(request.stableSessionKey)) throw new TaskSessionError("invalidSession", "stableSessionKey is required");
        const session = this.options.sessions.getNamed(controller.principalId, request.stableSessionKey);
        const cdpUrl = this.options.sessions.cdpUrl(session.id);
        if (cdpUrl === undefined) throw new TaskSessionError("invalidSession", "session relay is not ready");
        result = { session, cdpUrl };
      } else if (request.command === "requestAccess") {
        if (!this.options.isTrusted()) throw new TaskSessionError("invalidSession", "browser extension is not trusted");
        const controller = connectionController(); if (!controller) throw new TaskSessionError("invalidSession", "browser identity is unavailable");
        if (!isStableSessionKey(request.stableSessionKey)) throw new TaskSessionError("invalidSession", "stableSessionKey is required");
        if (!isSessionAccessDelta(request.accessDelta)) throw new TaskSessionError("invalidSession", "accessDelta is invalid");
        if (!this.options.requestAccess) throw new TaskSessionError("invalidSession", "access upgrades are unavailable");
        const accessRequest = await this.options.requestAccess(controller.principalId, request.stableSessionKey, request.accessDelta);
        this.bindSessionOwner(accessRequest.sessionId, socket, false);
        result = { accessRequest };
      } else if (request.command === "closeSession") {
        if (!this.options.isTrusted()) throw new TaskSessionError("invalidSession", "browser extension is not trusted");
        const controller = connectionController(); if (!controller) throw new TaskSessionError("invalidSession", "browser identity is unavailable");
        if (!isStableSessionKey(request.stableSessionKey)) throw new TaskSessionError("invalidSession", "stableSessionKey is required");
        result = { session: await this.options.sessions.revokeNamed(controller.principalId, request.stableSessionKey, request.reason ?? "cliClosed") };
      } else if (request.command === "enrollProfile") {
        if (!this.options.isTrusted()) throw new TaskSessionError("invalidSession", "browser extension is not trusted");
        if (!this.options.enrollProfile) throw new TaskSessionError("invalidSession", "profile enrollment is unavailable");
        if (typeof request.profileName !== "string" || !PROFILE_NAME_PATTERN.test(request.profileName)) throw new TaskSessionError("invalidSession", "profileName is invalid");
        if (typeof request.publicKeySpki !== "string" || !request.publicKeySpki.length || request.publicKeySpki.length > 8192) throw new TaskSessionError("invalidSession", "publicKeySpki is invalid");
        result = { enrollment: await this.options.enrollProfile(request.profileName, request.publicKeySpki) };
      } else {
        if (typeof request.sessionId !== "string") throw new TaskSessionError("invalidSession", "sessionId is required");
        if (this.options.sessions.isReusable(request.sessionId)) throw new TaskSessionError("invalidSession", "named reusable sessions must be closed with their stable session key");
        if (!this.sessionOwners.get(request.sessionId)?.sockets.has(socket)) throw new TaskSessionError("invalidSession", "session is owned by another controller");
        result = { session: await this.options.sessions.revoke(request.sessionId, request.reason ?? "cliRevoked") };
      }
      socket.write(JSON.stringify({ id: request.id, ok: true, result } satisfies BrokerResponse) + "\n");
    } catch (error) { socket.write(JSON.stringify({ id: request.id, ok: false, error: { code: code(error), message: message(error) } } satisfies BrokerResponse) + "\n"); }
  }
}
export async function startBrokerServer(options: BrokerServerOptions): Promise<BrokerServer> { return await BrokerServer.start(options); }

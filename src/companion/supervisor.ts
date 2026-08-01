import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { chmod, lstat, mkdir, open, rm, stat, type FileHandle } from "node:fs/promises";
import { createConnection, createServer, type Server, type Socket } from "node:net";
import type { TLSSocket } from "node:tls";
import { dirname, join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import { startAgentTabRelay } from "../../extensions/browser/src/browser/extension-relay/relay-server.js";
import { BrokerServer } from "./broker.js";
import { IdentityStore, createBrokerSecret, fingerprintSpki } from "./identity.js";
import { runNativeEndpoint } from "./native-host.js";
import { createEnrollmentStatement } from "./enrollment-statement.js";
import { applicationSupportDirectory, atomicWritePrivateJson, readPrivateJson, CompanionStateStore, type ApplicationSupportOptions, type PinnedExtensionIdentity } from "./state.js";
import { EdgeHubPairingClient } from "./pairing/edge.js";
import type { HubRouteConnection, HubRouteStream } from "./pairing/routes.js";
import { acceptChannel } from "./channel/index.js";
import { routedChannelContext } from "./channel/context.js";
import { SecureChannelTransportAdapter, connectTransports } from "./transport-adapter.js";
import type { RoutedBrokerAddress } from "../hub/routing.js";
import type { NativeEndpointRecovery } from "./endpoint-recovery.js";
import { ENDPOINT_RECOVERY_GRACE_MS } from "./endpoint-contracts.js";
import type { TaskSessionRelay } from "./task-sessions.js";

export const SUPERVISOR_CONTROL_SOCKET_FILE = "supervisor.sock";
export const LEGACY_BROKER_SOCKET_FILE = "broker.sock";
export const ENDPOINT_SOCKET_DIRECTORY = "endpoints";
export const LIVE_ENDPOINT_REGISTRY_FILE = "live-endpoints.json";
const SUPERVISOR_LOCK_FILE = "supervisor.lock";
const CONNECT_RETRIES = 200;
const CONNECT_DELAY_MS = 10;
const STALE_LOCK_MS = 5_000;

/** Stable local paths. Endpoint socket names are derived from, but never replace, endpoint fingerprints. */
export interface SupervisorSocketLayout {
  controlSocketPath: string;
  brokerSocketPath: string;
  endpointDirectory: string;
  registryPath: string;
  electionLockPath: string;
}

export interface LiveEndpointRecord {
  endpointId: string;
  label: string;
  socketPath: string;
}
export type SupervisorLifecycleEvent =
  | Readonly<{ type: "started"; machineId: string }>
  | Readonly<{ type: "shimConnected" }>
  | Readonly<{ type: "shimDisconnected" }>
  | Readonly<{ type: "endpointReady"; endpoint: LiveEndpointRecord }>
  | Readonly<{ type: "endpointDisconnected"; endpointId: string }>
  | Readonly<{ type: "hubConnected" }>
  | Readonly<{ type: "hubDisconnected" }>
  | Readonly<{ type: "stopping" }>
  | Readonly<{ type: "stopped" }>;

export interface SupervisorStatus {
  machineId: string;
  shimCount: number;
  brokerClientCount: number;
  endpoints: LiveEndpointRecord[];
  sockets: SupervisorSocketLayout;
}
export type SupervisorOptions = ApplicationSupportOptions & {
  stateStore?: CompanionStateStore;
  identityStore?: IdentityStore;
  hubPairing?: EdgeHubPairingClient;
  startRelay?: () => Promise<TaskSessionRelay>;
  onEvent?: (event: SupervisorLifecycleEvent) => void;
};

export type NativeMessagingShimOptions = ApplicationSupportOptions & {
  input?: NodeJS.ReadableStream;
  output?: NodeJS.WritableStream;
  connect?: (socketPath: string) => Promise<Socket>;
  startSupervisor?: (layout: SupervisorSocketLayout) => Promise<void>;
};

type EndpointRuntime = { endpoint: LiveEndpointRecord; broker: BrokerServer; recovery: NativeEndpointRecovery; generation: symbol; recoveryTimer?: NodeJS.Timeout };

export function supervisorSocketLayout(options: ApplicationSupportOptions = {}): SupervisorSocketLayout {
  const directory = applicationSupportDirectory(options);
  return {
    controlSocketPath: join(directory, SUPERVISOR_CONTROL_SOCKET_FILE),
    brokerSocketPath: join(directory, LEGACY_BROKER_SOCKET_FILE),
    endpointDirectory: join(directory, ENDPOINT_SOCKET_DIRECTORY),
    registryPath: join(directory, LIVE_ENDPOINT_REGISTRY_FILE),
    electionLockPath: join(directory, SUPERVISOR_LOCK_FILE),
  };
}

/** A compact local socket name leaves space for the host-specific state directory. */
export function endpointSocketPath(endpointId: string, options: ApplicationSupportOptions = {}): string {
  if (!/^sha256\/[A-Za-z0-9+/=_-]{1,249}$/.test(endpointId)) throw new TypeError("invalid endpoint ID");
  const name = createHash("sha256").update(endpointId, "utf8").digest("base64url").slice(0, 7);
  return join(applicationSupportDirectory(options), `e-${name}`);
}

function endpointRecord(identity: PinnedExtensionIdentity, socketPath: string): LiveEndpointRecord {
  return { endpointId: identity.fingerprint, label: identity.label?.trim() || identity.extensionId, socketPath };
}

function emit(listener: SupervisorOptions["onEvent"], event: SupervisorLifecycleEvent): void { try { listener?.(event); } catch {} }

async function connected(socketPath: string): Promise<Socket> {
  return await new Promise<Socket>((resolvePromise, reject) => {
    const socket = createConnection(socketPath);
    socket.once("connect", () => resolvePromise(socket));
    socket.once("error", (error) => { socket.destroy(); reject(error); });
  });
}

async function removeStaleSocket(socketPath: string): Promise<void> {
  try {
    if (!(await lstat(socketPath)).isSocket()) throw new Error(`supervisor socket path exists and is not a socket: ${socketPath}`);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
    throw error;
  }
  try {
    const probe = await connected(socketPath);
    probe.destroy();
    throw new Error("Agent Tab Bridge supervisor is already running");
  } catch (error) {
    if (error instanceof Error && error.message === "Agent Tab Bridge supervisor is already running") throw error;
  }
  await rm(socketPath, { force: true });
}

async function listen(server: Server, socketPath: string): Promise<void> {
  await new Promise<void>((resolvePromise, reject) => {
    server.once("error", reject);
    server.listen(socketPath, () => { server.off("error", reject); resolvePromise(); });
  });
  await chmod(socketPath, 0o600);
}

async function closeServer(server: Server): Promise<void> {
  if (!server.listening) return;
  await new Promise<void>((resolvePromise) => server.close(() => resolvePromise()));
}

/**
 * One per machine. The control socket carries raw Native Messaging frames from shims;
 * endpoint sockets carry authenticated broker traffic after the end-to-end handshake.
 */
export class EdgeSupervisor {
  readonly sockets: SupervisorSocketLayout;
  private readonly stateStore: CompanionStateStore;
  private readonly identityStore: IdentityStore;
  private readonly control: Server;
  private readonly brokerRouter: Server;
  private readonly shims = new Set<Socket>();
  private readonly brokerClients = new Set<Socket>();
  private readonly endpoints = new Map<string, EndpointRuntime>();
  private readonly suspendedEndpoints = new Map<string, EndpointRuntime>();
  private readonly endpointRuns = new Set<Promise<void>>();
  private machineId = "";
  private hubSocket?: TLSSocket;
  private hubRoutes?: HubRouteConnection;
  private hubId?: string;
  private hubReconnectTimer?: NodeJS.Timeout;
  private hubReconnectInFlight = false;
  private started = false;
  private closing: Promise<void> | undefined;
  private registryTail = Promise.resolve();
  private readonly closedSignal = Promise.withResolvers<void>();

  private readonly hubPairing: EdgeHubPairingClient;
  constructor(private readonly options: SupervisorOptions = {}) {
    this.sockets = supervisorSocketLayout(options);
    this.stateStore = options.stateStore ?? new CompanionStateStore(options);
    this.identityStore = options.identityStore ?? new IdentityStore("companion", options);
    this.hubPairing = options.hubPairing ?? new EdgeHubPairingClient(options);
    this.control = createServer((socket) => this.attachShim(socket));
    this.brokerRouter = createServer((socket) => this.routeBroker(socket));
  }

  async start(): Promise<this> {
    if (this.started) return this;
    await mkdir(this.sockets.endpointDirectory, { recursive: true, mode: 0o700 });
    await chmod(dirname(this.sockets.controlSocketPath), 0o700);
    await chmod(this.sockets.endpointDirectory, 0o700);
    await Promise.all([removeStaleSocket(this.sockets.controlSocketPath), removeStaleSocket(this.sockets.brokerSocketPath)]);
    const identity = await this.identityStore.loadOrCreate();
    await this.stateStore.initializeMachine(identity.principalId, createBrokerSecret());
    this.machineId = identity.principalId;
    try {
      await listen(this.control, this.sockets.controlSocketPath);
      await listen(this.brokerRouter, this.sockets.brokerSocketPath);
    } catch (error) {
      await Promise.allSettled([closeServer(this.control), closeServer(this.brokerRouter)]);
      await Promise.allSettled([rm(this.sockets.controlSocketPath, { force: true }), rm(this.sockets.brokerSocketPath, { force: true })]);
      throw error;
    }
    this.started = true;
    await this.writeRegistry();
    emit(this.options.onEvent, { type: "started", machineId: this.machineId });
    const pairing = await this.hubPairing.store.load();
    this.hubId = pairing?.pairing.pinnedPeerKey.principalId;
    if (this.hubId) {
      await this.connectHub().catch(() => {
        emit(this.options.onEvent, { type: "hubDisconnected" });
        this.scheduleHubReconnect();
      });
    }
    return this;
  }

  get closed(): Promise<void> { return this.closedSignal.promise; }

  status(): SupervisorStatus {
    return {
      machineId: this.machineId,
      shimCount: this.shims.size,
      brokerClientCount: this.brokerClients.size + [...this.endpoints.values()].reduce((count, endpoint) => count + endpoint.broker.connectionCount, 0),
      endpoints: [...this.endpoints.values()].map(({ endpoint }) => ({ ...endpoint })),
      sockets: { ...this.sockets },
    };
  }

  async close(): Promise<void> {
    if (this.closing) return await this.closing;
    this.closing = this.stop();
    return await this.closing;
  }

  private async stop(): Promise<void> {
    emit(this.options.onEvent, { type: "stopping" });
    clearTimeout(this.hubReconnectTimer);
    this.hubReconnectTimer = undefined;
    this.hubRoutes?.close();
    this.hubRoutes = undefined;
    this.hubSocket?.destroy();
    this.hubSocket = undefined;
    for (const socket of this.brokerClients) socket.destroy();
    for (const socket of this.shims) socket.destroy();
    for (const runtime of [...this.endpoints.values(), ...this.suspendedEndpoints.values()]) {
      clearTimeout(runtime.recoveryTimer);
      await runtime.recovery.sessions.revokeAll("supervisorClosing").catch(() => undefined);
      await runtime.broker.close().catch(() => undefined);
    }
    this.endpoints.clear();
    this.suspendedEndpoints.clear();
    await this.writeRegistry();
    await Promise.allSettled([closeServer(this.control), closeServer(this.brokerRouter)]);
    await Promise.allSettled([
      rm(this.sockets.controlSocketPath, { force: true }),
      rm(this.sockets.brokerSocketPath, { force: true }),
      rm(this.sockets.registryPath, { force: true }),
      rm(this.sockets.endpointDirectory, { recursive: true, force: true }),
    ]);
    this.started = false;
    emit(this.options.onEvent, { type: "stopped" });
    this.closedSignal.resolve();
  }

  private attachShim(socket: Socket): void {
    if (this.closing) { socket.destroy(); return; }
    this.shims.add(socket);
    emit(this.options.onEvent, { type: "shimConnected" });
    const generation = Symbol("native-endpoint-run");
    const run = runNativeEndpoint({
      input: socket,
      output: socket,
      stateStore: this.stateStore,
      onProfileEnrolled: async (record) => await this.publishEnrollment(record),
      identityStore: this.identityStore,
      startRelay: this.options.startRelay ?? startAgentTabRelay,
      brokerSocketPath: (identity) => endpointSocketPath(identity.fingerprint, this.options),
      recoverEndpoint: (identity) => this.recoverEndpoint(identity, generation),
      onEndpointReady: async (identity, broker, recovery) => await this.endpointReady(identity, broker, recovery, generation),
      onEndpointSuspended: async (recovery) => await this.endpointSuspended(recovery, generation),
      onEndpointClosed: async (endpointId, broker) => await this.endpointClosed(endpointId, broker, generation),
    }).catch(() => {}).finally(() => {
      this.endpointRuns.delete(run);
      this.shims.delete(socket);
      socket.destroy();
      emit(this.options.onEvent, { type: "shimDisconnected" });
      void this.exitIfIdle();
    });
    this.endpointRuns.add(run);
  }

  private recoverEndpoint(identity: PinnedExtensionIdentity, generation: symbol): NativeEndpointRecovery | undefined {
    const live = this.endpoints.get(identity.fingerprint);
    if (live) {
      live.generation = generation;
      live.recovery.sessions.suspend();
      return live.recovery;
    }
    const suspended = this.suspendedEndpoints.get(identity.fingerprint);
    if (suspended) suspended.generation = generation;
    return suspended?.recovery;
  }

  private async endpointReady(identity: PinnedExtensionIdentity, broker: BrokerServer, recovery: NativeEndpointRecovery, generation: symbol): Promise<void> {
    const socketPath = endpointSocketPath(identity.fingerprint, this.options);
    const existing = this.endpoints.get(identity.fingerprint);
    if (existing && (existing.broker !== broker || existing.recovery !== recovery || existing.generation !== generation)) throw new Error("endpoint run was replaced");
    const suspended = this.suspendedEndpoints.get(identity.fingerprint);
    if (suspended && (suspended.recovery !== recovery || suspended.generation !== generation)) throw new Error("endpoint recovery run was replaced");
    if (suspended) {
      clearTimeout(suspended.recoveryTimer);
      this.suspendedEndpoints.delete(identity.fingerprint);
    }
    const endpoint = endpointRecord(identity, socketPath);
    this.endpoints.set(identity.fingerprint, { endpoint, broker, recovery, generation });
    await this.writeRegistry();
    emit(this.options.onEvent, { type: "endpointReady", endpoint });
    if (this.hubSocket) await this.hubPairing.pushPresence(this.hubSocket).catch(() => undefined);
  }

  private async endpointSuspended(recovery: NativeEndpointRecovery, generation: symbol): Promise<boolean> {
    if (this.closing) return false;
    const endpointId = recovery.identity.fingerprint;
    const existing = this.endpoints.get(endpointId);
    if (!existing) return this.suspendedEndpoints.get(endpointId)?.recovery === recovery;
    if (existing.recovery !== recovery) return false;
    if (existing.generation !== generation) return true;
    if (!recovery.sessions.snapshot().some((session) => session.state === "active" || session.state === "reconnecting")) return false;
    recovery.sessions.suspend();
    this.endpoints.delete(endpointId);
    existing.recoveryTimer = setTimeout(() => void this.expireRecovery(endpointId, recovery), ENDPOINT_RECOVERY_GRACE_MS);
    existing.recoveryTimer.unref?.();
    this.suspendedEndpoints.set(endpointId, existing);
    await this.writeRegistry();
    emit(this.options.onEvent, { type: "endpointDisconnected", endpointId });
    if (this.hubSocket) await this.hubPairing.pushPresence(this.hubSocket).catch(() => undefined);
    return true;
  }

  private async expireRecovery(endpointId: string, recovery: NativeEndpointRecovery): Promise<void> {
    const existing = this.suspendedEndpoints.get(endpointId);
    if (!existing || existing.recovery !== recovery) return;
    this.suspendedEndpoints.delete(endpointId);
    clearTimeout(existing.recoveryTimer);
    await recovery.sessions.revokeAll("endpointRecoveryExpired");
    await recovery.broker.close().catch(() => undefined);
    void this.exitIfIdle();
  }

  private async endpointClosed(endpointId: string, broker: BrokerServer | null, generation: symbol): Promise<void> {
    const live = this.endpoints.get(endpointId);
    const suspended = this.suspendedEndpoints.get(endpointId);
    const existing = live ?? suspended;
    if (!existing || existing.generation !== generation || (broker && existing.broker !== broker)) return;
    clearTimeout(existing.recoveryTimer);
    this.endpoints.delete(endpointId);
    this.suspendedEndpoints.delete(endpointId);
    if (!live) return;
    await this.writeRegistry();
    emit(this.options.onEvent, { type: "endpointDisconnected", endpointId });
    if (this.hubSocket) await this.hubPairing.pushPresence(this.hubSocket).catch(() => undefined);
  }

  /** Terminates a routed profile-auth stream and begins only explicit remote enrollments at its selected edge. */
  private async connectHub(): Promise<void> {
    if (this.closing || !this.hubId || this.hubSocket) return;
    const routes = await this.hubPairing.connectRoutes((stream, address) => this.routeHubBroker(stream, address));
    if (!routes) throw new Error("hub pairing state is unavailable");
    this.hubRoutes = routes;
    const socket = routes.connectionSocket;
    this.hubSocket = socket;
    socket.once("close", () => { void this.handleHubDisconnected(socket); });
    emit(this.options.onEvent, { type: "hubConnected" });
  }

  private async handleHubDisconnected(socket: TLSSocket): Promise<void> {
    if (this.hubSocket !== socket && this.hubRoutes?.connectionSocket !== socket) return;
    this.hubSocket = undefined;
    this.hubRoutes = undefined;
    await Promise.all([...this.endpoints.values(), ...this.suspendedEndpoints.values()].map(async ({ broker }) => await broker.revokeRoutedSessions()));
    emit(this.options.onEvent, { type: "hubDisconnected" });
    this.scheduleHubReconnect();
  }

  private scheduleHubReconnect(): void {
    if (this.closing || !this.hubId || this.hubReconnectTimer || this.hubReconnectInFlight) return;
    this.hubReconnectTimer = setTimeout(() => {
      this.hubReconnectTimer = undefined;
      this.hubReconnectInFlight = true;
      void this.connectHub().then(() => undefined, () => undefined).finally(() => {
        this.hubReconnectInFlight = false;
        if (!this.hubSocket) this.scheduleHubReconnect();
      });
    }, 1_000);
    this.hubReconnectTimer.unref?.();
  }

  private routeHubBroker(stream: HubRouteStream, address: RoutedBrokerAddress): void {
    const hubEnablement = this.hubPairing.store.load();
    const runtime = this.endpoints.get(address.endpointId);
    const hubId = this.hubId;
    if (!hubId || address.machineId !== this.machineId || !runtime || runtime.endpoint.endpointId !== address.endpointId) { stream.close(); return; }
    let upstream: Socket | undefined;
    let relayPort: number | undefined;
    let first = true;
    let channelMode = false;
    let channelPurpose: "broker" | "enroll" | "relay" | undefined;
    let accepted: ReturnType<typeof acceptChannel> | undefined;
    let secure: SecureChannelTransportAdapter | undefined;
    let channelOptions: Promise<Parameters<typeof acceptChannel>[0]> | undefined;
    const close = () => { stream.close(); upstream?.destroy(); secure?.destroy(); };
    stream.onPayload((payload) => {
      void (async () => {
        try {
          const hubState = await hubEnablement;
          if (!hubState?.enabledEndpointIds.includes(address.endpointId)) {
            stream.send(Buffer.from(JSON.stringify({ type: "error", error: { code: "endpointHubDisabled", message: "endpoint is not enabled for this hub" } }), "utf8"));
            close();
            return;
          }
        } catch { close(); return; }
        if (first) {
          first = false;
          let request: Record<string, unknown> | undefined;
          try { request = JSON.parse(payload.toString("utf8")) as Record<string, unknown>; } catch {}
          if (request?.type === "channelHello" && Object.keys(request).length === 4 && typeof request.profileName === "string" && typeof request.publicKeySpki === "string" && request.value && typeof request.value === "object") {
            let peerFingerprint: string;
            try { peerFingerprint = fingerprintSpki(request.publicKeySpki); } catch { close(); return; }
            const peerPublicKeySpki = request.publicKeySpki;
            const state = await this.stateStore.load();
            const enrolled = state.machine.enrollments.find((profile) => profile.principalId === address.principalId);
            if (enrolled && enrolled.publicKeySpki !== peerPublicKeySpki) { close(); return; }
            channelPurpose = enrolled ? "broker" : "enroll";
            channelMode = true;
            channelOptions = (async () => {
              const identity = await this.identityStore.loadOrCreate();
              return { identity, peerPublicKeySpki, sessionId: address.stableSessionKey, context: routedChannelContext(address, stream.routeId, stream.streamId) };
            })();
          } else if (request?.type === "relayTransport" && Object.keys(request).length === 5 && Number.isSafeInteger(request.port) && Number(request.port) >= 1 && Number(request.port) <= 65_535 && typeof request.profileName === "string" && typeof request.sessionId === "string" && typeof request.cdpUrl === "string") {
            let cdp: URL;
            try { cdp = new URL(request.cdpUrl); } catch { close(); return; }
            if (cdp.protocol !== "ws:" || (cdp.hostname !== "127.0.0.1" && cdp.hostname !== "localhost") || Number(cdp.port) !== Number(request.port) || !runtime.broker.authorizeRoutedRelay(request.sessionId, request.cdpUrl, address)) { close(); return; }
            channelMode = true;
            channelPurpose = "relay";
            relayPort = Number(request.port);
            const profileName = request.profileName;
            channelOptions = (async () => {
              const state = await this.stateStore.load();
              const enrolled = state.machine.enrollments.find((profile) => profile.name === profileName);
              if (!enrolled) throw new Error("connector profile is not enrolled at this edge");
              const identity = await this.identityStore.loadOrCreate();
              return { identity, peerPublicKeySpki: enrolled.publicKeySpki, sessionId: address.stableSessionKey, context: routedChannelContext(address, stream.routeId, stream.streamId) };
            })();
            return;
          } else {
            upstream = createConnection(runtime.endpoint.socketPath);
            upstream.once("error", close);
            upstream.once("close", () => stream.close());
            upstream.on("data", (chunk: Buffer) => { try { stream.send(chunk); } catch { close(); } });
            stream.onClose(close);
            upstream.write(`${JSON.stringify(runtime.broker.authorizeRoutedContext({ hubId, routeId: stream.routeId, streamId: stream.streamId, address }))}\n`);
          }
        }
        if (channelMode) {
          if (!accepted) {
            let message: Record<string, unknown>;
            const options = await channelOptions;
            if (!options) { close(); return; }
            try { message = JSON.parse(payload.toString("utf8")) as Record<string, unknown>; } catch { close(); return; }
            if (message.type !== "channelHello" || !message.value || typeof message.value !== "object") { close(); return; }
            try {
              accepted = acceptChannel(options, message.value as never);
              stream.send(Buffer.from(JSON.stringify({ type: "channelAccept", value: accepted.accept }), "utf8"));
            } catch { close(); }
            return;
          }
          if (!secure) {
            let message: Record<string, unknown>;
            try { message = JSON.parse(payload.toString("utf8")) as Record<string, unknown>; } catch { close(); return; }
            if (message.type !== "channelConfirm" || !message.value || typeof message.value !== "object") { close(); return; }
            try {
              const channel = accepted.complete(message.value as never);
              secure = new SecureChannelTransportAdapter(channel, (frame) => { stream.send(frame); });
              secure.once("error", close);
              if (channelPurpose === "enroll") {
                secure.on("data", (chunk: Buffer) => {
                  let enrollment: Record<string, unknown>;
                  try { enrollment = JSON.parse(chunk.toString("utf8")) as Record<string, unknown>; } catch { close(); return; }
                  if (enrollment.type !== "remoteEnroll" || typeof enrollment.profileName !== "string" || typeof enrollment.publicKeySpki !== "string") { close(); return; }
                  void runtime.broker.enrollProfile(enrollment.profileName, enrollment.publicKeySpki).then((result) => {
                    secure?.write(JSON.stringify({ type: "remoteEnrollResult", ok: true, enrollment: result }));
                    secure?.end();
                  }, (error: unknown) => {
                    secure?.write(JSON.stringify({ type: "remoteEnrollResult", ok: false, error: error instanceof Error ? error.message : "enrollment failed" }));
                    secure?.end();
                  });
                });
              } else {
                upstream = channelPurpose === "relay" ? createConnection({ host: "127.0.0.1", port: relayPort! }) : createConnection(runtime.endpoint.socketPath);
                upstream.once("error", close);
                upstream.once("close", close);
                if (channelPurpose === "broker") upstream.write(`${JSON.stringify(runtime.broker.authorizeRoutedContext({ hubId, routeId: stream.routeId, streamId: stream.streamId, address }))}\n`);
                connectTransports(secure, upstream);
              }
            } catch { close(); }
            return;
          }
          secure.receive(payload);
          return;
        }
        if (!upstream || upstream.destroyed) { close(); return; }
        upstream.write(payload, (error) => { if (error) close(); });
      })().catch(close);
    });
  }
  private async publishEnrollment(record: Readonly<{ endpointId: string; profileName: string; principalId: string; publicKeySpki: string; enrolledAt: number }>): Promise<void> {
    if (!this.hubSocket) return;
    const identity = await this.identityStore.loadOrCreate();
    await this.hubPairing.pushEnrollment(createEnrollmentStatement(identity, record));
  }


  private routeBroker(socket: Socket): void {
    if (this.closing) { socket.destroy(); return; }
    this.brokerClients.add(socket);
    const live = [...this.endpoints.values()];
    if (live.length !== 1) {
      socket.end(`${JSON.stringify({ type: "error", error: { code: "endpointSelectionRequired", message: live.length ? "multiple browser endpoints are live; select one" : "no browser endpoint is live" } })}\n`, () => socket.destroy());
      socket.once("close", () => { this.brokerClients.delete(socket); void this.exitIfIdle(); });
      return;
    }
    const upstream = createConnection(live[0]!.endpoint.socketPath);
    const close = () => { this.brokerClients.delete(socket); upstream.destroy(); void this.exitIfIdle(); };
    socket.once("close", close);
    socket.once("error", () => socket.destroy());
    upstream.once("error", () => socket.destroy());
    socket.pipe(upstream);
    upstream.pipe(socket);
  }

  private async writeRegistry(): Promise<void> {
    const operation = this.registryTail.then(async () => {
      const endpoints = [...this.endpoints.values()].map(({ endpoint }) => endpoint);
      if (endpoints.length === 0) await rm(this.sockets.registryPath, { force: true });
      else await atomicWritePrivateJson(this.sockets.registryPath, { version: 1, endpoints });
    });
    this.registryTail = operation.then(() => undefined, () => undefined);
    await operation;
  }

  private async exitIfIdle(): Promise<void> {
    if (this.closing || this.shims.size !== 0 || this.suspendedEndpoints.size !== 0) return;
    const sessionsOrClientsRemain = this.brokerClients.size !== 0 || [...this.endpoints.values()].some(({ broker }) => broker.connectionCount !== 0);
    if (!sessionsOrClientsRemain) void this.close();
  }
}

async function waitForSupervisor(layout: SupervisorSocketLayout, connect: (socketPath: string) => Promise<Socket>): Promise<Socket> {
  let lastError: unknown;
  for (let attempt = 0; attempt < CONNECT_RETRIES; attempt += 1) {
    try { return await connect(layout.controlSocketPath); } catch (error) { lastError = error; await delay(CONNECT_DELAY_MS); }
  }
  throw lastError instanceof Error ? lastError : new Error("supervisor did not start");
}

async function defaultStartSupervisor(layout: SupervisorSocketLayout): Promise<void> {
  const executable = fileURLToPath(new URL("./supervisor.js", import.meta.url));
  const child = spawn(process.execPath, [executable, "--atb-supervisor"], {
    detached: true,
    stdio: "ignore",
    env: { ...process.env, ATB_STATE_DIRECTORY: dirname(layout.controlSocketPath) },
  });
  child.unref();
}

async function acquireElection(layout: SupervisorSocketLayout, start: (layout: SupervisorSocketLayout) => Promise<void>, connect: (socketPath: string) => Promise<Socket>): Promise<Socket> {
  for (;;) {
    try { return await connect(layout.controlSocketPath); } catch {}
    let lock: FileHandle | undefined;
    try {
      lock = await open(layout.electionLockPath, "wx", 0o600);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      try {
        if (Date.now() - (await stat(layout.electionLockPath)).mtimeMs > STALE_LOCK_MS) await rm(layout.electionLockPath, { force: true });
      } catch {}
      await delay(CONNECT_DELAY_MS);
      continue;
    }
    try {
      await start(layout);
      return await waitForSupervisor(layout, connect);
    } finally {
      await lock.close();
      await rm(layout.electionLockPath, { force: true });
    }
  }
}

/** Native Messaging transport only: it forwards raw framed bytes and never parses identity or authority. */
export async function runNativeMessagingShim(options: NativeMessagingShimOptions = {}): Promise<void> {
  const directory = options.directory ?? process.env.ATB_STATE_DIRECTORY;
  const layout = supervisorSocketLayout(directory ? { ...options, directory } : options);
  await mkdir(dirname(layout.controlSocketPath), { recursive: true, mode: 0o700 });
  await chmod(dirname(layout.controlSocketPath), 0o700);
  const connect = options.connect ?? connected;
  const socket = await acquireElection(layout, options.startSupervisor ?? defaultStartSupervisor, connect);
  const input = options.input ?? process.stdin;
  const output = options.output ?? process.stdout;
  await new Promise<void>((resolvePromise) => {
    let done = false;
    const finish = () => {
      if (done) return;
      done = true;
      input.unpipe(socket);
      socket.unpipe(output);
      socket.destroy();
      resolvePromise();
    };
    socket.once("error", finish);
    socket.once("close", finish);
    input.once("error", finish);
    input.once("end", finish);
    input.pipe(socket);
    socket.pipe(output, { end: false });
  });
}

/** Entry point used only by the detached process created by the Native Messaging shim. */
export async function runSupervisorProcess(options: SupervisorOptions = {}): Promise<void> {
  const supervisor = await new EdgeSupervisor(options).start();
  await supervisor.closed;
}

if (process.argv.includes("--atb-supervisor")) {
  const directory = process.env.ATB_STATE_DIRECTORY;
  void runSupervisorProcess(directory ? { directory } : {}).catch((error) => {
    process.stderr.write(`Agent Tab Bridge supervisor failed: ${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}

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
import { IdentityStore, createBrokerSecret } from "./identity.js";
import { runNativeEndpoint } from "./native-host.js";
import { createEnrollmentStatement } from "./enrollment-statement.js";
import { applicationSupportDirectory, atomicWritePrivateJson, readPrivateJson, CompanionStateStore, type ApplicationSupportOptions, type PinnedExtensionIdentity } from "./state.js";
import { EdgeHubPairingClient } from "./pairing/edge.js";
import type { HubRouteConnection, HubRouteStream } from "./pairing/routes.js";
import type { RoutedBrokerAddress } from "../hub/routing.js";
import type { NativeEndpointRecovery } from "./endpoint-recovery.js";
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

type EndpointRuntime = { endpoint: LiveEndpointRecord; broker: BrokerServer; recovery: NativeEndpointRecovery; recoveryTimer?: NodeJS.Timeout };

export const ENDPOINT_RECOVERY_GRACE_MS = 30_000;
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
    try {
      const pairing = await this.hubPairing.store.load();
      this.hubId = pairing?.pairing.pinnedPeerKey.principalId;
      const routes = await this.hubPairing.connectRoutes((stream, address) => this.routeHubBroker(stream, address));
      if (routes) {
        this.hubRoutes = routes;
        this.hubSocket = routes.connectionSocket;
        emit(this.options.onEvent, { type: "hubConnected" });
        this.hubSocket.once("close", () => { this.hubSocket = undefined; this.hubRoutes = undefined; emit(this.options.onEvent, { type: "hubDisconnected" }); });
      }
    } catch { emit(this.options.onEvent, { type: "hubDisconnected" }); }
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
    const run = runNativeEndpoint({
      input: socket,
      output: socket,
      stateStore: this.stateStore,
      onProfileEnrolled: async (record) => await this.publishEnrollment(record),
      identityStore: this.identityStore,
      startRelay: this.options.startRelay ?? startAgentTabRelay,
      brokerSocketPath: (identity) => endpointSocketPath(identity.fingerprint, this.options),
      recoverEndpoint: (identity) => this.recoverEndpoint(identity),
      onEndpointReady: async (identity, broker, recovery) => await this.endpointReady(identity, broker, recovery),
      onEndpointSuspended: async (recovery) => await this.endpointSuspended(recovery),
      onEndpointClosed: async (endpointId, broker) => await this.endpointClosed(endpointId, broker),
    }).catch(() => {}).finally(() => {
      this.endpointRuns.delete(run);
      this.shims.delete(socket);
      socket.destroy();
      emit(this.options.onEvent, { type: "shimDisconnected" });
      void this.exitIfIdle();
    });
    this.endpointRuns.add(run);
  }

  private recoverEndpoint(identity: PinnedExtensionIdentity): NativeEndpointRecovery | undefined {
    return this.suspendedEndpoints.get(identity.fingerprint)?.recovery;
  }

  private async endpointReady(identity: PinnedExtensionIdentity, broker: BrokerServer, recovery: NativeEndpointRecovery): Promise<void> {
    const socketPath = endpointSocketPath(identity.fingerprint, this.options);
    const existing = this.endpoints.get(identity.fingerprint);
    if (existing && existing.broker !== broker) throw new Error("endpoint is already connected");
    const suspended = this.suspendedEndpoints.get(identity.fingerprint);
    if (suspended && suspended.recovery !== recovery) throw new Error("endpoint recovery identity does not match");
    if (suspended) {
      clearTimeout(suspended.recoveryTimer);
      this.suspendedEndpoints.delete(identity.fingerprint);
    }
    const endpoint = endpointRecord(identity, socketPath);
    this.endpoints.set(identity.fingerprint, { endpoint, broker, recovery });
    await this.writeRegistry();
    emit(this.options.onEvent, { type: "endpointReady", endpoint });
    if (this.hubSocket) await this.hubPairing.pushPresence(this.hubSocket).catch(() => undefined);
  }

  private async endpointSuspended(recovery: NativeEndpointRecovery): Promise<boolean> {
    if (this.closing) return false;
    const endpointId = recovery.identity.fingerprint;
    const existing = this.endpoints.get(endpointId);
    if (!existing || existing.recovery !== recovery || !recovery.sessions.snapshot().some((session) => session.state === "active")) return false;
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

  private async endpointClosed(endpointId: string, broker: BrokerServer | null): Promise<void> {
    const live = this.endpoints.get(endpointId);
    const suspended = this.suspendedEndpoints.get(endpointId);
    const existing = live ?? suspended;
    if (!existing || (broker && existing.broker !== broker)) return;
    clearTimeout(existing.recoveryTimer);
    this.endpoints.delete(endpointId);
    this.suspendedEndpoints.delete(endpointId);
    if (!live) return;
    await this.writeRegistry();
    emit(this.options.onEvent, { type: "endpointDisconnected", endpointId });
    if (this.hubSocket) await this.hubPairing.pushPresence(this.hubSocket).catch(() => undefined);
  }

  /** Terminates a routed profile-auth stream and begins only explicit remote enrollments at its selected edge. */
  private routeHubBroker(stream: HubRouteStream, address: RoutedBrokerAddress): void {
    const runtime = this.endpoints.get(address.endpointId);
    const hubId = this.hubId;
    if (!hubId || address.machineId !== this.machineId || !runtime || runtime.endpoint.endpointId !== address.endpointId) { stream.close(); return; }
    let upstream: Socket | undefined;
    let first = true;
    const close = () => { stream.close(); upstream?.destroy(); };
    stream.onPayload((payload) => {
      if (first) {
        first = false;
        try {
          const request = JSON.parse(payload.toString("utf8")) as Record<string, unknown>;
          if (request.type === "remoteEnroll" && Object.keys(request).length === 3 && typeof request.profileName === "string" && typeof request.publicKeySpki === "string") {
            void runtime.broker.enrollProfile(request.profileName, request.publicKeySpki).then((enrollment) => {
              stream.send(Buffer.from(JSON.stringify({ type: "remoteEnrollResult", ok: true, enrollment }), "utf8"));
              stream.close();
            }, (error: unknown) => {
              stream.send(Buffer.from(JSON.stringify({ type: "remoteEnrollResult", ok: false, error: error instanceof Error ? error.message : "enrollment failed" }), "utf8"));
              stream.close();
            });
            return;
          }
        } catch { /* A broker protocol line need not be a standalone JSON enrollment request. */ }
        upstream = createConnection(runtime.endpoint.socketPath);
        upstream.once("error", close);
        upstream.once("close", () => stream.close());
        upstream.on("data", (chunk: Buffer) => { try { stream.send(chunk); } catch { close(); } });
        stream.onClose(close);
        upstream.write(`${JSON.stringify(runtime.broker.authorizeRoutedContext({ hubId, routeId: stream.routeId, streamId: stream.streamId, address }))}\n`);
      }
      if (!upstream || upstream.destroyed) { close(); return; }
      upstream.write(payload, (error) => { if (error) close(); });
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
  const layout = supervisorSocketLayout(options);
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

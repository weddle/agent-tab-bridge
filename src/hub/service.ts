import { X509Certificate } from "node:crypto";
import { createServer, type Server as NetServer } from "node:tls";
import type { TLSSocket } from "node:tls";
import { applicationSupportPath, atomicWritePrivateJson, readPrivateJson, type ApplicationSupportOptions } from "../companion/state.js";
import { fingerprintSpki, type StoredIdentity } from "../companion/identity.js";
import { HubPairingCeremony, startHubPairing, type HubCeremonyStart, type HubPairingResult, type HubResponse, type MachineConfirmation, type MachineHello, type PairingRoles, type PinnedPeerKeyset } from "../companion/pairing/index.js";
import { pinnedTlsOptions, type TlsPinningOptions } from "../companion/pairing/tls.js";
import { selfSignedCertificate } from "./certificate.js";
import { HUB_MAX_FRAME_BYTES, HubFrameDecoder, encodeHubFrame } from "./framing.js";
import { HUB_MAX_ACTIVE_ROUTES, HUB_OPAQUE_ROUTE_TYPE, parseHubOpaqueRoute, type HubOpaqueRouteEnvelope } from "./routing.js";
import { isEnrollmentStatement, verifyEnrollmentStatement, type EnrollmentStatement } from "../companion/enrollment-statement.js";

export const HUB_STATE_VERSION = 1 as const;
export type HubPresence = "online" | "offline";
export interface HubMachineRecord { alias: string; principalId: string; publicKeySpki: string; fingerprint: string; pairing: PinnedPeerKeyset; presence: HubPresence; lastSeen: number | null; }
export interface HubEndpointRecord { machineId: string; endpointId: string; alias?: string; fingerprint?: string; enabled: boolean; record: unknown; }
export interface HubState { version: typeof HUB_STATE_VERSION; machines: HubMachineRecord[]; endpoints: HubEndpointRecord[]; enrollments: EnrollmentStatement[]; connectors: string[]; }
export interface HubStatus { identityFingerprint: string; listenAddress: string; machines: HubMachineRecord[]; connectors: string[]; }
export interface HubServiceOptions extends ApplicationSupportOptions { identity: StoredIdentity; port?: number; host?: string; maxFrameBytes?: number; serverCertificate?: { key: string; cert: string } }
export interface HubStartResult { address: string; port: number; }
export interface HubPairingStart extends HubCeremonyStart { }

function clone<T>(value: T): T { return structuredClone(value); }
function validPort(port: number): boolean { return Number.isInteger(port) && port >= 0 && port <= 65535; }
function validAlias(alias: string): boolean { return alias.length > 0 && alias.length <= 128; }
function peerFingerprint(socket: TLSSocket): string | undefined {
  try {
    const certificate = socket.getPeerCertificate(true);
    if (!certificate.raw) return undefined;
    const spki = new X509Certificate(certificate.raw).publicKey.export({ type: "spki", format: "der" });
    return fingerprintSpki(spki);
  } catch { return undefined; }
}
function validState(value: unknown): value is HubState {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const state = value as Record<string, unknown>;
  if (state.version !== HUB_STATE_VERSION || !Array.isArray(state.machines) || !Array.isArray(state.endpoints) || !Array.isArray(state.connectors) || (state.enrollments !== undefined && (!Array.isArray(state.enrollments) || !state.enrollments.every(isEnrollmentStatement)))) return false;
  if (!state.machines.every((machine) => {
    if (!machine || typeof machine !== "object" || Array.isArray(machine)) return false;
    const item = machine as Record<string, unknown>;
    return validAlias(String(item.alias)) && typeof item.principalId === "string" && typeof item.publicKeySpki === "string" && typeof item.fingerprint === "string" && !!item.pairing && (item.presence === "online" || item.presence === "offline") && (item.lastSeen === null || typeof item.lastSeen === "number");
  })) return false;
  return state.endpoints.every((endpoint) => !!endpoint && typeof endpoint === "object" && !Array.isArray(endpoint) && typeof (endpoint as Record<string, unknown>).machineId === "string" && typeof (endpoint as Record<string, unknown>).endpointId === "string" && typeof (endpoint as Record<string, unknown>).enabled === "boolean") && state.connectors.every((connector) => typeof connector === "string");
}

export class HubStateStore {
  readonly filePath: string;
  private state: HubState | undefined;
  private writeTail = Promise.resolve();
  constructor(options: ApplicationSupportOptions & { fileName?: string } = {}) { this.filePath = applicationSupportPath(options.fileName ?? "hub-state.json", options); }
  async load(): Promise<HubState> {
    if (this.state) return clone(this.state);
    const value = await readPrivateJson<unknown>(this.filePath);
    if (value === undefined) this.state = { version: HUB_STATE_VERSION, machines: [], endpoints: [], enrollments: [], connectors: [] };
    else if (validState(value)) this.state = { ...clone(value), enrollments: Array.isArray(value.enrollments) ? clone(value.enrollments) : [] };
    else throw new Error("invalid hub state");
    return clone(this.state);
  }
  async save(state: HubState): Promise<void> {
    await this.write(async () => { if (!validState(state)) throw new TypeError("invalid hub state"); await atomicWritePrivateJson(this.filePath, state); this.state = clone(state); });
  }
  async update(mutator: (state: HubState) => HubState | Promise<HubState>): Promise<HubState> {
    return await this.write(async () => { const next = await mutator(await this.load()); if (!validState(next)) throw new TypeError("invalid hub state"); await atomicWritePrivateJson(this.filePath, next); this.state = clone(next); return clone(next); });
  }
  private async write<T>(operation: () => Promise<T>): Promise<T> {
    const next = this.writeTail.then(operation);
    this.writeTail = next.then(() => undefined, () => undefined);
    return await next;
  }
}

type HubClient = { socket: TLSSocket; machineId?: string; decoder: HubFrameDecoder; pairResponse?: HubResponse; pairMachineId?: string };

/** Optional LAN hub: inert until explicitly configured and started. */
export class HubService {
  readonly identity: StoredIdentity;
  readonly stateStore: HubStateStore;
  readonly configured: boolean;
  readonly host: string;
  private confirmedMachineFingerprint?: string;
  readonly port: number | undefined;
  readonly maxFrameBytes: number;
  private readonly certificate: { key: string; cert: string };
  private server?: NetServer;
  private actualPort?: number;
  private readonly clients = new Set<HubClient>();
  private readonly routes = new Map<string, Readonly<{ sourceMachineId: string; targetMachineId: string; streamId: string; address: HubOpaqueRouteEnvelope["address"] }>>();
  private pairing?: HubPairingStart;
  constructor(options: HubServiceOptions) {
    if (!validPort(options.port ?? 0)) throw new RangeError("hub port must be between 0 and 65535");
    this.identity = clone(options.identity);
    if (fingerprintSpki(this.identity.publicKeySpki) !== this.identity.principalId) throw new TypeError("invalid hub identity");
    this.stateStore = new HubStateStore(options);
    this.configured = options.port !== undefined;
    this.port = options.port;
    this.host = options.host ?? "0.0.0.0";
    this.maxFrameBytes = options.maxFrameBytes ?? HUB_MAX_FRAME_BYTES;
    const generatedCertificate = selfSignedCertificate(this.identity);
    this.certificate = options.serverCertificate ?? { key: generatedCertificate.keyPem, cert: generatedCertificate.certPem };
  }
  get listening(): boolean { return this.server?.listening === true; }
  get address(): HubStartResult | undefined { return this.actualPort === undefined ? undefined : { address: `${this.host}:${this.actualPort}`, port: this.actualPort }; }
  get serverCertificatePem(): string { return this.certificate.cert; }
  async start(): Promise<HubStartResult | undefined> {
    if (!this.configured) return undefined;
    if (this.server?.listening) return this.address;
    const server = createServer({ key: this.certificate.key, cert: this.certificate.cert, minVersion: "TLSv1.3", maxVersion: "TLSv1.3", requestCert: true, rejectUnauthorized: false }, (socket) => this.accept(socket));
    this.server = server;
    await new Promise<void>((resolve, reject) => { const onError = (error: Error) => { server.off("listening", onListen); reject(error); }; const onListen = () => { server.off("error", onError); resolve(); }; server.once("error", onError); server.once("listening", onListen); server.listen(this.port, this.host); });
    const address = server.address(); this.actualPort = address && typeof address === "object" ? address.port : undefined;
    if (this.actualPort === undefined) { await this.stop(); throw new Error("hub listener did not report a port"); }
    return this.address;
  }
  async stop(): Promise<void> {
    for (const client of this.clients) client.socket.destroy();
    this.clients.clear();
    this.routes.clear();
    const server = this.server; this.server = undefined; this.actualPort = undefined;
    if (server) await new Promise<void>((resolve) => server.close(() => resolve()));
    await this.stateStore.update((state) => ({ ...state, machines: state.machines.map((machine) => ({ ...machine, presence: "offline" })) }));
  }
  async startPairing(roles: PairingRoles = { machine: ["edge"], hub: ["hub"] }): Promise<HubPairingStart> {
    this.stateCache = await this.stateStore.load();
    const start = startHubPairing({ identity: this.identity, roles, isDuplicateIdentity: (principalId) => this.hasMachine(principalId) });
    this.pairing = start;
    return start;
  }
  pairingCode(): string | undefined { return this.pairing?.code; }
  confirmPairingMachineFingerprint(fingerprint: string): void { this.confirmedMachineFingerprint = fingerprint; }
  async respondPairing(hello: MachineHello, confirmedMachineFingerprint: string): Promise<HubResponse> {
    if (!this.pairing) throw new Error("hub pairing ceremony has not started");
    return this.pairing.ceremony.respond(hello, confirmedMachineFingerprint);
  }
  async completePairing(response: HubResponse, confirmation: MachineConfirmation, alias?: string): Promise<HubPairingResult> {
    if (!this.pairing) throw new Error("hub pairing ceremony has not started");
    try {
      const result = this.pairing.ceremony.complete(response, confirmation);
      await this.enrollMachine(result.pairing, alias);
      this.pairing = undefined;
      this.confirmedMachineFingerprint = undefined;
      return result;
    } catch (error) {
      this.pairing = undefined;
      this.confirmedMachineFingerprint = undefined;
      throw error;
    }
  }
  async enrollMachine(pairing: PinnedPeerKeyset, alias = pairing.pinnedPeerKey.principalId): Promise<HubMachineRecord> {
    if (!validAlias(alias)) throw new TypeError("machine alias must be 1..128 characters");
    const peer = { principalId: pairing.pinnedPeerKey.principalId, publicKeySpki: pairing.pinnedPeerKey.publicKeySpki, fingerprint: pairing.pinnedPeerKey.fingerprint };
    if (peer.fingerprint !== fingerprintSpki(peer.publicKeySpki) || peer.principalId !== peer.fingerprint) throw new TypeError("invalid machine key");
    const normalizedPairing: PinnedPeerKeyset = { ...pairing, pinnedPeerKey: peer };
    const record: HubMachineRecord = { alias, principalId: peer.principalId, publicKeySpki: peer.publicKeySpki, fingerprint: peer.fingerprint, pairing: clone(normalizedPairing), presence: "offline", lastSeen: null };
    await this.stateStore.update((state) => ({ ...state, machines: [...state.machines.filter((machine) => machine.principalId !== peer.principalId), record] }));
    this.stateCache = await this.stateStore.load();
    return clone(record);
  }
  hasMachine(principalId: string): boolean { return this.stateStoreSnapshot().some((machine) => machine.principalId === principalId); }
  private stateCache?: HubState;
  private stateStoreSnapshot(): HubMachineRecord[] { return this.stateCache?.machines ?? []; }
  async forgetMachine(principalId: string): Promise<void> {
    for (const client of this.clients) if (client.machineId === principalId) { client.machineId = undefined; client.socket.destroy(); }
    this.forgetRoutes(principalId);
    await this.stateStore.update((state) => ({ ...state, machines: state.machines.filter((machine) => machine.principalId !== principalId), endpoints: state.endpoints.filter((endpoint) => endpoint.machineId !== principalId), enrollments: state.enrollments.filter((statement) => statement.machineId !== principalId) }));
    this.stateCache = await this.stateStore.load();
  }
  async setPresence(principalId: string, presence: HubPresence): Promise<void> { await this.stateStore.update((state) => ({ ...state, machines: state.machines.map((machine) => machine.principalId === principalId ? { ...machine, presence, lastSeen: Date.now() } : machine) })); this.stateCache = await this.stateStore.load(); }
  async putEndpoint(endpoint: HubEndpointRecord): Promise<void> {
    if (!endpoint.machineId || !endpoint.endpointId) throw new TypeError("endpoint requires machineId and endpointId");
    await this.stateStore.update((state) => ({ ...state, endpoints: [...state.endpoints.filter((item) => item.machineId !== endpoint.machineId || item.endpointId !== endpoint.endpointId), clone(endpoint)] }));
  }
  async setEndpointEnabled(machineId: string, endpointId: string, enabled: boolean): Promise<void> { await this.stateStore.update((state) => ({ ...state, endpoints: state.endpoints.map((item) => item.machineId === machineId && item.endpointId === endpointId ? { ...item, enabled } : item) })); }
  async putEnrollment(statement: EnrollmentStatement): Promise<void> {
    const state = await this.stateStore.load();
    const machine = state.machines.find((item) => item.principalId === statement.machineId);
    if (!machine || !verifyEnrollmentStatement(statement, machine.publicKeySpki)) throw new TypeError("invalid signed enrollment statement");
    await this.stateStore.update((current) => ({ ...current, enrollments: [...current.enrollments.filter((item) => item.machineId !== statement.machineId || item.endpointId !== statement.endpointId || item.profileName !== statement.profileName), clone(statement)] }));
  }
  async enrollments(machineId?: string): Promise<EnrollmentStatement[]> { return clone((await this.stateStore.load()).enrollments.filter((statement) => machineId === undefined || statement.machineId === machineId)); }
  async directory(machineId?: string): Promise<HubEndpointRecord[]> { const state = await this.stateStore.load(); return clone(state.endpoints.filter((endpoint) => endpoint.enabled && (machineId === undefined || endpoint.machineId === machineId))); }
  async status(): Promise<HubStatus> { const state = await this.stateStore.load(); return { identityFingerprint: fingerprintSpki(this.identity.publicKeySpki), listenAddress: this.address?.address ?? "disabled", machines: clone(state.machines), connectors: [...state.connectors] }; }
  private sendControl(client: HubClient, message: Record<string, unknown>): void { client.socket.write(encodeHubFrame(Buffer.from(JSON.stringify(message), "utf8"), this.maxFrameBytes)); }

  private async routeOpaqueFrame(client: HubClient, frame: Buffer, envelope: HubOpaqueRouteEnvelope): Promise<void> {
    if (!client.machineId) throw new Error("unpaired hub connection cannot route");
    if (envelope.direction === "request") {
      const endpoint = (await this.stateStore.load()).endpoints.find((item) => item.machineId === envelope.address.machineId && item.endpointId === envelope.address.endpointId && item.enabled);
      const target = endpoint ? [...this.clients].find((item) => item.machineId === endpoint.machineId) : undefined;
      if (!endpoint || !target) throw new Error("routed endpoint is unavailable");
      const existing = this.routes.get(envelope.routeId);
      const route = { sourceMachineId: client.machineId, targetMachineId: endpoint.machineId, streamId: envelope.streamId, address: envelope.address };
      if (existing && (existing.sourceMachineId !== route.sourceMachineId || existing.targetMachineId !== route.targetMachineId || existing.streamId !== route.streamId || JSON.stringify(existing.address) !== JSON.stringify(route.address))) throw new Error("route ID is already bound to another stream");
      if (!existing && this.routes.size >= HUB_MAX_ACTIVE_ROUTES) throw new Error("hub route capacity reached");
      if (!existing) this.routes.set(envelope.routeId, route);
      target.socket.write(encodeHubFrame(frame, this.maxFrameBytes));
      return;
    }
    if (envelope.direction === "close") {
      const route = this.routes.get(envelope.routeId);
      if (!route || envelope.streamId !== route.streamId || JSON.stringify(envelope.address) !== JSON.stringify(route.address) || (client.machineId !== route.sourceMachineId && client.machineId !== route.targetMachineId)) throw new Error("unknown routed close");
      const targetMachineId = client.machineId === route.sourceMachineId ? route.targetMachineId : route.sourceMachineId;
      const target = [...this.clients].find((item) => item.machineId === targetMachineId);
      this.routes.delete(envelope.routeId);
      if (target) target.socket.write(encodeHubFrame(frame, this.maxFrameBytes));
      return;
    }
    const route = this.routes.get(envelope.routeId);
    if (!route || client.machineId !== route.targetMachineId || envelope.streamId !== route.streamId || JSON.stringify(envelope.address) !== JSON.stringify(route.address)) throw new Error("unknown routed response");
    const target = [...this.clients].find((item) => item.machineId === route.sourceMachineId);
    if (!target) throw new Error("routed requester is unavailable");
    target.socket.write(encodeHubFrame(frame, this.maxFrameBytes));
  }
  private forgetRoutes(machineId: string): void {
    for (const [routeId, route] of this.routes) if (route.sourceMachineId === machineId || route.targetMachineId === machineId) this.routes.delete(routeId);
  }


  private async handleFrame(client: HubClient, frame: Buffer, peerFingerprintValue: string | undefined): Promise<void> {
    const routed = parseHubOpaqueRoute(frame);
    if (routed) { await this.routeOpaqueFrame(client, frame, routed); return; }
    let message: Record<string, unknown>;
    try { message = JSON.parse(frame.toString("utf8")) as Record<string, unknown>; } catch { message = {}; }
    const type = typeof message.type === "string" ? message.type : "";
    if (type === HUB_OPAQUE_ROUTE_TYPE) throw new Error("invalid opaque route envelope");
    if (!client.machineId) {
      if (type === "pairInvitationRequest" && this.pairing) {
        this.sendControl(client, { type: "pairInvitation", invitation: this.pairing.invitation });
        return;
      }
      if (type === "pairHello" && this.pairing && this.confirmedMachineFingerprint && message.hello && typeof message.hello === "object") {
        const hello = message.hello as MachineHello;
        if (peerFingerprintValue !== hello.machine.fingerprint) throw new Error("pairing certificate does not match machine key");
        const response = await this.respondPairing(hello, this.confirmedMachineFingerprint);
        client.pairResponse = response; client.pairMachineId = hello.machine.principalId;
        this.sendControl(client, { type: "pairResponse", response });
        return;
      }
      if (type === "pairConfirmation" && this.pairing && client.pairResponse && client.pairMachineId && message.confirmation && typeof message.confirmation === "object") {
        const result = await this.completePairing(client.pairResponse, message.confirmation as MachineConfirmation);
        client.machineId = result.pairing.pinnedPeerKey.principalId;
        this.sendControl(client, { type: "pairComplete", pairing: result.pairing });
        return;
      }
      throw new Error("unpaired hub connection sent an invalid control frame");
    }
    if (type === "directoryRequest") {
      this.sendControl(client, { type: "directoryResponse", endpoints: await this.directory(client.machineId) });
      return;
    }
    if (type === "presence" && message.machineId === client.machineId && Array.isArray(message.endpoints)) {
      const incoming = new Set(message.endpoints.flatMap((endpoint) => endpoint && typeof endpoint === "object" && typeof (endpoint as Record<string, unknown>).endpointId === "string" ? [(endpoint as Record<string, unknown>).endpointId as string] : []));
      await this.stateStore.update((state) => ({ ...state, endpoints: state.endpoints.filter((endpoint) => endpoint.machineId !== client.machineId || incoming.has(endpoint.endpointId)) }));
      for (const endpoint of message.endpoints) if (endpoint && typeof endpoint === "object") await this.putEndpoint({ ...(endpoint as HubEndpointRecord), machineId: client.machineId });
      this.sendControl(client, { type: "presenceAck" });
      return;
    }
    if (type === "enrollmentStatement" && message.statement && isEnrollmentStatement(message.statement) && message.statement.machineId === client.machineId) {
      await this.putEnrollment(message.statement);
      return;
    }
    throw new Error("paired hub connection sent an invalid control frame");
  }
  private async accept(socket: TLSSocket): Promise<void> {
    const client: HubClient = { socket, decoder: new HubFrameDecoder(this.maxFrameBytes) }; this.clients.add(client);
    const fingerprint = peerFingerprint(socket);
    const state = await this.stateStore.load();
    const machine = fingerprint ? state.machines.find((item) => item.fingerprint === fingerprint) : undefined;
    if (machine) { client.machineId = machine.principalId; await this.setPresence(machine.principalId, "online"); }
    const onData = (chunk: Buffer) => {
      try {
        const frames = client.decoder.feed(chunk);
        for (const frame of frames) void this.handleFrame(client, frame, fingerprint).catch(() => socket.destroy());
      } catch { socket.destroy(); }
    };
    socket.on("data", onData);
    socket.on("close", () => { this.clients.delete(client); if (client.machineId) { this.forgetRoutes(client.machineId); void this.setPresence(client.machineId, "offline"); } });
    socket.on("error", () => socket.destroy());
  }
}

export function clientTlsOptions(pairing: PinnedPeerKeyset, identity: StoredIdentity, _hubCertificatePem: string): Omit<TlsPinningOptions, "rejectUnauthorized"> & { rejectUnauthorized: false; key: string; cert: string } {
  const certificate = selfSignedCertificate(identity, "atb machine");
  return { ...pinnedTlsOptions(pairing), rejectUnauthorized: false, key: certificate.keyPem, cert: certificate.certPem };
}

export function formatHubStatus(status: HubStatus): string {
  const rows = [`identity fingerprint\t${status.identityFingerprint}`, `listen address\t${status.listenAddress}`];
  for (const machine of status.machines) {
    rows.push(`machine alias\t${JSON.stringify(machine.alias)}`, `machine fingerprint\t${machine.fingerprint}`, `machine presence\t${machine.presence}`);
  }
  rows.push(`connectors admitted\t${status.connectors.length}`);
  return `${rows.join("\n")}\n`;
}

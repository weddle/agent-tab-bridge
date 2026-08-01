import { X509Certificate } from "node:crypto";
import { rm } from "node:fs/promises";
import { isIP } from "node:net";
import { connect, type ConnectionOptions, type TLSSocket } from "node:tls";
import { applicationSupportPath, atomicWritePrivateJson, readPrivateJson, CompanionStateStore, type ApplicationSupportOptions } from "../state.js";
import { fingerprintSpki, IdentityStore, type StoredIdentity } from "../identity.js";
import { MachinePairingCeremony, type HubResponse, type MachineConfirmation, type MachineHello, type PairingInvitation, type PinnedPeerKeyset } from "./index.js";
import { clientTlsOptions } from "../../hub/service.js";
import { selfSignedCertificate } from "../../hub/certificate.js";
import { encodeHubFrame, HubFrameDecoder } from "../../hub/framing.js";
import { HubRouteConnection, type HubRouteHandler } from "./routes.js";
import type { EnrollmentStatement } from "../enrollment-statement.js";

export const EDGE_HUB_STATE_VERSION = 1 as const;
export interface EdgeHubState { version: typeof EDGE_HUB_STATE_VERSION; address: string; pairing: PinnedPeerKeyset; hubCertificatePem: string; enabledEndpointIds: string[]; }
export interface HubAddress { host: string; port: number; }
export interface EdgePairingResult { pairing: PinnedPeerKeyset; address: string; code: string; }

function clone<T>(value: T): T { return structuredClone(value); }
function validState(value: unknown): value is EdgeHubState {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const item = value as Record<string, unknown>;
  return item.version === EDGE_HUB_STATE_VERSION && typeof item.address === "string" && item.address.length > 0 && typeof item.pairing === "object" && !!item.pairing && typeof item.hubCertificatePem === "string" && Array.isArray(item.enabledEndpointIds) && item.enabledEndpointIds.every((id) => typeof id === "string");
}
export function parseHubAddress(value: string): HubAddress {
  const match = /^\[?([^\]]+)\]?:([0-9]+)$/.exec(value.trim());
  if (!match) throw new Error("hub address must be host:port");
  const port = Number(match[2]);
  if (!Number.isSafeInteger(port) || port < 1 || port > 65535) throw new Error("hub address port must be 1..65535");
  return { host: match[1]!, port };
}
export class EdgeHubPairingStore {
  readonly filePath: string;
  private state?: EdgeHubState;
  constructor(options: ApplicationSupportOptions & { fileName?: string } = {}) { this.filePath = applicationSupportPath(options.fileName ?? "hub-pairing.json", options); }
  async load(): Promise<EdgeHubState | undefined> {
    if (this.state) return clone(this.state);
    const value = await readPrivateJson<unknown>(this.filePath);
    if (value === undefined) return undefined;
    if (!validState(value)) throw new Error("invalid hub pairing state");
    this.state = clone(value); return clone(value);
  }
  async save(state: EdgeHubState): Promise<void> { if (!validState(state)) throw new TypeError("invalid hub pairing state"); await atomicWritePrivateJson(this.filePath, state); this.state = clone(state); }
  async forget(): Promise<void> { this.state = undefined; await rm(this.filePath, { force: true }); }
  async setEndpointEnabled(endpointId: string, enabled: boolean): Promise<EdgeHubState | undefined> {
    const state = await this.load(); if (!state) return undefined;
    const ids = new Set(state.enabledEndpointIds); if (enabled) ids.add(endpointId); else ids.delete(endpointId);
    const next = { ...state, enabledEndpointIds: [...ids].sort() }; await this.save(next); return next;
  }
}

function pemFromDer(der: Uint8Array): string { const body = Buffer.from(der).toString("base64").match(/.{1,64}/g)?.join("\n") ?? ""; return `-----BEGIN CERTIFICATE-----\n${body}\n-----END CERTIFICATE-----\n`; }
function peerFingerprint(socket: TLSSocket): { fingerprint: string; certificatePem: string } {
  const peer = socket.getPeerCertificate(true); if (!peer.raw) throw new Error("hub did not present a certificate");
  const spki = new X509Certificate(peer.raw).publicKey.export({ type: "spki", format: "der" });
  return { fingerprint: fingerprintSpki(spki), certificatePem: pemFromDer(peer.raw) };
}
async function connectSocket(options: ConnectionOptions): Promise<TLSSocket> {
  return await new Promise<TLSSocket>((resolve, reject) => { const socket = connect(options); socket.once("secureConnect", () => resolve(socket)); socket.once("error", (error) => { socket.destroy(); reject(error); }); });
}
async function control(socket: TLSSocket, decoder: HubFrameDecoder, message: unknown): Promise<Record<string, unknown>> {
  socket.write(encodeHubFrame(Buffer.from(JSON.stringify(message), "utf8"), decoder.maxFrameBytes));
  return await new Promise<Record<string, unknown>>((resolve, reject) => {
    const onData = (chunk: Buffer) => { try { const frames = decoder.feed(chunk); if (!frames.length) return; socket.off("data", onData); socket.off("error", onError); resolve(JSON.parse(frames[0]!.toString("utf8")) as Record<string, unknown>); } catch (error) { socket.off("data", onData); reject(error); } };
    const onError = (error: Error) => { socket.off("data", onData); reject(error); };
    socket.on("data", onData); socket.once("error", onError);
  });
}

export class EdgeHubPairingClient {
  readonly store: EdgeHubPairingStore;
  constructor(private readonly options: ApplicationSupportOptions & { stateStore?: CompanionStateStore; identityStore?: IdentityStore; maxFrameBytes?: number } = {}) { this.store = new EdgeHubPairingStore(options); }
  private presenceSocket?: TLSSocket;
  private routes?: HubRouteConnection;
  async pair(addressValue: string, code: string, confirmedHubFingerprint: string): Promise<EdgePairingResult> {
    if (!code || !/^\d{6}$/.test(code)) throw new Error("pairing code must be a 6-digit operator-supplied code");
    const address = parseHubAddress(addressValue);
    const identity = await (this.options.identityStore ?? new IdentityStore("companion", this.options)).loadOrCreate();
    const certificate = selfSignedCertificate(identity, "atb machine");
    const socket = await connectSocket({ host: address.host, port: address.port, rejectUnauthorized: false, minVersion: "TLSv1.3", maxVersion: "TLSv1.3", key: certificate.keyPem, cert: certificate.certPem });
    const decoder = new HubFrameDecoder(this.options.maxFrameBytes); const invitationMessage = await control(socket, decoder, { type: "pairInvitationRequest" });
    if (invitationMessage.type !== "pairInvitation" || !invitationMessage.invitation) throw new Error("hub did not return a pairing invitation");
    const invitation = invitationMessage.invitation as PairingInvitation; const peer = peerFingerprint(socket);
    if (peer.fingerprint !== invitation.hub.fingerprint || confirmedHubFingerprint !== invitation.hub.fingerprint) throw new Error("hub fingerprint confirmation did not match");
    const ceremony = new MachinePairingCeremony({ identity, invitation, code, confirmedHubFingerprint });
    const hello = ceremony.createHello(); const responseMessage = await control(socket, decoder, { type: "pairHello", hello });
    if (responseMessage.type !== "pairResponse" || !responseMessage.response) throw new Error("hub did not return a pairing response");
    const response = responseMessage.response as HubResponse; const result = ceremony.complete(response);
    const completeMessage = await control(socket, decoder, { type: "pairConfirmation", confirmation: result.confirmation });
    if (completeMessage.type !== "pairComplete") throw new Error("hub did not confirm pairing");
    await this.store.save({ version: EDGE_HUB_STATE_VERSION, address: addressValue, pairing: result.pairing, hubCertificatePem: peer.certificatePem, enabledEndpointIds: [] });
    socket.destroy(); return { pairing: result.pairing, address: addressValue, code };
  }
  async pushPresence(socket: TLSSocket): Promise<void> {
    const state = await this.store.load(); if (!state) return;
    const companion = await (this.options.stateStore ?? new CompanionStateStore(this.options)).load();
    const identity = await (this.options.identityStore ?? new IdentityStore("companion", this.options)).loadOrCreate();
    const enabled = new Set(state.enabledEndpointIds);
    const endpoints = companion.endpoints.filter((endpoint) => enabled.has(endpoint.identity.endpointId)).map((endpoint) => ({ machineId: companion.machine.identity.machineId, endpointId: endpoint.identity.endpointId, alias: endpoint.identity.label, fingerprint: endpoint.identity.endpointId, enabled: true, record: { extensionId: endpoint.identity.extensionId, label: endpoint.identity.label, publicKeySpki: endpoint.identity.publicKeySpki, machinePublicKeySpki: identity.publicKeySpki } }));
    const response = await control(socket, new HubFrameDecoder(this.options.maxFrameBytes), { type: "presence", machineId: companion.machine.identity.machineId, endpoints });
    if (response.type !== "presenceAck") throw new Error("hub did not acknowledge presence");
  }
  async connectPresence(addressValue?: string): Promise<TLSSocket | undefined> {
    const state = await this.store.load(); if (!state) return undefined;
    const identity = await (this.options.identityStore ?? new IdentityStore("companion", this.options)).loadOrCreate();
    const address = parseHubAddress(addressValue ?? state.address);
    const tls = clientTlsOptions(state.pairing, identity, state.hubCertificatePem);
    const socket = await connectSocket({ ...tls, host: address.host, port: address.port, ...(isIP(address.host) === 0 ? { servername: address.host } : {}) });
    this.presenceSocket = socket;
    socket.once("close", () => { if (this.presenceSocket === socket) this.presenceSocket = undefined; });
    await this.pushPresence(socket);
    return socket;
  }
  async pushEnrollment(statement: EnrollmentStatement): Promise<void> {
    const socket = this.presenceSocket ?? await this.connectPresence();
    if (!socket) return;
    socket.write(encodeHubFrame(Buffer.from(JSON.stringify({ type: "enrollmentStatement", statement }), "utf8"), this.options.maxFrameBytes));
  }
  async connectRoutes(onRequest: HubRouteHandler, addressValue?: string): Promise<HubRouteConnection | undefined> {
    const socket = await this.connectPresence(addressValue);
    if (!socket) return undefined;
    this.routes?.close();
    const routes = new HubRouteConnection(socket, onRequest, this.options.maxFrameBytes);
    this.routes = routes;
    socket.once("close", () => { if (this.routes === routes) this.routes = undefined; });
    return routes;
  }
  async unpair(): Promise<void> { this.routes?.close(); this.routes = undefined; this.presenceSocket?.destroy(); this.presenceSocket = undefined; await this.store.forget(); }
  async directory(addressValue?: string): Promise<ReadonlyArray<{ machineId: string; endpointId: string; alias?: string; fingerprint?: string; enabled: boolean; record: unknown }>> {
    const socket = this.presenceSocket ?? await this.connectPresence(addressValue);
    if (!socket) return [];
    const response = await control(socket, new HubFrameDecoder(this.options.maxFrameBytes), { type: "directoryRequest" });
    if (response.type !== "directoryResponse" || !Array.isArray(response.endpoints)) throw new Error("hub did not return an endpoint directory");
    return response.endpoints as ReadonlyArray<{ machineId: string; endpointId: string; alias?: string; fingerprint?: string; enabled: boolean; record: unknown }>;
  }
}

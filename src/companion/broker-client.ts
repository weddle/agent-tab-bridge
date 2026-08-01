 import net from "node:net";
 import type { Duplex } from "node:stream";
 import { defaultBrokerSocketPath, type BrokerRouteContext } from "./broker.js";
 import { signTranscript, verifyTranscript } from "./identity.js";
 import { canonicalAuthV2Transcript, createAuthV2EphemeralPublicKey, createAuthV2Nonce, isAuthV2Transcript, type AuthV2RequestedAuthority } from "./auth-v2.js";
 import { loadProfile } from "./profiles.js";
 import { normalizeSessionAccess, type SessionAccess } from "./session-access.js";
 import { CompanionStateStore } from "./state.js";
 import type { HubRouteStream } from "./pairing/routes.js";
 import type { BrokerEvent } from "../atb.js";
 import { initiateChannel } from "./channel/index.js";
 import { routedChannelContext } from "./channel/context.js";
 import { SecureChannelTransportAdapter } from "./transport-adapter.js";

export async function createCompanionBrokerClient(options: { directory?: string; profile?: string; socketPath?: string } = {}) {
  const socketPath = options.socketPath ?? defaultBrokerSocketPath({ directory: options.directory });
  if (options.profile !== undefined) {
    const record = await loadProfile(options.profile, { directory: options.directory });
    return createBrokerClient({ socketPath, profile: { name: record.name, principalId: record.principalId, publicKeySpki: record.publicKeySpki, privateKeyPkcs8: record.privateKeyPkcs8 } });
  }
  const state = await new CompanionStateStore({ directory: options.directory }).load();
  if (!state.machine.brokerSecret) throw new Error("companion is not installed");
  return createBrokerClient({ socketPath, token: state.machine.brokerSecret });
}

export type BrokerClientOptions = { socketPath: string; token?: string; profile?: { name: string; principalId: string; publicKeySpki: string; privateKeyPkcs8: string }; route?: Pick<BrokerRouteContext, "hubId" | "routeId" | "streamId" | "address">; socketFactory?: () => net.Socket | Duplex };
type Pending = { resolve: (value: unknown) => void; reject: (error: Error) => void };

/** Newline-delimited broker client. Authentication precedes every command stream. */
export function createBrokerClient(options: BrokerClientOptions) {
  if (options.token === undefined && options.profile === undefined) throw new Error("broker client requires a token or a profile");
  const socket = options.socketFactory?.() ?? net.createConnection(options.socketPath);
  let buffer = "";
  let closed = false;
  let nextId = 1;
  let authDone = false;
  let resolveAuth: (() => void) | undefined;
  let rejectAuth: ((error: Error) => void) | undefined;
  const pending = new Map<string, Pending>();
  const listeners = new Set<(event: BrokerEvent) => void>();
  let connected = false;
  let profileAttempt: { authority: AuthV2RequestedAuthority; controllerNonce: string; controllerEphemeralPublicKey: string } | undefined;
  const authenticated = new Promise<void>((resolve, reject) => { resolveAuth = resolve; rejectAuth = reject; });
  const failPending = (error: Error) => {
    for (const request of pending.values()) request.reject(error);
    pending.clear();
    rejectAuth?.(error);
  };
  const requestedAuthority = (command: string, params: Record<string, unknown>): AuthV2RequestedAuthority => {
    let scope: SessionAccess | null = null;
    if (command === "openSession") {
      try { scope = normalizeSessionAccess(params.access as SessionAccess | undefined); } catch { /* server rejects malformed command data */ }
    }
    return { scope, ttlMs: command === "openSession" && Number.isSafeInteger(params.ttlMs) && (params.ttlMs as number) > 0 ? params.ttlMs as number : null, stableSessionKey: typeof params.stableSessionKey === "string" ? params.stableSessionKey : null };
  };
  const startProfileAuth = (command: string, params: Record<string, unknown>) => {
    if (!options.profile || profileAttempt) return;
    profileAttempt = { authority: requestedAuthority(command, params), controllerNonce: createAuthV2Nonce(), controllerEphemeralPublicKey: createAuthV2EphemeralPublicKey() };
    if (connected) socket.write(`${JSON.stringify({ type: "authHello", profile: options.profile.name, ...profileAttempt })}\n`);
  };
  const handleLine = (line: string) => {
    if (!line) return;
    let message: Record<string, unknown>;
    try { message = JSON.parse(line) as Record<string, unknown>; } catch { return; }
    if (!authDone) {
      if (message.type === "authOk") {
        authDone = true;
        resolveAuth?.();
      } else if (message.type === "authChallenge" && options.profile && profileAttempt && isAuthV2Transcript(message.transcript) && typeof message.signature === "string") {
        const transcript = message.transcript;
        const validChallenge = transcript.controller.principalId === options.profile.principalId
          && transcript.controller.publicKeySpki === options.profile.publicKeySpki
          && transcript.controllerNonce === profileAttempt.controllerNonce
          && transcript.controllerEphemeralPublicKey === profileAttempt.controllerEphemeralPublicKey
          && transcript.expiresAt >= Date.now()
          && JSON.stringify(transcript.authority) === JSON.stringify(profileAttempt.authority)
          && (options.route === undefined || (transcript.edge.machineId === options.route.address.machineId && transcript.endpointId === options.route.address.endpointId && transcript.hubId === options.route.hubId && transcript.routeId === options.route.routeId && transcript.streamId === options.route.streamId))
          && verifyTranscript(transcript.edge.publicKeySpki, canonicalAuthV2Transcript(transcript), message.signature);
        if (!validChallenge) {
          rejectAuth?.(new Error("broker authentication failed"));
        } else {
          socket.write(`${JSON.stringify({ type: "authProof", transcript, signature: signTranscript(options.profile.privateKeyPkcs8, canonicalAuthV2Transcript(transcript)) })}\n`);
        }
      } else if (message.type === "error") {
        rejectAuth?.(new Error(message.error && typeof message.error === "object" && typeof (message.error as Record<string, unknown>).message === "string" ? String((message.error as Record<string, unknown>).message) : "broker authentication failed"));
      }
      return;
    }
    const value = message.id ?? message.requestId;
    const id = typeof value === "string" ? value : undefined;
    if (id && pending.has(id)) {
      const request = pending.get(id)!;
      pending.delete(id);
      if (message.ok === false || message.type === "error") {
        const error = message.error;
        request.reject(new Error(error && typeof error === "object" && typeof (error as Record<string, unknown>).message === "string" ? String((error as Record<string, unknown>).message) : "broker request failed"));
      } else request.resolve(message.result ?? message);
      return;
    }
    if (typeof message.event === "string") for (const listener of listeners) listener(message as BrokerEvent);
  };
  socket.on("connect", () => {
    connected = true;
    if (options.token !== undefined) socket.write(`${JSON.stringify({ type: "auth", token: options.token })}\n`);
    else if (options.profile && profileAttempt) socket.write(`${JSON.stringify({ type: "authHello", profile: options.profile.name, ...profileAttempt })}\n`);
  });
  socket.on("data", (chunk: Buffer | string) => {
    buffer += chunk.toString();
    for (;;) {
      const newline = buffer.indexOf("\n");
      if (newline < 0) break;
      const line = buffer.slice(0, newline);
      buffer = buffer.slice(newline + 1);
      handleLine(line);
    }
  });
  socket.on("error", (error) => failPending(error));
  socket.on("close", () => {
    closed = true;
    const error = new Error("broker connection closed");
    failPending(error);
    for (const listener of listeners) listener({ event: "hostClosing" });
  });
  return {
    async request(command: string, params: Record<string, unknown> = {}): Promise<unknown> {
      if (closed) throw new Error("broker connection closed");
      if (options.profile) startProfileAuth(command, params);
      await authenticated;
      const id = String(nextId++);
      const message = { id, command, ...params };
      return new Promise((resolve, reject) => {
        pending.set(id, { resolve, reject });
        socket.write(`${JSON.stringify(message)}\n`, (error) => {
          if (error) { pending.delete(id); reject(error); }
        });
      });
    },
    onEvent(listener: (event: BrokerEvent) => void): () => void { listeners.add(listener); return () => listeners.delete(listener); },
    async close(): Promise<void> {
      if (closed) return;
      socket.end();
      const transport: unknown = socket;
      if (transport && typeof transport === "object" && "destroy" in transport && typeof transport.destroy === "function") transport.destroy();
    },
  };
}
export async function createSecureRoutedTransport(options: Readonly<{ stream: HubRouteStream; profile: NonNullable<BrokerClientOptions["profile"]>; route: NonNullable<BrokerClientOptions["route"]>; targetPublicKeySpki: string }>): Promise<SecureChannelTransportAdapter> {
  const identity = { version: 1 as const, kind: "controller" as const, principalId: options.profile.principalId, publicKeySpki: options.profile.publicKeySpki, privateKeyPkcs8: options.profile.privateKeyPkcs8, createdAt: Date.now() };
  const initiated = initiateChannel({ identity, peerPublicKeySpki: options.targetPublicKeySpki, sessionId: options.route.address.stableSessionKey, context: routedChannelContext(options.route.address, options.stream.routeId, options.stream.streamId) });
  let done = false;
  const { promise, resolve, reject } = Promise.withResolvers<SecureChannelTransportAdapter>();
  const timer = setTimeout(() => { if (!done) { done = true; off(); options.stream.close(); reject(new Error("secure routed channel handshake timed out")); } }, 15_000);
  timer.unref?.();
  const off = options.stream.onPayload((payload) => {
    if (done) return;
    let message: Record<string, unknown>;
    try { message = JSON.parse(payload.toString("utf8")) as Record<string, unknown>; } catch { return; }
    if (message.type !== "channelAccept" || !message.value || typeof message.value !== "object") return;
    done = true; clearTimeout(timer); off();
    try {
      const completed = initiated.complete(message.value as never);
      options.stream.send(Buffer.from(JSON.stringify({ type: "channelConfirm", value: completed.confirm }), "utf8"));
      const secure = new SecureChannelTransportAdapter(completed.channel, (frame) => { options.stream.send(frame); });
      options.stream.onPayload((frame) => secure.receive(frame));
      resolve(secure);
    } catch (error) { options.stream.close(); reject(error instanceof Error ? error : new Error(String(error))); }
  });
  options.stream.onClose(() => { if (!done) { done = true; clearTimeout(timer); off(); reject(new Error("secure routed broker channel closed during handshake")); } });
  options.stream.send(Buffer.from(JSON.stringify({ type: "channelHello", profileName: options.profile.name, publicKeySpki: options.profile.publicKeySpki, value: initiated.hello }), "utf8"));
  return await promise;
}

export async function createRoutedBrokerClient(options: Readonly<{ stream: HubRouteStream; profile: NonNullable<BrokerClientOptions["profile"]>; route: NonNullable<BrokerClientOptions["route"]>; targetPublicKeySpki: string }>) {
  const transport = await createSecureRoutedTransport(options);
  const client = createBrokerClient({ socketPath: "hub-routed", profile: options.profile, route: options.route, socketFactory: () => transport });
  queueMicrotask(() => transport.emit("connect"));
  return client;
}

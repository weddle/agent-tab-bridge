import net from "node:net";
import { defaultBrokerSocketPath } from "./broker.js";
import { signTranscript, verifyTranscript } from "./identity.js";
import { canonicalAuthV2Transcript, createAuthV2EphemeralPublicKey, createAuthV2Nonce, isAuthV2Transcript, type AuthV2RequestedAuthority } from "./auth-v2.js";
import { loadProfile } from "./profiles.js";
import { normalizeSessionAccess, type SessionAccess } from "./session-access.js";
import { CompanionStateStore } from "./state.js";
import type { BrokerEvent } from "../atb.js";

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

export type BrokerClientOptions = { socketPath: string; token?: string; profile?: { name: string; principalId: string; publicKeySpki: string; privateKeyPkcs8: string }; socketFactory?: () => net.Socket };
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

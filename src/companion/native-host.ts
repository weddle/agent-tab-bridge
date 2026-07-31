import { type Readable, type Writable } from "node:stream";
import { startAgentTabRelay } from "../../extensions/browser/src/browser/extension-relay/relay-server.js";
import { BrokerServer, startBrokerServer } from "./broker.js";
import { deriveControllerPrincipalId, HostIdentityHandshake, IdentityStore, createBrokerSecret } from "./identity.js";
import { NativeMessageDecoder, writeNativeFrame } from "./native-framing.js";
import { NATIVE_PROTOCOL_VERSION, type ExtensionToHostMessage, type HostToExtensionMessage, type NativeMessage } from "./native-protocol.js";
import { CompanionStateStore } from "./state.js";
import { TaskSessionManager, type TaskSessionRelay } from "./task-sessions.js";

export const NATIVE_HOST_NAME = "com.agenttabbridge.companion";
export type NativeHostOptions = { input?: Readable; output?: Writable; stateStore?: CompanionStateStore; identityStore?: IdentityStore; startRelay?: () => Promise<TaskSessionRelay> };
class NativeOutputFailure extends Error { constructor(cause: unknown) { super(`native messaging output failed: ${cause instanceof Error ? cause.message : String(cause)}`); this.name = "NativeOutputFailure"; } }

export async function runNativeMessagingHost(options: NativeHostOptions = {}): Promise<void> {
  const input = options.input ?? process.stdin;
  const output = options.output ?? process.stdout;
  const stateStore = options.stateStore ?? new CompanionStateStore();
  const identityStore = options.identityStore ?? new IdentityStore("companion");
  const companion = await identityStore.loadOrCreate();
  const state = await stateStore.update(async (current) => ({ ...current, companionPrincipalId: companion.principalId, brokerSecret: current.brokerSecret || createBrokerSecret() }));
  const controllerPrincipalId = deriveControllerPrincipalId(state.brokerSecret);
  let trusted: { extensionId: string; fingerprint: string; principalId: string; displayName: string } | null = null;
  let broker: BrokerServer | null = null;
  let ending = false;
  let finishHost: () => void = () => {};
  let outputFailure: NativeOutputFailure | null = null;
  let outputTail = Promise.resolve();
  const send = (message: HostToExtensionMessage): Promise<void> => {
    const operation = outputTail.then(async () => { if (!ending) await writeNativeFrame(output, message); });
    const result = operation.catch((error) => { throw new NativeOutputFailure(error); });
    outputTail = result.catch((error) => { if (!outputFailure) { outputFailure = error; finishHost(); } });
    return result;
  };
  const sessions = new TaskSessionManager({ startRelay: options.startRelay ?? startAgentTabRelay, onEvent: (event) => {
    const session = { ...event.session, requestedCapabilities: [...event.session.requestedCapabilities] };
    if (event.type === "pending") { broker?.publish({ event: "pending", sessionId: session.id, session }); void send({ version: NATIVE_PROTOCOL_VERSION, type: "sessionPending", session }).catch(() => {}); }
    else if (event.type === "active") broker?.publish({ event: "active", sessionId: session.id, session, cdpUrl: event.cdpUrl });
    else { broker?.publish({ event: "revoked", sessionId: session.id, session, reason: event.reason }); void send({ version: NATIVE_PROTOCOL_VERSION, type: "sessionStopped", session, reason: event.reason }).catch(() => {}); }
  } });
  broker = await startBrokerServer({ token: state.brokerSecret, sessions, isTrusted: () => trusted !== null, controller: () => trusted ? { principalId: controllerPrincipalId, displayName: "Local controller" } : null, status: () => ({ companionPrincipalId: companion.principalId, controllerPrincipalId }) });
  const handshake = new HostIdentityHandshake(identityStore, stateStore);
  const decoder = new NativeMessageDecoder();
  const requestIds = new Set<string>();
  const stop = async () => {
    if (outputFailure) trusted = null;
    try { await sessions.revokeAll("hostClosing"); } finally { try { await broker?.close(); } catch {} }
  };
  const snapshot = async () => {
    const all = sessions.snapshot().map((session) => ({ ...session, requestedCapabilities: [...session.requestedCapabilities] }));
    await send({ version: NATIVE_PROTOCOL_VERSION, type: "snapshot", pending: all.filter(({ state }) => state === "pending"), active: all.filter(({ state }) => state === "active"), sharedTabs: [] });
  };
  await new Promise<void>((resolve) => {
    finishHost = () => { if (ending) return; ending = true; void outputTail.then(stop, stop).then(() => resolve(), () => resolve()); };
    const enqueue = (message: NativeMessage) => { queue = queue.then(async () => await handle(message as ExtensionToHostMessage)).catch((error) => { if (error instanceof NativeOutputFailure || error instanceof Error) finishHost(); }); };
    let queue = Promise.resolve();
    input.on("data", (chunk: Buffer) => {
      if (ending) return;
      try { for (const message of decoder.feed(chunk)) enqueue(message); } catch { finishHost(); }
    });
    input.once("end", () => { try { decoder.finish(); } catch {} finishHost(); });
    input.once("error", finishHost);
    async function handle(message: ExtensionToHostMessage): Promise<void> {
      if (message.requestId && (requestIds.has(message.requestId) || !requestIds.add(message.requestId))) return;
      try {
        if (message.type === "hello") { const challenge = await handshake.createChallenge(message); await send(message.requestId ? { ...challenge, requestId: message.requestId } : challenge); return; }
        if (message.type === "helloProof") { const pinned = await handshake.verifyProof(message); trusted = { extensionId: pinned.extensionId, fingerprint: pinned.fingerprint, principalId: pinned.fingerprint, displayName: pinned.extensionId }; await send({ version: NATIVE_PROTOCOL_VERSION, type: "trusted", companionPrincipalId: companion.principalId, extensionFingerprint: pinned.fingerprint, ...(message.requestId ? { requestId: message.requestId } : {}) }); await snapshot(); return; }
        if (!trusted) return;
        if (message.type === "revokeDevice") { const current = trusted; await sessions.revokeAll("deviceRevoked"); await stateStore.unpinExtension(current.extensionId, current.fingerprint); trusted = null; await outputTail; finishHost(); return; }
        if (message.type === "approveSession") { const session = sessions.get(message.sessionId); if (!session || session.state !== "pending" || session.controllerPrincipalId !== message.controllerPrincipalId || session.displayControllerName !== message.displayControllerName || session.taskLabel !== message.taskLabel || session.expiresAt !== message.expiresAt || session.requestedCapabilities.join(",") !== message.requestedCapabilities.join(",")) return; const approved = await sessions.approve(session.id); await send({ version: NATIVE_PROTOCOL_VERSION, type: "sessionStarted", session: { ...approved.session, requestedCapabilities: [...approved.session.requestedCapabilities] }, relayUrl: approved.pairingUrl, ...(message.requestId ? { requestId: message.requestId } : {}) }); return; }
        if (message.type === "revokeSession" && sessions.get(message.sessionId)) { await sessions.revoke(message.sessionId, message.reason ?? "browserRevoked"); return; }
        if (message.type === "relayReady") { sessions.relayReady(message.sessionId); await snapshot(); return; }
        if (message.type === "relayFailed" && sessions.get(message.sessionId)) await sessions.relayFailed(message.sessionId, "relayFailed");
      } catch (error) { if (error instanceof NativeOutputFailure) throw error; if (message.type === "helloProof" || message.type === "approveSession" || message.type === "revokeSession" || message.type === "relayReady" || message.type === "relayFailed") return; throw error; }
    }
  });
}

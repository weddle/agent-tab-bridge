import { randomInt, randomUUID, timingSafeEqual } from "node:crypto";
import { type Readable, type Writable } from "node:stream";
import { startAgentTabRelay } from "../../extensions/browser/src/browser/extension-relay/relay-server.js";
import { BrokerServer, startBrokerServer } from "./broker.js";
import { deriveControllerPrincipalId, fingerprintSpki, HostIdentityHandshake, IdentityStore, createBrokerSecret } from "./identity.js";
import { NativeMessageDecoder, writeNativeFrame } from "./native-framing.js";
import { NATIVE_PROTOCOL_VERSION, type AccessUpgradeRecord, type ExtensionToHostMessage, type HostToExtensionMessage, type NativeMessage, type SharedTabRecord } from "./native-protocol.js";
import { CompanionStateStore } from "./state.js";
import { TaskSessionError, TaskSessionManager, type TaskSessionRelay } from "./task-sessions.js";
import { sameSessionAccess, type SessionAccessDelta } from "./session-access.js";

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
  let nextTabRequestId = 0;
  const pendingTabRequests = new Map<string, { resolve: (tabs: SharedTabRecord[]) => void; reject: (error: Error) => void; timer: NodeJS.Timeout }>();
  const pendingClaimRequests = new Map<string, { resolve: (tab: SharedTabRecord) => void; reject: (error: Error) => void; timer: NodeJS.Timeout }>();
  const pendingAccess = new Map<string, AccessUpgradeRecord>();
  const pendingAccessBySession = new Map<string, string>();
  const pendingEnrollments = new Map<string, { profileName: string; publicKeySpki: string; fingerprint: string; code: string; expiresAt: number; attempts: number; timer: NodeJS.Timeout }>();
  let outputTail = Promise.resolve();
  const send = (message: HostToExtensionMessage): Promise<void> => {
    const operation = outputTail.then(async () => { if (!ending) await writeNativeFrame(output, message); });
    const result = operation.catch((error) => { throw new NativeOutputFailure(error); });
    outputTail = result.catch((error) => { if (!outputFailure) { outputFailure = error; finishHost(); } });
    return result;
  };
  const listTabs = async (sessionId: string | undefined, scope: "all" | "session"): Promise<SharedTabRecord[]> => {
    if (!trusted) throw new Error("browser extension is not trusted");
    nextTabRequestId += 1;
    const requestId = `host-tabs-${nextTabRequestId}`;
    const { promise, resolve, reject } = Promise.withResolvers<SharedTabRecord[]>();
    const timer = setTimeout(() => {
      pendingTabRequests.delete(requestId);
      reject(new Error("browser tab enumeration timed out"));
    }, 5_000);
    timer.unref?.();
    pendingTabRequests.set(requestId, { resolve, reject, timer });
    void send({ version: NATIVE_PROTOCOL_VERSION, type: "listTabs", requestId, scope, ...(sessionId === undefined ? {} : { sessionId }) }).catch((error) => {
      clearTimeout(timer);
      pendingTabRequests.delete(requestId);
      reject(error instanceof Error ? error : new Error(String(error)));
    });
    return await promise;
  };
  const claimTab = async (sessionId: string, tabId: number): Promise<SharedTabRecord> => {
    if (!trusted) throw new Error("browser extension is not trusted");
    nextTabRequestId += 1;
    const requestId = `host-claim-${nextTabRequestId}`;
    const { promise, resolve, reject } = Promise.withResolvers<SharedTabRecord>();
    const timer = setTimeout(() => {
      pendingClaimRequests.delete(requestId);
      reject(new Error("browser tab claim timed out"));
    }, 5_000);
    timer.unref?.();
    pendingClaimRequests.set(requestId, { resolve, reject, timer });
    void send({ version: NATIVE_PROTOCOL_VERSION, type: "claimTab", requestId, sessionId, tabId }).catch((error) => {
      clearTimeout(timer);
      pendingClaimRequests.delete(requestId);
      reject(error instanceof Error ? error : new Error(String(error)));
    });
    return await promise;
  };
  const requestAccess = async (principalId: string, stableSessionKey: string, delta: SessionAccessDelta): Promise<AccessUpgradeRecord> => {
    if (!trusted) throw new TaskSessionError("invalidSession", "browser extension is not trusted");
    const preview = sessions.previewAccessUpgrade(principalId, stableSessionKey, delta);
    if (pendingAccessBySession.has(preview.session.id)) throw new TaskSessionError("sessionConflict", "an access upgrade is already awaiting approval");
    const request: AccessUpgradeRecord = {
      id: randomUUID(),
      sessionId: preview.session.id,
      delta: { ...delta, tabIds: [...delta.tabIds], domains: [...delta.domains] },
      requestedAccess: { ...preview.access, tabIds: [...preview.access.tabIds], domains: [...preview.access.domains] },
      createdAt: Date.now(),
    };
    pendingAccess.set(request.id, request);
    pendingAccessBySession.set(request.sessionId, request.id);
    broker?.publish({ event: "accessPending", sessionId: request.sessionId, accessRequest: request });
    await send({ version: NATIVE_PROTOCOL_VERSION, type: "accessPending", request });
    return request;
  };
  const enrollProfile = async (profileName: string, publicKeySpki: string) => {
    if (!trusted) throw new TaskSessionError("invalidSession", "browser extension is not trusted");
    for (const pending of pendingEnrollments.values()) if (pending.profileName === profileName) throw new TaskSessionError("sessionConflict", "an enrollment for this profile is already awaiting confirmation");
    let fingerprint: string;
    try { fingerprint = fingerprintSpki(publicKeySpki); } catch { throw new TaskSessionError("invalidSession", "publicKeySpki is not a valid key"); }
    const enrollmentId = randomUUID();
    const code = String(randomInt(0, 1_000_000)).padStart(6, "0");
    const expiresAt = Date.now() + 2 * 60_000;
    const timer = setTimeout(() => {
      if (!pendingEnrollments.delete(enrollmentId)) return;
      broker?.publish({ event: "enrollDeclined", enrollmentId, profileName, reason: "enrollment code expired" });
    }, expiresAt - Date.now());
    timer.unref?.();
    pendingEnrollments.set(enrollmentId, { profileName, publicKeySpki, fingerprint, code, expiresAt, attempts: 0, timer });
    await send({ version: NATIVE_PROTOCOL_VERSION, type: "enrollPending", enrollmentId, profileName, profileFingerprint: fingerprint, expiresAt });
    return { enrollmentId, code, expiresAt };
  };
  const sessions = new TaskSessionManager({ startRelay: options.startRelay ?? startAgentTabRelay, onEvent: (event) => {
    const session = { ...event.session, requestedCapabilities: [...event.session.requestedCapabilities], access: { ...event.session.access, tabIds: [...event.session.access.tabIds], domains: [...event.session.access.domains] } };
    if (event.type === "pending") { broker?.publish({ event: "pending", sessionId: session.id, session }); void send({ version: NATIVE_PROTOCOL_VERSION, type: "sessionPending", session }).catch(() => {}); }
    else if (event.type === "active") broker?.publish({ event: "active", sessionId: session.id, session, cdpUrl: event.cdpUrl });
    else {
      const accessRequestId = pendingAccessBySession.get(session.id);
      if (accessRequestId) {
        pendingAccessBySession.delete(session.id);
        pendingAccess.delete(accessRequestId);
        broker?.publish({ event: "accessDeclined", sessionId: session.id, accessRequestId, reason: "session ended" });
        void send({ version: NATIVE_PROTOCOL_VERSION, type: "accessDeclined", accessRequestId, sessionId: session.id }).catch(() => {});
      }
      broker?.publish({ event: "revoked", sessionId: session.id, session, reason: event.reason });
      void send({ version: NATIVE_PROTOCOL_VERSION, type: "sessionStopped", session, reason: event.reason }).catch(() => {});
    }
  } });
  broker = await startBrokerServer({ token: state.brokerSecret, sessions, isTrusted: () => trusted !== null, controller: () => trusted ? { principalId: controllerPrincipalId, displayName: "Local controller" } : null, profile: async (name) => {
    const current = await stateStore.load();
    const record = (current.enrolledProfiles ?? []).find((profile) => profile.name === name);
    return record ? { principalId: record.principalId, displayName: record.name, publicKeySpki: record.publicKeySpki } : null;
  }, enrollProfile, status: () => ({ companionPrincipalId: companion.principalId, controllerPrincipalId }), listTabs, claimTab, requestAccess });
  const handshake = new HostIdentityHandshake(identityStore, stateStore);
  const decoder = new NativeMessageDecoder();
  const requestIds = new Set<string>();
  const stop = async () => {
    if (outputFailure) trusted = null;
    for (const pending of pendingTabRequests.values()) {
      clearTimeout(pending.timer);
      pending.reject(new Error("native host is closing"));
    }
    pendingTabRequests.clear();
    for (const pending of pendingClaimRequests.values()) {
      clearTimeout(pending.timer);
      pending.reject(new Error("native host is closing"));
    }
    pendingClaimRequests.clear();
    try { await sessions.revokeAll("hostClosing"); } finally { try { await broker?.close(); } catch {} }
  };
  const snapshot = async () => {
    const all = sessions.snapshot().map((session) => ({ ...session, requestedCapabilities: [...session.requestedCapabilities], access: { ...session.access, tabIds: [...session.access.tabIds], domains: [...session.access.domains] } }));
    await send({ version: NATIVE_PROTOCOL_VERSION, type: "snapshot", pending: all.filter(({ state }) => state === "pending"), active: all.filter(({ state }) => state === "active"), sharedTabs: [], pendingAccess: [...pendingAccess.values()] });
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
        if (message.type === "tabsListed") {
          const pending = pendingTabRequests.get(message.requestId);
          if (!pending) return;
          pendingTabRequests.delete(message.requestId);
          clearTimeout(pending.timer);
          pending.resolve(message.tabs);
          return;
        }
        if (message.type === "tabClaimed") {
          const pending = pendingClaimRequests.get(message.requestId);
          if (!pending) return;
          pendingClaimRequests.delete(message.requestId);
          clearTimeout(pending.timer);
          if (!message.ok || !message.tab) {
            pending.reject(new Error(message.error ?? "browser rejected tab claim"));
            return;
          }
          pending.resolve(message.tab);
          return;
        }
        if (message.type === "revokeDevice") { const current = trusted; await sessions.revokeAll("deviceRevoked"); await stateStore.unpinExtension(current.extensionId, current.fingerprint); trusted = null; await outputTail; finishHost(); return; }
        if (message.type === "approveSession") { const session = sessions.get(message.sessionId); if (!session || session.state !== "pending" || session.controllerPrincipalId !== message.controllerPrincipalId || session.displayControllerName !== message.displayControllerName || session.taskLabel !== message.taskLabel || session.expiresAt !== message.expiresAt || session.requestedCapabilities.join(",") !== message.requestedCapabilities.join(",") || !sameSessionAccess(session.access, message.access)) return; const approved = await sessions.approve(session.id); await send({ version: NATIVE_PROTOCOL_VERSION, type: "sessionStarted", session: { ...approved.session, requestedCapabilities: [...approved.session.requestedCapabilities], access: { ...approved.session.access, tabIds: [...approved.session.access.tabIds], domains: [...approved.session.access.domains] } }, relayUrl: approved.pairingUrl, ...(message.requestId ? { requestId: message.requestId } : {}) }); return; }
        if (message.type === "approveAccess") {
          const request = pendingAccess.get(message.accessRequestId);
          if (!request || request.sessionId !== message.sessionId || !sameSessionAccess(request.requestedAccess, message.requestedAccess)) return;
          const session = sessions.applyAccessUpgrade(request.sessionId, request.delta, request.requestedAccess);
          pendingAccess.delete(request.id);
          pendingAccessBySession.delete(request.sessionId);
          const serialized = { ...session, requestedCapabilities: [...session.requestedCapabilities], access: { ...session.access, tabIds: [...session.access.tabIds], domains: [...session.access.domains] } };
          broker?.publish({ event: "accessUpdated", sessionId: session.id, accessRequestId: request.id, session: serialized });
          await send({ version: NATIVE_PROTOCOL_VERSION, type: "accessUpdated", accessRequestId: request.id, session: serialized });
          return;
        }
        if (message.type === "declineAccess") {
          const request = pendingAccess.get(message.accessRequestId);
          if (!request || request.sessionId !== message.sessionId) return;
          pendingAccess.delete(request.id);
          pendingAccessBySession.delete(request.sessionId);
          broker?.publish({ event: "accessDeclined", sessionId: request.sessionId, accessRequestId: request.id, reason: "user declined access upgrade" });
          await send({ version: NATIVE_PROTOCOL_VERSION, type: "accessDeclined", accessRequestId: request.id, sessionId: request.sessionId });
          return;
        }
        if (message.type === "confirmEnrollment") {
          const pending = pendingEnrollments.get(message.enrollmentId);
          if (!pending || pending.expiresAt <= Date.now()) {
            await send({ version: NATIVE_PROTOCOL_VERSION, type: "enrollResult", requestId: message.requestId, enrollmentId: message.enrollmentId, ok: false, error: "enrollment request is no longer pending" });
            return;
          }
          const expected = Buffer.from(pending.code, "utf8");
          const presented = Buffer.from(message.code, "utf8");
          if (presented.length !== expected.length || !timingSafeEqual(expected, presented)) {
            pending.attempts += 1;
            if (pending.attempts >= 3) {
              clearTimeout(pending.timer);
              pendingEnrollments.delete(message.enrollmentId);
              broker?.publish({ event: "enrollDeclined", enrollmentId: message.enrollmentId, profileName: pending.profileName, reason: "too many incorrect codes" });
              await send({ version: NATIVE_PROTOCOL_VERSION, type: "enrollResult", requestId: message.requestId, enrollmentId: message.enrollmentId, ok: false, error: "too many incorrect codes; restart enrollment" });
              return;
            }
            await send({ version: NATIVE_PROTOCOL_VERSION, type: "enrollResult", requestId: message.requestId, enrollmentId: message.enrollmentId, ok: false, error: "incorrect code" });
            return;
          }
          clearTimeout(pending.timer);
          pendingEnrollments.delete(message.enrollmentId);
          await stateStore.update((current) => ({ ...current, enrolledProfiles: [...(current.enrolledProfiles ?? []).filter((profile) => profile.name !== pending.profileName), { name: pending.profileName, principalId: pending.fingerprint, publicKeySpki: pending.publicKeySpki, enrolledAt: Date.now() }] }));
          broker?.publish({ event: "profileEnrolled", enrollmentId: message.enrollmentId, profileName: pending.profileName });
          await send({ version: NATIVE_PROTOCOL_VERSION, type: "enrollResult", requestId: message.requestId, enrollmentId: message.enrollmentId, ok: true, profileName: pending.profileName });
          return;
        }
        if (message.type === "revokeSession" && sessions.get(message.sessionId)) { await sessions.revoke(message.sessionId, message.reason ?? "browserRevoked"); return; }
        if (message.type === "relayReady") { sessions.relayReady(message.sessionId); await snapshot(); return; }
        if (message.type === "relayFailed" && sessions.get(message.sessionId)) await sessions.relayFailed(message.sessionId, "relayFailed");
      } catch (error) { if (error instanceof NativeOutputFailure) throw error; if (message.type === "helloProof" || message.type === "approveSession" || message.type === "approveAccess" || message.type === "declineAccess" || message.type === "confirmEnrollment" || message.type === "revokeSession" || message.type === "relayReady" || message.type === "relayFailed") return; throw error; }
    }
  });
}

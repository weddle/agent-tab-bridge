import { randomInt, randomUUID, timingSafeEqual } from "node:crypto";
import { type Readable, type Writable } from "node:stream";
import { startAgentTabRelay } from "../../extensions/browser/src/browser/extension-relay/relay-server.js";
import { BrokerServer, startBrokerServer } from "./broker.js";
import { deriveControllerPrincipalId, fingerprintSpki, HostIdentityHandshake, IdentityStore, createBrokerSecret } from "./identity.js";
import { NativeMessageDecoder, writeNativeFrame } from "./native-framing.js";
import { NATIVE_PROTOCOL_VERSION, type AccessUpgradeRecord, type ExtensionToHostMessage, type HostToExtensionMessage, type NativeMessage, type SharedTabRecord } from "./native-protocol.js";
import { CompanionStateStore, type PinnedExtensionIdentity } from "./state.js";
import { TaskSessionError, TaskSessionManager, type TaskSessionRelay } from "./task-sessions.js";
import { sameSessionAccess, type SessionAccessDelta } from "./session-access.js";
import { localRouteProvenance, sameRouteProvenance } from "./endpoint-contracts.js";
import type { NativeEndpointBinding, NativeEndpointRecovery } from "./endpoint-recovery.js";

export const NATIVE_HOST_NAME = "com.agenttabbridge.companion";
export type NativeHostOptions = {
  input?: Readable;
  output?: Writable;
  stateStore?: CompanionStateStore;
  identityStore?: IdentityStore;
  startRelay?: () => Promise<TaskSessionRelay>;
  brokerSocketPath?: (identity: PinnedExtensionIdentity) => string;
  recoverEndpoint?: (identity: PinnedExtensionIdentity) => NativeEndpointRecovery | Promise<NativeEndpointRecovery | undefined> | undefined;
  onEndpointReady?: (identity: PinnedExtensionIdentity, broker: BrokerServer, recovery: NativeEndpointRecovery) => void | Promise<void>;
  onEndpointSuspended?: (recovery: NativeEndpointRecovery) => boolean | Promise<boolean>;
  onEndpointClosed?: (endpointId: string, broker: BrokerServer | null) => void | Promise<void>;
};
class NativeOutputFailure extends Error { constructor(cause: unknown) { super(`native messaging output failed: ${cause instanceof Error ? cause.message : String(cause)}`); this.name = "NativeOutputFailure"; } }

/** Endpoint engine owned by the machine supervisor; it never touches Native Messaging stdio directly. */
export async function runNativeEndpoint(options: NativeHostOptions = {}): Promise<void> {
  const input = options.input ?? process.stdin;
  const bufferedInput: Buffer[] = [];
  let receiveInput: ((chunk: Buffer) => void) | undefined;
  let inputTerminated = false;
  let finishInput = () => {};
  input.on("data", (chunk: Buffer) => {
    if (receiveInput) receiveInput(chunk);
    else bufferedInput.push(Buffer.from(chunk));
  });
  input.once("end", () => { inputTerminated = true; finishInput(); });
  input.once("close", () => { inputTerminated = true; finishInput(); });
  input.once("error", () => { inputTerminated = true; finishInput(); });
  input.resume();
  const output = options.output ?? process.stdout;
  const stateStore = options.stateStore ?? new CompanionStateStore();
  const identityStore = options.identityStore ?? new IdentityStore("companion");
  const companion = await identityStore.loadOrCreate();
  const state = await stateStore.initializeMachine(companion.principalId, createBrokerSecret());
  const controllerPrincipalId = deriveControllerPrincipalId(state.machine.brokerSecret);
  let trusted: { extensionId: string; fingerprint: string; principalId: string; displayName: string } | null = null;
  let endpointId: string | undefined;
  let broker: BrokerServer | null = null;
  let ending = false;
  let finishHost: () => void = () => {};
  let outputFailure: NativeOutputFailure | null = null;
  let nextTabRequestId = 0;
  const pendingTabRequests = new Map<string, { resolve: (tabs: SharedTabRecord[]) => void; reject: (error: Error) => void; timer: NodeJS.Timeout }>();
  const pendingClaimRequests = new Map<string, { resolve: (tab: SharedTabRecord) => void; reject: (error: Error) => void; timer: NodeJS.Timeout }>();
  const pendingAccess = new Map<string, AccessUpgradeRecord>();
  let recovery: NativeEndpointRecovery | undefined;
  let sessions: TaskSessionManager | undefined;
  let binding: NativeEndpointBinding | undefined;
  const sessionManager = (): TaskSessionManager => {
    if (!sessions) throw new TaskSessionError("invalidSession", "browser endpoint is not ready");
    return sessions;
  };
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
    const preview = sessionManager().previewAccessUpgrade(principalId, stableSessionKey, delta);
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
  const attachBinding = (target: NativeEndpointBinding): void => {
    binding = target;
    binding.trusted = true;
    binding.send = send;
    binding.listTabs = listTabs;
    binding.claimTab = claimTab;
    binding.requestAccess = requestAccess;
    binding.enrollProfile = enrollProfile;
  };
  const emitSessionEvent = (event: import("./task-sessions.js").SessionLifecycleEvent) => {
    const session = { ...event.session, requestedCapabilities: [...event.session.requestedCapabilities], access: { ...event.session.access, tabIds: [...event.session.access.tabIds], domains: [...event.session.access.domains] }, route: { ...event.session.route, accessCeiling: { ...event.session.route.accessCeiling, tabIds: [...event.session.route.accessCeiling.tabIds], domains: [...event.session.route.accessCeiling.domains] } } };
    if (event.type === "pending") {
      broker?.publish({ event: "pending", sessionId: session.id, session });
      void binding?.send?.({ version: NATIVE_PROTOCOL_VERSION, type: "sessionPending", session }).catch(() => {});
    } else if (event.type === "active") {
      broker?.publish({ event: "active", sessionId: session.id, session, cdpUrl: event.cdpUrl });
    } else if (event.type === "reconnecting") {
      broker?.publish({ event: "reconnecting", sessionId: session.id, session });
    } else {
      const accessRequestId = pendingAccessBySession.get(session.id);
      if (accessRequestId) {
        pendingAccessBySession.delete(session.id);
        pendingAccess.delete(accessRequestId);
        broker?.publish({ event: "accessDeclined", sessionId: session.id, accessRequestId, reason: "session ended" });
        void binding?.send?.({ version: NATIVE_PROTOCOL_VERSION, type: "accessDeclined", accessRequestId, sessionId: session.id }).catch(() => {});
      }
      broker?.publish({ event: "revoked", sessionId: session.id, session, reason: event.reason });
      void binding?.send?.({ version: NATIVE_PROTOCOL_VERSION, type: "sessionStopped", session, reason: event.reason }).catch(() => {});
    }
  };
  const createSessions = (identity: PinnedExtensionIdentity) => new TaskSessionManager({
    startRelay: options.startRelay ?? startAgentTabRelay,
    routeFor: (principalId, access) => localRouteProvenance(identity.fingerprint, principalId, access),
    onEvent: emitSessionEvent,
  });
  const unavailable = <T>(message: string): Promise<T> => Promise.reject(new TaskSessionError("invalidSession", message));
  const startBroker = async (identity: PinnedExtensionIdentity): Promise<BrokerServer> => {
    if (broker) return broker;
    broker = await startBrokerServer({
      ...(options.brokerSocketPath ? { socketPath: options.brokerSocketPath(identity) } : {}),
      token: state.machine.brokerSecret,
      sessions: sessionManager(),
      isTrusted: () => binding?.trusted === true,
      controller: () => binding?.trusted ? { principalId: controllerPrincipalId, displayName: "Local controller" } : null,
      profile: async (name) => {
        const current = await stateStore.load();
        const record = current.machine.enrollments.find((profile) => profile.name === name);
        return record ? { principalId: record.principalId, displayName: record.name, publicKeySpki: record.publicKeySpki } : null;
      },
      authContext: () => binding?.trusted ? { machineId: companion.principalId, machinePublicKeySpki: companion.publicKeySpki, machinePrivateKeyPkcs8: companion.privateKeyPkcs8, endpointId: identity.fingerprint } : null,
      enrollProfile: (profileName, publicKeySpki) => binding?.enrollProfile?.(profileName, publicKeySpki) ?? unavailable("browser endpoint is reconnecting"),
      status: () => ({ companionPrincipalId: companion.principalId, controllerPrincipalId, recovery: sessions?.snapshot().some((session) => session.state === "reconnecting") === true }),
      listTabs: (sessionId, scope) => binding?.listTabs?.(sessionId, scope) ?? unavailable("browser endpoint is reconnecting"),
      claimTab: (sessionId, tabId) => binding?.claimTab?.(sessionId, tabId) ?? unavailable("browser endpoint is reconnecting"),
      requestAccess: (principalId, stableSessionKey, delta) => binding?.requestAccess?.(principalId, stableSessionKey, delta) ?? unavailable("browser endpoint is reconnecting"),
    });
    return broker;
  };
  const handshake = new HostIdentityHandshake(identityStore, stateStore);
  const decoder = new NativeMessageDecoder();
  const requestIds = new Set<string>();
  let permanentClose = false;
  const stop = async () => {
    if (outputFailure) trusted = null;
    if (binding) {
      binding.trusted = false;
      binding.send = undefined;
      binding.listTabs = undefined;
      binding.claimTab = undefined;
      binding.requestAccess = undefined;
      binding.enrollProfile = undefined;
    }
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
    if (recovery && !outputFailure && !permanentClose && await options.onEndpointSuspended?.(recovery)) return;
    try {
      await sessions?.revokeAll("hostClosing");
    } finally {
      try { await broker?.close(); } catch {}
      if (endpointId) await options.onEndpointClosed?.(endpointId, broker);
    }
  };
  const snapshot = async () => {
    const manager = sessionManager();
    const all = manager.snapshot().map((session) => ({ ...session, requestedCapabilities: [...session.requestedCapabilities], access: { ...session.access, tabIds: [...session.access.tabIds], domains: [...session.access.domains] }, route: { ...session.route, accessCeiling: { ...session.route.accessCeiling, tabIds: [...session.route.accessCeiling.tabIds], domains: [...session.route.accessCeiling.domains] } } }));
    const current = await stateStore.load();
    const enrolledProfiles = current.machine.enrollments.map(({ name, principalId, enrolledAt }) => ({ name, principalId, enrolledAt }));
    await send({ version: NATIVE_PROTOCOL_VERSION, type: "snapshot", pending: all.filter(({ state }) => state === "pending"), active: all.filter(({ state }) => state === "active"), sharedTabs: [], pendingAccess: [...pendingAccess.values()], enrolledProfiles });
    for (const session of all.filter(({ state }) => state === "reconnecting")) {
      const relayUrl = manager.pairingUrl(session.id);
      if (relayUrl) await send({ version: NATIVE_PROTOCOL_VERSION, type: "sessionResuming", session, relayUrl });
    }
  };
  await new Promise<void>((resolve) => {
    finishHost = () => { if (ending) return; ending = true; void outputTail.then(stop, stop).then(() => resolve(), () => resolve()); };
    const enqueue = (message: NativeMessage) => { queue = queue.then(async () => await handle(message as ExtensionToHostMessage)).catch((error) => { if (error instanceof NativeOutputFailure || error instanceof Error) finishHost(); }); };
    let queue = Promise.resolve();
    finishInput = () => {
      try { decoder.finish(); } catch {}
      finishHost();
    };
    receiveInput = (chunk) => {
      if (ending) return;
      try { for (const message of decoder.feed(chunk)) enqueue(message); } catch { finishHost(); }
    };
    for (const chunk of bufferedInput) receiveInput(chunk);
    bufferedInput.length = 0;
    if (inputTerminated) finishInput();
    async function handle(message: ExtensionToHostMessage): Promise<void> {
      if (message.requestId && (requestIds.has(message.requestId) || !requestIds.add(message.requestId))) return;
      try {
        if (message.type === "hello") { const challenge = await handshake.createChallenge(message); await send(message.requestId ? { ...challenge, requestId: message.requestId } : challenge); return; }
        if (message.type === "helloProof") {
          const pinned = await handshake.verifyProof(message);
          trusted = { extensionId: pinned.extensionId, fingerprint: pinned.fingerprint, principalId: pinned.fingerprint, displayName: pinned.extensionId };
          endpointId = pinned.fingerprint;
          recovery = await options.recoverEndpoint?.(pinned);
          if (recovery) {
            sessions = recovery.sessions;
            broker = recovery.broker;
            sessions.setEventListener(emitSessionEvent);
            attachBinding(recovery.binding);
            if (binding) binding.trusted = false;
          } else {
            sessions = createSessions(pinned);
            const freshBinding: NativeEndpointBinding = { trusted: false, send: undefined, listTabs: undefined, claimTab: undefined, requestAccess: undefined, enrollProfile: undefined };
            attachBinding(freshBinding);
            const endpointBroker = await startBroker(pinned);
            recovery = { identity: pinned, sessions, broker: endpointBroker, binding: freshBinding };
          }
          const endpointBroker = broker!;
          await options.onEndpointReady?.(pinned, endpointBroker, recovery);
          await send({ version: NATIVE_PROTOCOL_VERSION, type: "trusted", companionPrincipalId: companion.principalId, extensionFingerprint: pinned.fingerprint, ...(message.requestId ? { requestId: message.requestId } : {}) });
          await snapshot();
          return;
        }
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
        if (message.type === "revokeDevice") { const current = trusted; permanentClose = true; await sessionManager().revokeAll("deviceRevoked"); await stateStore.unpinExtension(current.extensionId, current.fingerprint); trusted = null; await outputTail; finishHost(); return; }
        if (message.type === "approveSession") {
          const manager = sessionManager();
          const session = manager.get(message.sessionId);
          if (!session || session.state !== "pending" || session.controllerPrincipalId !== message.controllerPrincipalId || session.displayControllerName !== message.displayControllerName || session.taskLabel !== message.taskLabel || session.expiresAt !== message.expiresAt || session.requestedCapabilities.join(",") !== message.requestedCapabilities.join(",") || !sameSessionAccess(session.access, message.access) || !sameRouteProvenance(session.route, message.route)) return;
          const approved = await manager.approve(session.id);
          await send({ version: NATIVE_PROTOCOL_VERSION, type: "sessionStarted", session: { ...approved.session, requestedCapabilities: [...approved.session.requestedCapabilities], access: { ...approved.session.access, tabIds: [...approved.session.access.tabIds], domains: [...approved.session.access.domains] }, route: { ...approved.session.route, accessCeiling: { ...approved.session.route.accessCeiling, tabIds: [...approved.session.route.accessCeiling.tabIds], domains: [...approved.session.route.accessCeiling.domains] } } }, relayUrl: approved.pairingUrl });
          return;
        }
        if (message.type === "approveAccess") {
          const request = pendingAccess.get(message.accessRequestId);
          if (!request || request.sessionId !== message.sessionId || !sameSessionAccess(request.requestedAccess, message.requestedAccess)) return;
          const session = sessionManager().applyAccessUpgrade(request.sessionId, request.delta, request.requestedAccess);
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
          await stateStore.update((current) => ({ ...current, machine: { ...current.machine, enrollments: [...current.machine.enrollments.filter((profile) => profile.name !== pending.profileName), { name: pending.profileName, principalId: pending.fingerprint, publicKeySpki: pending.publicKeySpki, enrolledAt: Date.now() }] } }));
          broker?.publish({ event: "profileEnrolled", enrollmentId: message.enrollmentId, profileName: pending.profileName });
          await send({ version: NATIVE_PROTOCOL_VERSION, type: "enrollResult", requestId: message.requestId, enrollmentId: message.enrollmentId, ok: true, profileName: pending.profileName });
          return;
        }
        if (message.type === "revokeProfile") {
          const current = await stateStore.load();
          const record = current.machine.enrollments.find((profile) => profile.name === message.profileName);
          if (record) {
            await stateStore.update((state) => ({ ...state, machine: { ...state.machine, enrollments: state.machine.enrollments.filter((profile) => profile.name !== message.profileName) } }));
            await Promise.allSettled(sessionManager().snapshot().filter((session) => session.controllerPrincipalId === record.principalId && session.state !== "revoked").map(async (session) => await sessionManager().revoke(session.id, "profileRevoked")));
          }
          await snapshot();
          return;
        }
        if (message.type === "revokeSession" && sessionManager().get(message.sessionId)) { await sessionManager().revoke(message.sessionId, message.reason ?? "browserRevoked"); return; }
        if (message.type === "relayReady") { sessionManager().relayReady(message.sessionId); if (binding) binding.trusted = true; await snapshot(); return; }
        if (message.type === "relayFailed" && sessionManager().get(message.sessionId)) await sessionManager().relayFailed(message.sessionId, "relayFailed");
      } catch (error) { if (error instanceof NativeOutputFailure) throw error; if (message.type === "helloProof" || message.type === "approveSession" || message.type === "approveAccess" || message.type === "declineAccess" || message.type === "confirmEnrollment" || message.type === "revokeProfile" || message.type === "revokeSession" || message.type === "relayReady" || message.type === "relayFailed") return; throw error; }
    }
  });
}

import { toRelayTabInfo } from "./modules/relay-core.js";
import { isPermittedPageCdpMethod } from "./modules/cdp-policy.js";
import {
  buildRelayWsProtocols,
  claimTab,
  matchesSessionAuthority,
  parseRelayPairingUrl,
  reconnectDelayMs,
  releaseSessionTabs,
  releaseTab,
  sessionOwnsGroup,
  sessionOwnsTab,
  sessionTabIds,
} from "./modules/session-core.js";
import {
  fingerprintSpki,
  forgetPinnedCompanion,
  loadExtensionIdentity,
  loadPinnedCompanion,
  pinCompanion,
  signNativeProof,
  verifyNativeChallenge,
  toBase64Url,
} from "./modules/native-identity.js";
const NATIVE_HOST_NAME = "com.agenttabbridge.companion";
const PROTOCOL_VERSION = 1;
const TASK_GROUP_COLOR = "blue";
const MAX_TASK_LABEL_LENGTH = 128;
const CDP_POLICY_ERROR = "CDP method is not permitted by Agent Tab Bridge";
const BADGE = {
  disconnected: { text: "", color: "#000000" },
  connecting: { text: "…", color: "#F59E0B" },
  connected: { text: "ON", color: "#0F9D58" },
  error: { text: "!", color: "#B91C1C" },
};

/** Session records supplied by the authenticated companion, keyed by task ID. */
const sessions = new Map();
/** One ephemeral relay socket per active task session. */
const relaySockets = new Map();
/** Relays that completed hello and were acknowledged to the companion. */
const readyRelaySessions = new Set();
/** Prevent a startup error and its resulting close event from reporting twice. */
const failedRelaySockets = new WeakSet();
/** Authoritative extension-created group ID per task session; titles are display-only. */
const sessionGroups = new Map();
/** Serializes first-group creation so a session never acquires competing groups. */
const creatingSessionGroups = new Map();
/** Authoritative tab ownership; a tab ID maps to at most one task session. */
const tabOwners = new Map();
/** Debugger attachment ownership, distinct from sharing because relay commands attach lazily. */
const attachedTabs = new Map();
/** Coalesces attach requests for one owned tab. */
const attachingTabs = new Map();
/** Suppresses duplicate group-change callbacks while a claimed tab is revoked. */
const revokingTabs = new Set();
/** Suppresses the expected onDetach callback while the extension itself detaches. */
const intentionalDebuggerDetaches = new Set();
/** Coalesces stop operations so native loss and browser events remain idempotent. */
const stoppingSessions = new Map();
/** Popup-approved records awaiting exactly one matching active transition. */
const approvedSessions = new Map();


let nativePort = null;
let nativeState = "disconnected";
let nativeGeneration = 0;
let nativeReconnectAttempt = 0;
let nativeReconnectTimer = null;
let nativeReconnectAllowed = true;
let nativeIdentityPromise = null;
let pendingHello = null;
let trustedCompanion = null;
const requestIdPrefix = randomNonce();
let nextRequestId = 0;

function setBadge(state) {
  const badge = BADGE[state] ?? BADGE.disconnected;
  void chrome.action.setBadgeText({ text: badge.text });
  void chrome.action.setBadgeBackgroundColor({ color: badge.color });
}

function refreshBadge() {
  if (nativeState === "disconnected") {
    setBadge("disconnected");
  } else if (nativeState === "connecting") {
    setBadge("connecting");
  } else if (relaySockets.size > 0) {
    setBadge("connected");
  } else {
    setBadge("connected");
  }
}

function newRequestId() {
  nextRequestId += 1;
  return `ext-${requestIdPrefix}-${nextRequestId}`;
}

function validId(value) {
  return typeof value === "string" && value.length > 0 && value.length <= 256;
}



function normalizeSession(raw, expectedState) {
  const value = raw?.session && typeof raw.session === "object" ? raw.session : raw;
  const fields = [
    "id",
    "controllerPrincipalId",
    "displayControllerName",
    "taskLabel",
    "requestedCapabilities",
    "createdAt",
    "expiresAt",
    "state",
  ];
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).length !== fields.length ||
    !fields.every((field) => Object.hasOwn(value, field)) ||
    !validId(value.id) ||
    !validId(value.controllerPrincipalId) ||
    typeof value.displayControllerName !== "string" ||
    value.displayControllerName.length === 0 ||
    value.displayControllerName.length > 128 ||
    typeof value.taskLabel !== "string" ||
    value.taskLabel.length === 0 ||
    value.taskLabel.length > MAX_TASK_LABEL_LENGTH ||
    !Array.isArray(value.requestedCapabilities) ||
    value.requestedCapabilities.length > 1 ||
    new Set(value.requestedCapabilities).size !== value.requestedCapabilities.length ||
    value.requestedCapabilities.some((capability) => capability !== "cdp") ||
    !Number.isInteger(value.createdAt) ||
    (value.expiresAt !== null &&
      (!Number.isInteger(value.expiresAt) ||
        value.expiresAt <= value.createdAt ||
        value.expiresAt - value.createdAt > 24 * 60 * 60 * 1_000)) ||
    !["pending", "active", "revoked"].includes(value.state) ||
    (expectedState && value.state !== expectedState)
  ) {
    return null;
  }
  return {
    id: value.id,
    controllerId: value.controllerPrincipalId,
    controllerName: value.displayControllerName,
    taskLabel: value.taskLabel,
    capabilities: value.requestedCapabilities,
    createdAt: value.createdAt,
    expiresAt: value.expiresAt,
    state: value.state,
  };
}

function sessionDto(session) {
  return {
    id: session.id,
    controllerId: session.controllerId,
    controllerName: session.controllerName,
    taskLabel: session.taskLabel,
    capabilities: session.capabilities,
    createdAt: session.createdAt,
    expiresAt: session.expiresAt,
    state: session.state,
  };
}

function sessionIsActive(sessionId) {
  const session = sessions.get(sessionId);
  return session?.state === "active" && relaySockets.has(sessionId) && readyRelaySessions.has(sessionId);
}

function taskGroupTitle(session) {
  const label = session.taskLabel || "Task";
  return `Agent Tab Bridge · ${label}`;
}

function stopNativeReconnect() {
  if (nativeReconnectTimer) {
    clearTimeout(nativeReconnectTimer);
    nativeReconnectTimer = null;
  }
}

function scheduleNativeReconnect() {
  if (!nativeReconnectAllowed || nativeReconnectTimer || nativePort) {
    return;
  }
  const delay = reconnectDelayMs(nativeReconnectAttempt);
  nativeReconnectAttempt += 1;
  nativeReconnectTimer = setTimeout(() => {
    nativeReconnectTimer = null;
    void connectNative();
  }, delay);
}

function postNative(message) {
  if (!nativePort || nativeState !== "connected") {
    throw new Error("Native Messaging companion is unavailable.");
  }
  nativePort.postMessage(message);
}

function postSessionRevocation(sessionId, reason) {
  if (!nativePort || nativeState !== "connected") {
    return;
  }
  try {
    nativePort.postMessage({
      version: PROTOCOL_VERSION,
      type: "revokeSession",
      requestId: newRequestId(),
      sessionId,
      reason,
    });
  } catch {
    // Local teardown already removed the browser authority. A later native
    // disconnect will not restore it.
  }
}

async function extensionIdentity() {
  nativeIdentityPromise ??= loadExtensionIdentity();
  try {
    return await nativeIdentityPromise;
  } catch (error) {
    nativeIdentityPromise = null;
    throw error;
  }
}

function randomNonce() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return toBase64Url(bytes);
}

async function beginNativeHello(port, generation) {
  const identity = await extensionIdentity();
  if (nativePort !== port || generation !== nativeGeneration) {
    return;
  }
  const hello = {
    version: PROTOCOL_VERSION,
    type: "hello",
    role: "extension",
    extensionId: chrome.runtime.id,
    extensionPublicKey: identity.publicKeySpki,
    extensionNonce: randomNonce(),
    requestId: newRequestId(),
  };
  pendingHello = { generation, identity, hello };
  port.postMessage(hello);
}

async function handleHelloChallenge(message, port, generation) {
  const pending = pendingHello;
  if (
    !pending ||
    pending.generation !== generation ||
    nativePort !== port ||
    message?.version !== PROTOCOL_VERSION ||
    message?.type !== "helloChallenge" ||
    message?.role !== "companion" ||
    message.extensionId !== pending.hello.extensionId ||
    message.extensionPublicKey !== pending.hello.extensionPublicKey ||
    message.extensionNonce !== pending.hello.extensionNonce ||
    !(typeof message.companionId === "string" && message.companionId.length <= 256 && /^sha256\/[A-Za-z0-9+/=_-]+$/u.test(message.companionId)) ||
    typeof message.companionPublicKey !== "string" ||
    typeof message.companionNonce !== "string" ||
    typeof message.signature !== "string"
  ) {
    throw new Error("Native Messaging challenge did not bind this extension identity.");
  }

  const fields = {
    companionId: message.companionId,
    companionNonce: message.companionNonce,
    companionPublicKey: message.companionPublicKey,
    extensionId: pending.hello.extensionId,
    extensionNonce: pending.hello.extensionNonce,
    extensionPublicKey: pending.hello.extensionPublicKey,
  };
  if (!(await verifyNativeChallenge(message.companionPublicKey, message.signature, fields))) {
    throw new Error("Native Messaging companion challenge signature is invalid.");
  }
  const [companion, extensionFingerprint] = await Promise.all([
    pinCompanion({
      id: message.companionId,
      publicKeySpki: message.companionPublicKey,
    }),
    fingerprintSpki(pending.identity.publicKeySpki),
  ]);
  if (
    companion.id !== message.companionId ||
    companion.publicKeySpki !== message.companionPublicKey ||
    nativePort !== port ||
    generation !== nativeGeneration ||
    pendingHello !== pending
  ) {
    throw new Error("Native Messaging companion identity changed during authentication.");
  }

  const signature = await signNativeProof(pending.identity, fields);
  if (nativePort !== port || generation !== nativeGeneration || pendingHello !== pending) {
    return;
  }
  pending.companion = companion;
  pending.extensionFingerprint = extensionFingerprint;
  port.postMessage({
    version: PROTOCOL_VERSION,
    type: "helloProof",
    role: "extension",
    ...fields,
    signature,
    requestId: newRequestId(),
  });
}

async function handleTrusted(message, port, generation) {
  const pending = pendingHello;
  if (
    nativePort !== port ||
    generation !== nativeGeneration ||
    message?.version !== PROTOCOL_VERSION ||
    message?.type !== "trusted" ||
    !pending ||
    !pending.companion ||
    typeof message.companionPrincipalId !== "string" ||
    typeof message.extensionFingerprint !== "string"
  ) {
    throw new Error("Native Messaging companion did not complete authentication.");
  }
  const extensionFingerprint = await fingerprintSpki(pending.identity.publicKeySpki);
  if (
    nativePort !== port ||
    generation !== nativeGeneration ||
    pendingHello !== pending ||
    message.companionPrincipalId !== pending.companion.id ||
    message.extensionFingerprint !== extensionFingerprint ||
    pending.extensionFingerprint !== extensionFingerprint
  ) {
    throw new Error("Native Messaging trusted response did not bind the pinned identities.");
  }
  trustedCompanion = {
    id: pending.companion.id,
    name: pending.companion.name,
  };
  pendingHello = null;
  nativeState = "connected";
  nativeReconnectAttempt = 0;
  refreshBadge();
}

async function handleNativeSnapshot(message) {
  const rawSessions = [
    ...(Array.isArray(message.pending) ? message.pending : []),
    ...(Array.isArray(message.active) ? message.active : []),
  ];
  const incoming = new Map();
  for (const raw of rawSessions) {
    const session = normalizeSession(raw);
    if (session) {
      incoming.set(session.id, session);
    }
  }

  for (const sessionId of [...sessions.keys()]) {
    if (!incoming.has(sessionId)) {
      await stopSession(sessionId, { removeSession: true });
    }
  }
  for (const session of incoming.values()) {
    const existing = sessions.get(session.id);
    sessions.set(session.id, { ...existing, ...session });
    if (session.state === "revoked" || session.state === "pending") {
      await stopSession(session.id, { removeSession: session.state === "revoked" });
      if (session.state === "pending") {
        sessions.set(session.id, session);
      }
    } else if (!relaySockets.has(session.id)) {
      // A relay credential is intentionally memory-only. A resurrected worker
      // cannot reconnect an old active task, so remove its authority instead.
      await stopSession(session.id, { removeSession: true });
      postSessionRevocation(session.id, "extension relay state was lost");
    }
  }
}

async function rejectSessionStart(sessionId, reason) {
  if (!validId(sessionId)) {
    return;
  }
  approvedSessions.delete(sessionId);
  postSessionRevocation(sessionId, reason);
  await stopSession(sessionId, { removeSession: true });
}

async function handleSessionPending(message) {
  const session = normalizeSession(message, "pending");
  if (!session) {
    return;
  }
  const approval = approvedSessions.get(session.id);
  if (approval && !matchesSessionAuthority(approval.session, session)) {
    await rejectSessionStart(session.id, "pending session metadata changed after popup approval");
    return;
  }
  await stopSession(session.id, { removeSession: false });
  sessions.set(session.id, session);
}

async function handleSessionStarted(message) {
  const hintedSessionId = message?.session?.id ?? message?.id;
  const sessionUpdate = normalizeSession(message, "active");
  const sessionId = sessionUpdate?.id ?? (validId(hintedSessionId) ? hintedSessionId : null);
  if (!validId(sessionId)) {
    return;
  }
  const known = sessions.get(sessionId);
  const approval = approvedSessions.get(sessionId);
  if (
    !sessionUpdate ||
    typeof message?.relayUrl !== "string" ||
    !known ||
    known.state !== "pending" ||
    !approval ||
    !matchesSessionAuthority(known, sessionUpdate) ||
    !matchesSessionAuthority(approval.session, sessionUpdate) ||
    relaySockets.has(sessionId)
  ) {
    await rejectSessionStart(sessionId, "session start was not the popup-approved pending session");
    return;
  }

  approvedSessions.delete(sessionId);
  sessions.set(sessionId, sessionUpdate);
  await openSessionRelay(sessionId, message.relayUrl);
}

async function handleSessionStopped(message) {
  const session = normalizeSession(message);
  if (!session) {
    return;
  }
  approvedSessions.delete(session.id);
  await stopSession(session.id, { removeSession: true });
}

async function handleNativeMessage(message, port, generation) {
  if (nativePort !== port || generation !== nativeGeneration || !message || typeof message !== "object") {
    return;
  }
  if (message.type === "helloChallenge") {
    await handleHelloChallenge(message, port, generation);
    return;
  }
  if (message.type === "trusted") {
    await handleTrusted(message, port, generation);
    return;
  }
  if (!trustedCompanion) {
    return;
  }
  switch (message.type) {
    case "snapshot":
      await handleNativeSnapshot(message);
      return;
    case "sessionPending":
      await handleSessionPending(message);
      return;
    case "sessionStarted":
      await handleSessionStarted(message);
      return;
    case "sessionStopped":
      await handleSessionStopped(message);
      return;
    default:
      return;
  }
}

async function handleNativeDisconnect(port, generation) {
  if (nativePort !== port || generation !== nativeGeneration) {
    return;
  }
  nativePort = null;
  pendingHello = null;
  trustedCompanion = null;
  nativeState = "disconnected";
  try {
    await stopAllSessions();
  } finally {
    sessions.clear();
    approvedSessions.clear();
    refreshBadge();
    scheduleNativeReconnect();
  }
}

async function terminateNativeConnection(port, generation) {
  try {
    port.disconnect();
  } catch {
    // Native Messaging may already have closed the port.
  }
  await handleNativeDisconnect(port, generation);
}

async function connectNative() {
  if (!nativeReconnectAllowed || nativePort) {
    return;
  }
  stopNativeReconnect();
  nativeState = "connecting";
  refreshBadge();
  let port;
  try {
    port = chrome.runtime.connectNative(NATIVE_HOST_NAME);
  } catch {
    nativeState = "disconnected";
    refreshBadge();
    scheduleNativeReconnect();
    return;
  }

  const generation = nativeGeneration + 1;
  nativeGeneration = generation;
  nativePort = port;
  port.onMessage.addListener((message) => {
    void handleNativeMessage(message, port, generation).catch(() => {
      void terminateNativeConnection(port, generation).catch(() => {});
    });
  });
  port.onDisconnect.addListener(() => {
    void handleNativeDisconnect(port, generation).catch(() => {});
  });

  try {
    await beginNativeHello(port, generation);
  } catch {
    await terminateNativeConnection(port, generation);
  }
}

function sendRelay(sessionId, message) {
  const socket = relaySockets.get(sessionId);
  if (socket?.readyState !== WebSocket.OPEN) {
    return false;
  }
  try {
    socket.send(JSON.stringify(message));
    return true;
  } catch {
    return false;
  }
}

async function sessionRelayTabs(sessionId) {
  const tabs = [];
  for (const tabId of sessionTabIds(tabOwners, sessionId)) {
    try {
      const tab = await chrome.tabs.get(tabId);
      if (await tabStillBelongsToSession(sessionId, tab)) {
        tabs.push(toRelayTabInfo(tab));
      }
    } catch {
      releaseTab(tabOwners, sessionId, tabId);
    }
  }
  return tabs;
}

async function syncSessionTabs(sessionId) {
  if (!sessionIsActive(sessionId)) {
    return;
  }
  sendRelay(sessionId, { type: "tabs", tabs: await sessionRelayTabs(sessionId) });
}

async function sendRelayHello(sessionId) {
  const browserVersion = /(?:Brave|Chrome)\/[\d.]+/.exec(navigator.userAgent)?.[0] ?? "Chromium";
  if (!sendRelay(sessionId, {
    type: "hello",
    userAgent: navigator.userAgent,
    browserVersion,
    extensionVersion: chrome.runtime.getManifest().version,
    tabs: await sessionRelayTabs(sessionId),
  })) {
    throw new Error("The local relay closed before it accepted its hello.");
  }
}

function closeRelaySocket(sessionId) {
  const socket = relaySockets.get(sessionId);
  relaySockets.delete(sessionId);
  readyRelaySessions.delete(sessionId);
  if (socket) {
    try {
      socket.close();
    } catch {
      // Browser WebSockets can close while an extension callback is queued.
    }
  }
}

function reportRelayFailure(sessionId, error) {
  if (!nativePort || nativeState !== "connected") {
    return false;
  }
  try {
    nativePort.postMessage({
      version: PROTOCOL_VERSION,
      type: "relayFailed",
      requestId: newRequestId(),
      sessionId,
      error: String(error).slice(0, 512),
    });
    return true;
  } catch {
    // Native loss separately revokes all locally-controlled tabs.
    return false;
  }
}

function reportRelayReady(sessionId, relayUrl) {
  if (!nativePort || nativeState !== "connected") {
    return false;
  }
  try {
    nativePort.postMessage({
      version: PROTOCOL_VERSION,
      type: "relayReady",
      requestId: newRequestId(),
      sessionId,
      relayUrl,
    });
    return true;
  } catch {
    // Host loss causes the port's disconnect handler to revoke this session.
    return false;
  }
}

async function failRelaySession(sessionId, socket, error) {
  if (socket && failedRelaySockets.has(socket)) {
    return;
  }
  const current = relaySockets.get(sessionId);
  if (socket && current && current !== socket) {
    return;
  }
  if (socket) {
    failedRelaySockets.add(socket);
  }
  reportRelayFailure(sessionId, error);
  if (current === socket) {
    closeRelaySocket(sessionId);
  }
  try {
    await stopSession(sessionId, { removeSession: true });
  } finally {
    postSessionRevocation(sessionId, "extension relay startup failed");
    refreshBadge();
  }
}

async function handleRelayOpen(sessionId, socket, relayUrl) {
  if (relaySockets.get(sessionId) !== socket || !sessions.has(sessionId)) {
    await failRelaySession(sessionId, socket, "The local relay opened after its session was removed.");
    return;
  }
  await sendRelayHello(sessionId);
  if (!reportRelayReady(sessionId, relayUrl)) {
    throw new Error("Native Messaging companion disconnected before relay readiness.");
  }
  if (relaySockets.get(sessionId) !== socket || !sessions.has(sessionId)) {
    throw new Error("The local relay was removed during startup.");
  }
  const session = sessions.get(sessionId);
  readyRelaySessions.add(sessionId);
  sessions.set(sessionId, { ...session, state: "active" });
  return true;
}

async function handleRelayClose(sessionId, socket, ready) {
  if (relaySockets.get(sessionId) !== socket) {
    return;
  }
  relaySockets.delete(sessionId);
  readyRelaySessions.delete(sessionId);
  if (!ready) {
    await failRelaySession(sessionId, socket, "The local relay closed before readiness.");
    return;
  }
  try {
    await stopSession(sessionId, { removeSession: true });
  } finally {
    postSessionRevocation(sessionId, "local relay disconnected");
    refreshBadge();
  }
}

async function openSessionRelay(sessionId, pairingUrl) {
  const parsed = parseRelayPairingUrl(pairingUrl);
  if (!parsed) {
    await failRelaySession(sessionId, null, "Companion supplied an invalid local relay URL.");
    return;
  }

  closeRelaySocket(sessionId);
  let socket;
  try {
    socket = new WebSocket(parsed.relayUrl, buildRelayWsProtocols(parsed.token));
  } catch (error) {
    await failRelaySession(sessionId, null, error instanceof Error ? error.message : "Unable to open relay.");
    return;
  }

  let ready = false;
  relaySockets.set(sessionId, socket);
  socket.addEventListener("open", () => {
    void handleRelayOpen(sessionId, socket, parsed.relayUrl)
      .then((opened) => {
        ready = opened === true;
        if (ready) {
          refreshBadge();
        }
      })
      .catch((error) => {
        void failRelaySession(sessionId, socket, error instanceof Error ? error.message : String(error)).catch(() => {});
      });
  });
  socket.addEventListener("message", (event) => {
    let message;
    try {
      message = JSON.parse(String(event.data));
    } catch {
      return;
    }
    void handleRelayCommand(sessionId, socket, message).catch((error) => {
      void failRelaySession(sessionId, socket, error instanceof Error ? error.message : String(error)).catch(() => {});
    });
  });
  socket.addEventListener("error", () => {
    void failRelaySession(sessionId, socket, "The local relay reported an error.").catch(() => {});
  });
  socket.addEventListener("close", () => {
    void handleRelayClose(sessionId, socket, ready).catch((error) => {
      void failRelaySession(sessionId, socket, error instanceof Error ? error.message : String(error)).catch(() => {});
    });
  });
}

function isPermittedCdpMethod(method) {
  return isPermittedPageCdpMethod(method);
}

async function tabStillBelongsToSession(sessionId, tab) {
  if (!sessionOwnsTab(tabOwners, sessionId, tab.id)) {
    return false;
  }
  if (!sessionOwnsGroup(sessionGroups, sessionId, tab.groupId)) {
    await revokeTabAccess(sessionId, tab.id, "tab left its task group");
    return false;
  }
  return true;
}

async function assertSessionTab(sessionId, tabId) {
  if (!sessionIsActive(sessionId) || !sessionOwnsTab(tabOwners, sessionId, tabId)) {
    throw new Error("Tab is not shared with this active task session.");
  }
  const tab = await chrome.tabs.get(tabId);
  if (!(await tabStillBelongsToSession(sessionId, tab))) {
    throw new Error("Tab is no longer shared with this task session.");
  }
  return tab;
}

async function requireSessionGroupInWindow(sessionId, groupId, windowId) {
  let group;
  try {
    group = await chrome.tabGroups.get(groupId);
  } catch {
    if (sessionGroups.get(sessionId) === groupId) {
      sessionGroups.delete(sessionId);
    }
    throw new Error("The task session group no longer exists.");
  }
  if (group.windowId !== windowId) {
    throw new Error("A task session can share tabs from only one browser window.");
  }
  return groupId;
}

async function ensureSessionGroup(sessionId, tab) {
  const knownGroupId = sessionGroups.get(sessionId);
  if (Number.isInteger(knownGroupId)) {
    return await requireSessionGroupInWindow(sessionId, knownGroupId, tab.windowId);
  }

  const inFlight = creatingSessionGroups.get(sessionId);
  if (inFlight) {
    return await requireSessionGroupInWindow(sessionId, await inFlight, tab.windowId);
  }

  const creation = (async () => {
    const groupId = await chrome.tabs.group({ tabIds: [tab.id] });
    try {
      await chrome.tabGroups.update(groupId, {
        title: taskGroupTitle(sessions.get(sessionId)),
        color: TASK_GROUP_COLOR,
      });
      if (!sessionIsActive(sessionId)) {
        throw new Error("Task session stopped while its group was being created.");
      }
      sessionGroups.set(sessionId, groupId);
      return groupId;
    } catch (error) {
      try {
        await chrome.tabs.ungroup([tab.id]);
      } catch {
        // The browser may already have removed the tab or group.
      }
      throw error;
    }
  })();
  creatingSessionGroups.set(sessionId, creation);
  try {
    return await creation;
  } finally {
    if (creatingSessionGroups.get(sessionId) === creation) {
      creatingSessionGroups.delete(sessionId);
    }
  }
}

async function shareTab(sessionId, tabId) {
  if (!Number.isInteger(tabId)) {
    throw new Error("No tab was selected.");
  }
  if (!sessionIsActive(sessionId)) {
    throw new Error("Only an active task session can control tabs.");
  }
  const claim = claimTab(tabOwners, sessionId, tabId);
  if (!claim.ok) {
    throw new Error("This tab is already shared with another task session.");
  }

  try {
    const tab = await chrome.tabs.get(tabId);
    const groupId = await ensureSessionGroup(sessionId, tab);
    if (tab.groupId !== groupId) {
      await chrome.tabs.group({ tabIds: [tabId], groupId });
    }
    await syncSessionTabs(sessionId);
  } catch (error) {
    releaseTab(tabOwners, sessionId, tabId);
    throw error;
  }
}

async function detachChromeDebugger(tabId) {
  intentionalDebuggerDetaches.add(tabId);
  try {
    await chrome.debugger.detach({ tabId });
  } catch {
    // The tab may have been closed or Chrome may have detached it already.
  } finally {
    setTimeout(() => intentionalDebuggerDetaches.delete(tabId), 1_000);
  }
}

async function detachDebugger(tabId) {
  if (!attachedTabs.delete(tabId)) {
    return;
  }
  await detachChromeDebugger(tabId);
}

async function attachDebugger(sessionId, tabId) {
  const inFlight = attachingTabs.get(tabId);
  if (inFlight) {
    return await inFlight;
  }

  const attaching = (async () => {
    await assertSessionTab(sessionId, tabId);
    const currentOwner = attachedTabs.get(tabId);
    if (currentOwner && currentOwner !== sessionId) {
      throw new Error("Debugger attachment belongs to a different task session.");
    }
    if (!currentOwner) {
      try {
        await chrome.debugger.attach({ tabId }, "1.3");
      } catch (error) {
        throw new Error(
          `Unable to attach this session's debugger: ${error instanceof Error ? error.message : String(error)}`,
        );
      }
      try {
        await assertSessionTab(sessionId, tabId);
      } catch (error) {
        await detachChromeDebugger(tabId);
        throw error;
      }
      attachedTabs.set(tabId, sessionId);
    }
    const targets = await chrome.debugger.getTargets();
    const target = targets.find((candidate) => candidate.tabId === tabId && candidate.attached);
    return { targetId: target?.id ?? `tab-${tabId}` };
  })();

  attachingTabs.set(tabId, attaching);
  try {
    return await attaching;
  } finally {
    attachingTabs.delete(tabId);
  }
}

async function revokeTabAccess(sessionId, tabId, reason, { notifyRelay = true } = {}) {
  if (!releaseTab(tabOwners, sessionId, tabId)) {
    return;
  }
  await detachDebugger(tabId);
  const groupId = sessionGroups.get(sessionId);
  try {
    const tab = await chrome.tabs.get(tabId);
    if (tab.groupId === groupId) {
      await chrome.tabs.ungroup([tabId]);
    }
  } catch {
    // Closed tabs and already-removed groups have no remaining access.
  }
  if (sessionTabIds(tabOwners, sessionId).length === 0) {
    sessionGroups.delete(sessionId);
  }
  if (notifyRelay && sessionIsActive(sessionId)) {
    sendRelay(sessionId, { type: "detached", tabId, reason });
    await syncSessionTabs(sessionId);
  }
}

async function unshareTab(sessionId, tabId) {
  if (!sessionOwnsTab(tabOwners, sessionId, tabId)) {
    throw new Error("This tab is not shared with the selected task session.");
  }
  await revokeTabAccess(sessionId, tabId, "user removed shared tab", { notifyRelay: false });
  await syncSessionTabs(sessionId);
}

async function stopSession(sessionId, { removeSession = true } = {}) {
  const stopping = stoppingSessions.get(sessionId);
  if (stopping) {
    return await stopping;
  }
  const task = (async () => {
    closeRelaySocket(sessionId);
    const tabIds = sessionTabIds(tabOwners, sessionId);
    await Promise.all(
      tabIds.map((tabId) => revokeTabAccess(sessionId, tabId, "task session stopped", { notifyRelay: false })),
    );
    releaseSessionTabs(tabOwners, sessionId);
    sessionGroups.delete(sessionId);
    if (removeSession) {
      sessions.delete(sessionId);
      approvedSessions.delete(sessionId);
    }
  })();
  stoppingSessions.set(sessionId, task);
  try {
    await task;
  } finally {
    stoppingSessions.delete(sessionId);
  }
}

async function stopAllSessions() {
  await Promise.all([...sessions.keys()].map((sessionId) => stopSession(sessionId, { removeSession: true })));
  for (const tabId of [...attachedTabs.keys()]) {
    await detachDebugger(tabId);
  }
  relaySockets.clear();
  readyRelaySessions.clear();
  sessionGroups.clear();
  tabOwners.clear();
  approvedSessions.clear();
}

async function forwardDebuggerEvent(source, method, params) {
  const tabId = source?.tabId;
  const sessionId = attachedTabs.get(tabId);
  if (!Number.isInteger(tabId) || !sessionId) {
    return;
  }
  try {
    await assertSessionTab(sessionId, tabId);
  } catch {
    return;
  }
  sendRelay(sessionId, {
    type: "cdpEvent",
    tabId,
    ...(source.sessionId ? { sessionId: source.sessionId } : {}),
    method,
    params,
  });
}

async function handleRelayCommand(sessionId, socket, message) {
  const seq = message?.seq;
  if (relaySockets.get(sessionId) !== socket || !sessionIsActive(sessionId)) {
    return;
  }
  try {
    switch (message?.type) {
      case "ping":
        sendRelay(sessionId, { type: "pong" });
        return;
      case "attach": {
        const result = await attachDebugger(sessionId, message.tabId);
        sendRelay(sessionId, { type: "result", seq, result });
        return;
      }
      case "detach":
        await assertSessionTab(sessionId, message.tabId);
        await detachDebugger(message.tabId);
        sendRelay(sessionId, { type: "result", seq, result: {} });
        return;
      case "cdp": {
        if (!isPermittedCdpMethod(message.method)) {
          throw new Error(CDP_POLICY_ERROR);
        }
        await assertSessionTab(sessionId, message.tabId);
        if (attachedTabs.get(message.tabId) !== sessionId) {
          throw new Error("Tab is not attached for this task session.");
        }
        const target = message.sessionId
          ? { tabId: message.tabId, sessionId: message.sessionId }
          : { tabId: message.tabId };
        const result = await chrome.debugger.sendCommand(target, message.method, message.params ?? {});
        sendRelay(sessionId, { type: "result", seq, result: result ?? {} });
        return;
      }
      case "createTab": {
        const tab = await chrome.tabs.create({
          url: message.url,
          active: message.background !== true,
        });
        if (!Number.isInteger(tab.id)) {
          throw new Error("Browser did not return a tab ID.");
        }
        try {
          await shareTab(sessionId, tab.id);
          if (message.focus === true && Number.isInteger(tab.windowId)) {
            await chrome.windows.update(tab.windowId, { focused: true });
          }
        } catch (error) {
          try {
            await revokeTabAccess(sessionId, tab.id, "new tab setup failed", { notifyRelay: false });
          } catch {
            // Closing the just-created tab remains the safe fallback.
          }
          try {
            await chrome.tabs.remove(tab.id);
          } catch {
            // The browser may already have removed it.
          }
          throw error;
        }
        sendRelay(sessionId, { type: "result", seq, result: { tabId: tab.id } });
        return;
      }
      case "closeTab":
        await assertSessionTab(sessionId, message.tabId);
        await detachDebugger(message.tabId);
        releaseTab(tabOwners, sessionId, message.tabId);
        await chrome.tabs.remove(message.tabId);
        await syncSessionTabs(sessionId);
        sendRelay(sessionId, { type: "result", seq, result: {} });
        return;
      case "activateTab": {
        const tab = await assertSessionTab(sessionId, message.tabId);
        await chrome.tabs.update(message.tabId, { active: true });
        if (Number.isInteger(tab.windowId)) {
          await chrome.windows.update(tab.windowId, { focused: true });
        }
        sendRelay(sessionId, { type: "result", seq, result: {} });
        return;
      }
      default:
        if (typeof seq === "number") {
          sendRelay(sessionId, { type: "error", seq, message: `unknown relay command: ${message?.type}` });
        }
    }
  } catch (error) {
    if (typeof seq === "number") {
      sendRelay(sessionId, {
        type: "error",
        seq,
        message: error instanceof Error ? error.message : String(error),
      });
    }
  }
}

async function sharedTabsDto() {
  const rows = [];
  for (const [tabId, sessionId] of tabOwners) {
    try {
      const tab = await chrome.tabs.get(tabId);
      if (await tabStillBelongsToSession(sessionId, tab)) {
        rows.push({
          tabId,
          sessionId,
          title: tab.title ?? "",
          url: tab.url ?? "",
          active: tab.active === true,
          windowId: tab.windowId,
        });
      }
    } catch {
      releaseTab(tabOwners, sessionId, tabId);
    }
  }
  return rows;
}

async function forgetCompanion() {
  const port = nativePort;
  const generation = nativeGeneration;
  let firstError = null;
  nativeReconnectAllowed = false;
  stopNativeReconnect();

  if (port && nativeState === "connected") {
    try {
      port.postMessage({
        version: PROTOCOL_VERSION,
        type: "revokeDevice",
        requestId: newRequestId(),
      });
    } catch (error) {
      firstError = error;
    }
  }

  try {
    await stopAllSessions();
  } catch (error) {
    firstError ??= error;
  }
  sessions.clear();
  approvedSessions.clear();
  pendingHello = null;
  trustedCompanion = null;
  nativeState = "disconnected";

  try {
    await forgetPinnedCompanion();
  } catch (error) {
    firstError ??= error;
  }

  if (port) {
    try {
      await terminateNativeConnection(port, generation);
    } catch (error) {
      firstError ??= error;
    }
  } else {
    refreshBadge();
  }

  if (firstError) {
    throw firstError;
  }
}

async function statusDto() {
  let pinnedCompanion = null;
  let storedPinUnreadable = false;
  try {
    pinnedCompanion = await loadPinnedCompanion();
  } catch {
    storedPinUnreadable = true;
  }
  const sessionValues = [...sessions.values()];
  const companion = trustedCompanion ?? pinnedCompanion;
  return {
    ok: true,
    native: {
      state: nativeState,
      companion: {
        id: companion?.id ?? null,
        name: companion?.name ?? null,
        trusted: trustedCompanion !== null,
        pinned: pinnedCompanion !== null || storedPinUnreadable,
      },
    },
    pendingSessions: sessionValues.filter((session) => session.state === "pending").map(sessionDto),
    activeSessions: sessionValues
      .filter((session) => sessionIsActive(session.id))
      .map(sessionDto),
    sharedTabs: await sharedTabsDto(),
  };
}

function sendErrorResponse(sendResponse, error) {
  sendResponse({ ok: false, error: error instanceof Error ? error.message : String(error) });
}

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  void (async () => {
    switch (message?.type) {
      case "getStatus":
        sendResponse(await statusDto());
        return;
      case "forgetCompanion":
        await forgetCompanion();
        sendResponse({ ok: true });
        return;
      case "approveSession": {
        const session = sessions.get(message.sessionId);
        if (!session || session.state !== "pending") {
          throw new Error("This task session is not awaiting approval.");
        }
        if (approvedSessions.has(session.id)) {
          throw new Error("Approval is already awaiting the companion's matching session start.");
        }
        const approval = {
          requestId: newRequestId(),
          session: { ...session, capabilities: [...session.capabilities] },
        };
        approvedSessions.set(session.id, approval);
        try {
          postNative({
            version: PROTOCOL_VERSION,
            type: "approveSession",
            requestId: approval.requestId,
            sessionId: session.id,
            controllerPrincipalId: session.controllerId,
            displayControllerName: session.controllerName,
            taskLabel: session.taskLabel,
            requestedCapabilities: session.capabilities,
            expiresAt: session.expiresAt,
          });
        } catch (error) {
          approvedSessions.delete(session.id);
          throw error;
        }
        sendResponse({ ok: true });
        return;
      }
      case "revokeSession": {
        if (!validId(message.sessionId)) {
          throw new Error("No task session was selected.");
        }
        let nativeError = null;
        try {
          postSessionRevocation(message.sessionId, "user revoked task session");
        } catch (error) {
          nativeError = error;
        }
        await stopSession(message.sessionId, { removeSession: true });
        if (nativeError) {
          throw nativeError;
        }
        sendResponse({ ok: true });
        return;
      }
      case "shareTab":
        await shareTab(message.sessionId, message.tabId);
        sendResponse({ ok: true, shared: true });
        return;
      case "unshareTab":
        await unshareTab(message.sessionId, message.tabId);
        sendResponse({ ok: true, shared: false });
        return;
      default:
        throw new Error("Unknown message.");
    }
  })().catch((error) => sendErrorResponse(sendResponse, error));
  return true;
});

chrome.debugger.onEvent.addListener((source, method, params) => {
  void forwardDebuggerEvent(source, method, params).catch(() => {});
});

chrome.debugger.onDetach.addListener((source, reason) => {
  const tabId = source?.tabId;
  if (!Number.isInteger(tabId)) {
    return;
  }
  if (intentionalDebuggerDetaches.delete(tabId)) {
    attachedTabs.delete(tabId);
    return;
  }
  const sessionId = attachedTabs.get(tabId) ?? tabOwners.get(tabId);
  attachedTabs.delete(tabId);
  if (!sessionId) {
    return;
  }
  void revokeTabAccess(sessionId, tabId, reason || "debugger access was dismissed").catch(() => {
    releaseTab(tabOwners, sessionId, tabId);
  });
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (typeof changeInfo.groupId !== "number") {
    return;
  }
  const ownerSessionId = tabOwners.get(tabId);
  const groupOwnerSessionId = [...sessionGroups.entries()].find(([, groupId]) => groupId === changeInfo.groupId)?.[0];
  if (ownerSessionId) {
    if (creatingSessionGroups.has(ownerSessionId)) {
      return;
    }
    if (sessionGroups.get(ownerSessionId) !== changeInfo.groupId) {
      if (revokingTabs.has(tabId)) {
        return;
      }
      revokingTabs.add(tabId);
      if (groupOwnerSessionId && groupOwnerSessionId !== ownerSessionId) {
        void chrome.tabs.ungroup([tabId]).catch(() => {});
      }
      void revokeTabAccess(ownerSessionId, tabId, "tab left its task group")
        .catch(() => {
          releaseTab(tabOwners, ownerSessionId, tabId);
        })
        .finally(() => revokingTabs.delete(tabId));
    }
  } else if (groupOwnerSessionId) {
    if (revokingTabs.has(tabId)) {
      return;
    }
    if (!sessionIsActive(groupOwnerSessionId)) {
      void chrome.tabs.ungroup([tabId]).catch(() => {});
      return;
    }
    const claim = claimTab(tabOwners, groupOwnerSessionId, tabId);
    if (!claim.ok) {
      // Ownership is exclusive. Do not let a tab owned by another session
      // cross-claim merely because it was dragged over this group.
      void chrome.tabs.ungroup([tabId]).catch(() => {});
      return;
    }
    void syncSessionTabs(groupOwnerSessionId).catch(() => {
      void revokeTabAccess(
        groupOwnerSessionId,
        tabId,
        "tab sharing state could not be synchronized",
        { notifyRelay: false },
      ).catch(() => {
        releaseTab(tabOwners, groupOwnerSessionId, tabId);
      });
    });
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  const sessionId = tabOwners.get(tabId);
  attachedTabs.delete(tabId);
  if (sessionId) {
    releaseTab(tabOwners, sessionId, tabId);
    void syncSessionTabs(sessionId).catch(() => {
      postSessionRevocation(sessionId, "shared tab state could not be synchronized");
    });
  }
});

chrome.tabGroups.onRemoved.addListener((group) => {
  const sessionId = [...sessionGroups.entries()].find(([, groupId]) => groupId === group.id)?.[0];
  if (!sessionId) {
    return;
  }
  sessionGroups.delete(sessionId);
  void Promise.all(
    sessionTabIds(tabOwners, sessionId).map((tabId) => revokeTabAccess(sessionId, tabId, "task group was removed")),
  ).catch(() => {
    postSessionRevocation(sessionId, "task group cleanup failed");
  });
});

chrome.runtime.onStartup.addListener(() => void connectNative().catch(() => {}));
chrome.runtime.onInstalled.addListener(() => void connectNative().catch(() => {}));
void connectNative().catch(() => {});

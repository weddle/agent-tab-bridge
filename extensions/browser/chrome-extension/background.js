import { isCurrentRelaySocketFailure, relaySocketCloseDisposition, toRelayTabInfo } from "./modules/relay-core.js";
import { isPermittedPageCdpMethod } from "./modules/cdp-policy.js";
import {
  buildRelayWsProtocols,
  claimTab,
  classifyTabAccess,
  matchesSessionAuthority,
  makeSessionRecoveryRecord,
  parseRelayPairingUrl,
  reconnectDelayMs,
  releaseSessionTabs,
  releaseTab,
  sessionOwnsGroup,
  sessionOwnsTab,
  sessionTabIds,
  sessionAuthorityMismatchField,
  sameSessionAuthority,
  validateSessionRecoveryRecord,
} from "./modules/session-core.js";
import { accessWithinStandingGrant, isStandingGrant, localStandingGrantFor, migrateStandingGrants, rememberStandingGrant, routedStandingGrantFor } from "./modules/standing-grants.js";
import {
  NATIVE_PROTOCOL_VERSION as PROTOCOL_VERSION,
  createSerialNativeMessageHandler,
  fingerprintSpki,
  forgetPinnedCompanion,
  loadExtensionIdentity,
  loadPinnedCompanion,
  pinCompanion,
  signNativeProof,
  verifyNativeChallenge,
  toBase64Url,
} from "./modules/native-identity.js";
import { renderClaimedString, renderRouteMarker } from "./modules/ui-vocabulary.js";
const NATIVE_HOST_NAME = "com.agenttabbridge.companion";
const TASK_GROUP_COLOR = "blue";
const TASK_GROUP_TITLE_PREFIX = "Agent Tab Bridge · ";
const MAX_TASK_LABEL_LENGTH = 128;
const CDP_POLICY_ERROR = "CDP method is not permitted by Agent Tab Bridge";
const SESSION_PAGE_URL = chrome.runtime.getURL("session.html");
const TOOLBAR_TITLE = "Agent Tab Bridge";
const SESSION_RECOVERY_STORAGE_PREFIX = "sessionRecovery:";
/** Session records supplied by the authenticated companion, keyed by task ID. */
const sessions = new Map();
/** One ephemeral relay socket per active task session. */
const relaySockets = new Map();
/** Relays that completed hello and were acknowledged to the companion. */
const readyRelaySessions = new Set();
/** Prevent a startup error and its resulting close event from reporting twice. */
const failedRelaySockets = new WeakSet();
/** Extension-owned session page tab per active task session; never a relay target. */
const sessionAnchors = new Map();
/** Authoritative extension-created group ID per task session; titles are display-only. */
const sessionGroups = new Map();
/** Expired recovery groups awaiting Chromium's tab/session restore events. */
const orphanedRecoveryGroups = new Map();
/** Serializes first-group creation so a session never acquires competing groups. */
const creatingSessionGroups = new Map();
/** Authoritative tab ownership; a tab ID maps to at most one task session. */
const tabOwners = new Map();
/** Debugger attachment ownership, distinct from sharing because relay commands attach lazily. */
const attachedTabs = new Map();
/** Coalesces attach requests for one owned tab. */
const attachingTabs = new Map();
/** Suppresses group-change callbacks while the extension repairs authoritative membership. */
const revokingTabs = new Set();
/** Suppresses the expected onDetach callback while the extension itself detaches. */
const intentionalDebuggerDetaches = new Set();
/** Coalesces stop operations so native loss and browser events remain idempotent. */
const stoppingSessions = new Map();
/** Popup-approved records awaiting exactly one matching active transition. */
const approvedSessions = new Map();
/** Access upgrades awaiting a separate popup decision. */
const accessRequests = new Map();
/** Popup-approved upgrades awaiting one exact host confirmation. */
const approvedAccessRequests = new Map();
/** Profile enrollments awaiting the user's pairing code. */
const enrollmentRequests = new Map();
/** In-flight enrollment confirmations awaiting the host's result, keyed by requestId. */
const pendingEnrollConfirms = new Map();
/** Enrolled agent profiles reported by the companion's latest snapshot. */
let enrolledProfiles = [];
/**
 * Standing grants: auto-approve a NEW session from an enrolled profile up to
 * the remembered level. Full access is never remembered, and access upgrades
 * always prompt. Persisted in chrome.storage.local; revocable in the popup.
 */
let standingGrants = [];

let nativePort = null;
let nativeState = "disconnected";
let nativeGeneration = 0;
let nativeReconnectAttempt = 0;
let nativeReconnectTimer = null;
let nativeReconnectAllowed = true;
let runtimeSuspending = false;
let nativeIdentityPromise = null;
let pendingHello = null;
let trustedCompanion = null;
const requestIdPrefix = randomNonce();
let nextRequestId = 0;

function formatToolbarCount(count, noun) {
  return `${count} ${noun}${count === 1 ? "" : "s"}`;
}

function toolbarBadgeCount(count) {
  return count > 9 ? "9+" : String(count);
}

function toolbarSessionCounts() {
  let pending = 0;
  let active = 0;
  let remote = false;
  for (const session of sessions.values()) {
    if (session.state === "pending") {
      pending += 1;
    } else if (
      session.state === "active" &&
      relaySockets.has(session.id) &&
      readyRelaySessions.has(session.id)
    ) {
      active += 1;
      remote ||= session.route?.kind === "routed";
    }
  }
  return { pending, active, remote };
}

function refreshBadge() {
  const { pending, active, remote } = toolbarSessionCounts();
  let text;
  let color;
  let title;

  if (nativeState === "disconnected") {
    text = "OFF";
    color = "#5F6368";
    title = `${TOOLBAR_TITLE} — companion off`;
  } else if (nativeState === "connecting") {
    text = "…";
    color = "#F9AB00";
    title = `${TOOLBAR_TITLE} — connecting to companion`;
  } else if (pending > 0) {
    text = toolbarBadgeCount(pending);
    color = "#F9AB00";
    title = `${TOOLBAR_TITLE} — ${formatToolbarCount(pending, "approval")} waiting`;
    if (active > 0) title += ` · ${formatToolbarCount(active, "session")} active`;
  } else if (active > 0) {
    text = toolbarBadgeCount(active);
    color = "#188038";
    title = `${TOOLBAR_TITLE} — ${formatToolbarCount(active, "session")} active`;
  } else {
    text = "";
    title = `${TOOLBAR_TITLE} — connected, no active sessions`;
  }
  if (remote && active > 0) title += " · includes remote session";

  void chrome.action.setBadgeText({ text });
  if (color) void chrome.action.setBadgeBackgroundColor({ color });
  void chrome.action.setTitle({ title });
}

function newRequestId() {
  nextRequestId += 1;
  return `ext-${requestIdPrefix}-${nextRequestId}`;
}

function validId(value) {
  return typeof value === "string" && value.length > 0 && value.length <= 256;
}

function validRoute(value) {
  return !!value && typeof value === "object" && !Array.isArray(value) &&
    Object.keys(value).length === 8 &&
    ["kind", "endpointId", "controllerPrincipalId", "routePolicy", "accessCeiling", "hubId", "routeId", "streamId"].every((field) => Object.hasOwn(value, field)) &&
    (value.kind === "local" || value.kind === "routed") &&
    validId(value.endpointId) &&
    validId(value.controllerPrincipalId) &&
    ((value.kind === "local" && value.routePolicy === "localOnly" && value.hubId === null && value.routeId === null && value.streamId === null) || (value.kind === "routed" && value.routePolicy === "routed")) &&
    (value.hubId === null || validId(value.hubId)) &&
    (value.routeId === null || validId(value.routeId)) &&
    (value.streamId === null || validId(value.streamId)) &&
    !!normalizeAccess(value.accessCeiling);
}


async function loadStandingGrants() {
  try {
    const stored = await chrome.storage.local.get("standingGrants");
    const endpointIdentity = await loadExtensionIdentity();
    const endpointId = await fingerprintSpki(endpointIdentity.publicKeySpki);
    const rawGrants = Array.isArray(stored?.standingGrants) ? stored.standingGrants : [];
    standingGrants = migrateStandingGrants(rawGrants, endpointId);
    if (JSON.stringify(rawGrants) !== JSON.stringify(standingGrants)) await saveStandingGrants();
  } catch {
    standingGrants = [];
  }
}

async function saveStandingGrants() {
  if (standingGrants.length === 0) {
    await chrome.storage.local.remove("standingGrants");
  } else {
    await chrome.storage.local.set({ standingGrants });
  }
  const stored = await chrome.storage.local.get("standingGrants");
  const persisted = Array.isArray(stored?.standingGrants) ? stored.standingGrants.filter(isStandingGrant) : [];
  if (JSON.stringify(persisted) !== JSON.stringify(standingGrants)) {
    throw new Error("Standing grant storage did not retain the requested policy.");
  }
}


function enrolledPrincipal(controllerId) {
  return enrolledProfiles.some((profile) => profile.principalId === controllerId);
}

async function rememberGrant(session) {
  if (!enrolledPrincipal(session.controllerId)) return;
  const next = rememberStandingGrant(standingGrants, session);
  if (next === standingGrants) return;
  standingGrants = next;
  await saveStandingGrants();
}

const standingGrantsReady = loadStandingGrants();
function normalizeAccess(value) {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).length !== 3 ||
    !["level", "tabIds", "domains"].every((field) => Object.hasOwn(value, field)) ||
    !["selectedTabs", "domains", "full"].includes(value.level) ||
    !Array.isArray(value.tabIds) ||
    value.tabIds.length > 64 ||
    value.tabIds.some((tabId) => !Number.isInteger(tabId) || tabId < 0) ||
    !Array.isArray(value.domains) ||
    value.domains.length > 64 ||
    value.domains.some((domain) => typeof domain !== "string" || !/^[a-z0-9.-]+$/.test(domain))
  ) {
    return null;
  }
  const tabIds = [...new Set(value.tabIds)].sort((left, right) => left - right);
  const domains = [...new Set(value.domains)].sort();
  if (
    tabIds.length !== value.tabIds.length ||
    domains.length !== value.domains.length ||
    tabIds.some((tabId, index) => tabId !== value.tabIds[index]) ||
    domains.some((domain, index) => domain !== value.domains[index]) ||
    (value.level === "selectedTabs" && domains.length !== 0) ||
    (value.level === "domains" && domains.length === 0) ||
    (value.level === "full" && (tabIds.length !== 0 || domains.length !== 0))
  ) {
    return null;
  }
  return { level: value.level, tabIds, domains };
}
function normalizeAccessDelta(value) {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).length !== 3 ||
    !["kind", "tabIds", "domains"].every((field) => Object.hasOwn(value, field)) ||
    !["tabs", "domains", "full"].includes(value.kind) ||
    !Array.isArray(value.tabIds) ||
    value.tabIds.length > 64 ||
    value.tabIds.some((tabId) => !Number.isInteger(tabId) || tabId < 0) ||
    !Array.isArray(value.domains) ||
    value.domains.length > 64 ||
    value.domains.some((domain) => typeof domain !== "string" || !/^[a-z0-9.-]+$/.test(domain))
  ) {
    return null;
  }
  const tabIds = [...new Set(value.tabIds)].sort((left, right) => left - right);
  const domains = [...new Set(value.domains)].sort();
  if (
    tabIds.length !== value.tabIds.length ||
    domains.length !== value.domains.length ||
    tabIds.some((tabId, index) => tabId !== value.tabIds[index]) ||
    domains.some((domain, index) => domain !== value.domains[index]) ||
    (value.kind === "tabs" && (tabIds.length === 0 || domains.length !== 0)) ||
    (value.kind === "domains" && (domains.length === 0 || tabIds.length !== 0)) ||
    (value.kind === "full" && (tabIds.length !== 0 || domains.length !== 0))
  ) {
    return null;
  }
  return { kind: value.kind, tabIds, domains };
}

function upgradedAccess(current, delta) {
  if (!current || !delta || current.level === "full") return null;
  if (delta.kind === "full") return { level: "full", tabIds: [], domains: [] };
  const tabIds = [...new Set([...current.tabIds, ...(delta.kind === "tabs" ? delta.tabIds : [])])].sort((left, right) => left - right);
  const domains = [...new Set([...current.domains, ...(delta.kind === "domains" ? delta.domains : [])])].sort();
  const upgraded = normalizeAccess({ level: domains.length ? "domains" : "selectedTabs", tabIds, domains });
  return upgraded && JSON.stringify(upgraded) !== JSON.stringify(current) ? upgraded : null;
}

function normalizeAccessRequest(raw) {
  const value = raw?.request && typeof raw.request === "object" ? raw.request : raw;
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).length !== 5 ||
    !["id", "sessionId", "delta", "requestedAccess", "createdAt"].every((field) => Object.hasOwn(value, field)) ||
    !validId(value.id) ||
    !validId(value.sessionId) ||
    !Number.isInteger(value.createdAt) ||
    value.createdAt <= 0
  ) {
    return null;
  }
  const session = sessions.get(value.sessionId);
  const delta = normalizeAccessDelta(value.delta);
  const requestedAccess = normalizeAccess(value.requestedAccess);
  const expected = upgradedAccess(session?.access, delta);
  if (!session || session.state !== "active" || !delta || !requestedAccess || JSON.stringify(expected) !== JSON.stringify(requestedAccess)) {
    return null;
  }
  return { id: value.id, sessionId: value.sessionId, delta, requestedAccess, createdAt: value.createdAt };
}




function normalizeSession(raw, expectedState) {
  const value = raw?.session && typeof raw.session === "object" ? raw.session : raw;
  const fields = [
    "id",
    "controllerPrincipalId",
    "displayControllerName",
    "taskLabel",
    "requestedCapabilities",
    "access",
    "createdAt",
    "expiresAt",
    "state",
    "route",
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
    !normalizeAccess(value.access) ||
    !validRoute(value.route) ||
    value.route.controllerPrincipalId !== value.controllerPrincipalId ||
    !Number.isInteger(value.createdAt) ||
    (value.expiresAt !== null &&
      (!Number.isInteger(value.expiresAt) ||
        value.expiresAt <= value.createdAt ||
        value.expiresAt - value.createdAt > 24 * 60 * 60 * 1_000)) ||
    !["pending", "active", "reconnecting", "revoked"].includes(value.state) ||
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
    access: normalizeAccess(value.access),
    createdAt: value.createdAt,
    expiresAt: value.expiresAt,
    state: value.state,
    route: {
      ...value.route,
      accessCeiling: normalizeAccess(value.route.accessCeiling),
    },
  };
}

function sessionDto(session) {
  return {
    id: session.id,
    controllerId: session.controllerId,
    controllerName: session.controllerName,
    taskLabel: session.taskLabel,
    capabilities: session.capabilities,
    access: { ...session.access, tabIds: [...session.access.tabIds], domains: [...session.access.domains] },
    createdAt: session.createdAt,
    expiresAt: session.expiresAt,
    state: session.state,
    ...(session.rememberedGrant === true ? { rememberedGrant: true } : {}),
    route: { ...session.route, accessCeiling: { ...session.route.accessCeiling, tabIds: [...session.route.accessCeiling.tabIds], domains: [...session.route.accessCeiling.domains] } },
  };
}

function sessionIsActive(sessionId) {
  const session = sessions.get(sessionId);
  return session?.state === "active" && relaySockets.has(sessionId) && readyRelaySessions.has(sessionId);
}
function taskGroupColor(session) {
  if (session.access.level === "full") return "red";
  if (session.access.level === "domains") return "orange";
  return TASK_GROUP_COLOR;
}

function sessionAllowsUrl(session, rawUrl) {
  if (!session || typeof rawUrl !== "string") return false;
  let url;
  try { url = new URL(rawUrl); } catch { return false; }
  if (session.access.level === "full") {
    return url.protocol === "http:" || url.protocol === "https:" || rawUrl === "about:blank";
  }
  if (session.access.level !== "domains" || (url.protocol !== "http:" && url.protocol !== "https:")) {
    return false;
  }
  const hostname = url.hostname.toLowerCase().replace(/\.$/, "");
  return session.access.domains.some((domain) => hostname === domain || hostname.endsWith(`.${domain}`));
}

function sessionCanAdoptTab(session, tab) {
  return (
    !!session &&
    Number.isInteger(tab?.id) &&
    !isSessionPageTab(tab) &&
    (session.access.level === "full" ||
      session.access.tabIds.includes(tab.id) ||
      (session.access.level === "domains" && sessionAllowsUrl(session, tab.url)))
  );
}

function taskGroupTitle(session) {
  const label = session.taskLabel || "Task";
  const routeMarker = renderRouteMarker(session);
  return `${TASK_GROUP_TITLE_PREFIX}${renderClaimedString(label)}${routeMarker}`;
}
function sessionPageUrl(session) {
  const url = new URL(SESSION_PAGE_URL);
  url.searchParams.set("sessionId", session.id);
  url.searchParams.set("controller", session.controllerName);
  url.searchParams.set("controllerFingerprint", session.controllerId);
  url.searchParams.set("label", session.taskLabel);
  url.searchParams.set("capabilities", session.capabilities.join(", "));
  url.searchParams.set("access", session.access.level);
  url.searchParams.set("state", session.state);
  if (session.access.tabIds.length) url.searchParams.set("tabIds", session.access.tabIds.join(","));
  if (session.access.domains.length) url.searchParams.set("domains", session.access.domains.join(","));
  return url.toString();
}

async function updateSessionPageState(sessionId, state) {
  const anchorId = sessionAnchors.get(sessionId);
  const session = sessions.get(sessionId);
  if (!Number.isInteger(anchorId) || !session) return;
  const groupId = sessionGroups.get(sessionId);
  revokingTabs.add(anchorId);
  try {
    const updated = await chrome.tabs.update(anchorId, { url: sessionPageUrl({ ...session, state }) });
    if (Number.isInteger(groupId) && updated.groupId !== groupId) await chrome.tabs.group({ tabIds: [anchorId], groupId });
  } catch {
    // The popup and agent carry the state when the anchor is unavailable.
  } finally {
    revokingTabs.delete(anchorId);
  }
}

function isSessionPageTab(tab) {
  return (
    Number.isInteger(tab?.id) &&
    (sessionAnchors.has(tab.id) ||
      tab.url === SESSION_PAGE_URL ||
      (typeof tab.url === "string" && tab.url.startsWith(`${SESSION_PAGE_URL}?`)))
  );
}

function sessionRecoveryStorageKey(sessionId) {
  return `${SESSION_RECOVERY_STORAGE_PREFIX}${sessionId}`;
}

function anchorSessionId(tab) {
  if (!Number.isInteger(tab?.id) || typeof tab.url !== "string") return null;
  try {
    const actual = new URL(tab.url);
    const expected = new URL(SESSION_PAGE_URL);
    if (
      actual.protocol !== expected.protocol ||
      actual.host !== expected.host ||
      actual.pathname !== expected.pathname
    ) {
      return null;
    }
    const sessionId = actual.searchParams.get("sessionId");
    return validId(sessionId) ? sessionId : null;
  } catch {
    return null;
  }
}

async function storedSessionRecoveryRecords() {
  const stored = await chrome.storage.local.get(null);
  const records = new Map();
  const malformedKeys = [];
  for (const [key, value] of Object.entries(stored)) {
    if (!key.startsWith(SESSION_RECOVERY_STORAGE_PREFIX)) continue;
    const sessionId = key.slice(SESSION_RECOVERY_STORAGE_PREFIX.length);
    const record = makeSessionRecoveryRecord(value?.session, value?.groupId, value?.anchorId, value?.tabIds);
    if (!record || record.session?.id !== sessionId) {
      malformedKeys.push(key);
      continue;
    }
    records.set(sessionId, record);
  }
  if (malformedKeys.length > 0) await chrome.storage.local.remove(malformedKeys);
  return records;
}

async function persistSessionRecovery(sessionId) {
  const session = sessions.get(sessionId);
  const groupId = sessionGroups.get(sessionId);
  const anchorId = sessionAnchors.get(sessionId);
  const record = makeSessionRecoveryRecord(session, groupId, anchorId, sessionTabIds(tabOwners, sessionId));
  if (!record) throw new Error("Task session recovery state is incomplete.");
  await chrome.storage.local.set({ [sessionRecoveryStorageKey(sessionId)]: record });
}

async function removeSessionRecovery(sessionId) {
  await chrome.storage.local.remove(sessionRecoveryStorageKey(sessionId));
}

async function cleanupOrphanedRecoveryGroup(groupId) {
  if (orphanedRecoveryGroups.size === 0) return false;
  let groups;
  try {
    groups = Number.isInteger(groupId) && groupId >= 0 ? [await chrome.tabGroups.get(groupId)] : await chrome.tabGroups.query({});
  } catch {
    return false;
  }
  const ownedGroupIds = new Set(sessionGroups.values());
  let cleaned = false;
  for (const pending of orphanedRecoveryGroups.values()) {
    const matches = groups.filter((group) => group.title === pending.title && !ownedGroupIds.has(group.id));
    if (matches.length === 0) continue;
    for (const group of matches) {
      const groupTabs = await chrome.tabs.query({ groupId: group.id });
      const tabIds = groupTabs.map((tab) => tab.id).filter((tabId) => Number.isInteger(tabId));
      if (tabIds.length > 0) await chrome.tabs.ungroup(tabIds);
    }
    orphanedRecoveryGroups.delete(pending.sessionId);
    await removeSessionRecovery(pending.sessionId);
    cleaned = true;
  }
  return cleaned;
}

async function discardSessionRecovery(sessionId, record) {
  orphanedRecoveryGroups.set(sessionId, { sessionId, title: taskGroupTitle(record.session) });
  let anchor;
  try {
    anchor = await chrome.tabs.get(record.anchorId);
  } catch {
    // Tab and group IDs are not stable across a full browser restart.
  }
  const matchingAnchor = anchorSessionId(anchor) === sessionId && anchor.groupId === record.groupId;
  await cleanupOrphanedRecoveryGroup();
  if (!matchingAnchor) return;
  try {
    await chrome.tabs.remove(record.anchorId);
  } catch {
    // The anchor may already be gone.
  }
}

async function discardUnrecordedSessionArtifacts(sessionId) {
  const tabs = await chrome.tabs.query({});
  const anchors = tabs.filter((tab) => anchorSessionId(tab) === sessionId);
  await Promise.all(
    anchors.map(async (anchor) => {
      if (Number.isInteger(anchor.groupId) && anchor.groupId >= 0) {
        try {
          const groupTabs = await chrome.tabs.query({ groupId: anchor.groupId });
          const tabIds = groupTabs.map((tab) => tab.id).filter((tabId) => Number.isInteger(tabId));
          if (tabIds.length > 0) await chrome.tabs.ungroup(tabIds);
        } catch {
          // The group may already be gone.
        }
      }
      try {
        await chrome.tabs.remove(anchor.id);
      } catch {
        // The anchor may already be gone.
      }
    }),
  );
}

async function restoreSessionRecovery(session) {
  const key = sessionRecoveryStorageKey(session.id);
  const stored = await chrome.storage.local.get(key);
  const storedValue = stored?.[key];
  const record = validateSessionRecoveryRecord(storedValue, session);
  if (!record) {
    console.warn(`Agent Tab Bridge recovery rejected: ${storedValue === undefined ? "record missing" : `authority changed (${sessionAuthorityMismatchField(storedValue?.session, session) ?? "record"})`}`);
    await removeSessionRecovery(session.id);
    await discardUnrecordedSessionArtifacts(session.id);
    return storedValue === undefined ? "record missing" : "authority changed";
  }
  try {
    let anchor = null;
    try {
      anchor = await chrome.tabs.get(record.anchorId);
    } catch {
      // Chromium can remove extension-owned pages while reloading an unpacked extension.
    }
    if (anchor && (anchorSessionId(anchor) !== session.id || anchor.groupId !== record.groupId)) {
      throw new Error("Stored session anchor no longer matches its group.");
    }
    const group = await chrome.tabGroups.get(record.groupId);
    if (anchor && group.windowId !== anchor.windowId) throw new Error("Stored session group moved windows.");
    const groupTabs = await chrome.tabs.query({ groupId: record.groupId });
    const sharedTabs = anchor ? groupTabs.filter((tab) => tab.id !== record.anchorId) : groupTabs;
    const actualTabIds = sharedTabs
      .map((tab) => tab.id)
      .filter((tabId) => Number.isInteger(tabId))
      .sort((left, right) => left - right);
    if (
      actualTabIds.length !== sharedTabs.length ||
      JSON.stringify(actualTabIds) !== JSON.stringify(record.tabIds) ||
      sharedTabs.some((tab) => !sessionCanAdoptTab(session, tab))
    ) {
      throw new Error("Stored session tabs no longer match approved ownership.");
    }
    sessions.set(session.id, session);
    sessionGroups.set(session.id, record.groupId);
    if (anchor) sessionAnchors.set(session.id, record.anchorId);
    for (const tabId of record.tabIds) {
      if (!claimTab(tabOwners, session.id, tabId).ok) {
        throw new Error("Stored session tab is owned by another live session.");
      }
    }
    if (!anchor) {
      await ensureSessionGroup(session.id, group.windowId, true);
      await persistSessionRecovery(session.id);
    }
    return null;
  } catch (error) {
    console.warn(`Agent Tab Bridge recovery rejected: ${error instanceof Error ? error.message : "tab ownership changed"}`);
    sessions.delete(session.id);
    sessionAnchors.delete(session.id);
    sessionGroups.delete(session.id);
    releaseSessionTabs(tabOwners, session.id);
    await discardSessionRecovery(session.id, record);
    return "tab ownership changed";
  }
}

async function cleanupUnownedSessionGroups(records, retainedSessionIds) {
  const ownedGroupIds = new Set(sessionGroups.values());
  const retainedTitles = new Set(
    [...records]
      .filter(([sessionId]) => retainedSessionIds.has(sessionId))
      .map(([, record]) => taskGroupTitle(record.session)),
  );
  const groups = await chrome.tabGroups.query({});
  await Promise.all(
    groups
      .filter(
        (group) =>
          group.title?.startsWith(TASK_GROUP_TITLE_PREFIX) &&
          !ownedGroupIds.has(group.id) &&
          !retainedTitles.has(group.title),
      )
      .map(async (group) => {
        const tabs = await chrome.tabs.query({ groupId: group.id });
        const tabIds = tabs.map((tab) => tab.id).filter((tabId) => Number.isInteger(tabId));
        if (tabIds.length > 0) await chrome.tabs.ungroup(tabIds);
      }),
  );
}

async function cleanupOrphanedSessionRecovery(retainedSessionIds = new Set(sessions.keys())) {
  const records = await storedSessionRecoveryRecords();
  await Promise.all(
    [...records].map(async ([sessionId, record]) => {
      if (!retainedSessionIds.has(sessionId)) await discardSessionRecovery(sessionId, record);
    }),
  );
  await cleanupUnownedSessionGroups(records, retainedSessionIds);
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


/** Popup-equivalent approval used by both the popup route and standing grants. */
function approveSessionNow(session, rememberedGrant = false) {
  const approval = {
    requestId: newRequestId(),
    session: { ...session, capabilities: [...session.capabilities], rememberedGrant },
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
      access: { ...session.access, tabIds: [...session.access.tabIds], domains: [...session.access.domains] },
      route: { ...session.route, accessCeiling: { ...session.route.accessCeiling, tabIds: [...session.route.accessCeiling.tabIds], domains: [...session.route.accessCeiling.domains] } },
    });
  } catch (error) {
    approvedSessions.delete(session.id);
    throw error;
  }
}

/** Auto-approve a pending session only when its remembered route and scope are covered. */
async function maybeAutoApprove(session) {
  await standingGrantsReady;
  const route = session?.route;
  if (!session || session.state !== "pending" || approvedSessions.has(session.id) || !route || (route.kind !== "local" && route.kind !== "routed") || (route.kind === "local" && route.routePolicy !== "localOnly") || (route.kind === "routed" && (route.routePolicy !== "routed" || typeof route.hubId !== "string"))) return;
  if (!enrolledPrincipal(session.controllerId)) return;
  const grant = route.kind === "routed" ? routedStandingGrantFor(standingGrants, session.controllerId, route) : localStandingGrantFor(standingGrants, session.controllerId, route);
  if (!accessWithinStandingGrant(session.access, grant)) return;
  try {
    session.rememberedGrant = true;
    approveSessionNow(session, true);
  } catch {
    delete session.rememberedGrant;
    /* The popup path remains available. */
  }
}
async function handleNativeSnapshot(message) {
  enrolledProfiles = (Array.isArray(message.enrolledProfiles) ? message.enrolledProfiles : [])
    .filter((profile) => !!profile && typeof profile === "object" && validId(profile.name) && validId(profile.principalId) && Number.isInteger(profile.enrolledAt))
    .map(({ name, principalId, enrolledAt }) => ({ name, principalId, enrolledAt }));
  const rawSessions = [
    ...(Array.isArray(message.pending) ? message.pending : []),
    ...(Array.isArray(message.active) ? message.active : []),
  ];
  const hasRecoveryInventory = Array.isArray(message.reconnecting);
  const reconnecting = new Map();
  for (const raw of Array.isArray(message.reconnecting) ? message.reconnecting : []) {
    const session = normalizeSession(raw, "reconnecting");
    if (session) reconnecting.set(session.id, session);
  }
  const incoming = new Map();
  for (const raw of rawSessions) {
    const session = normalizeSession(raw);
    if (session) incoming.set(session.id, session);
  }
  for (const [sessionId, existing] of sessions) {
    if (!incoming.has(sessionId) && existing.state !== "reconnecting") await stopSession(sessionId, { removeSession: true });
  }
  for (const session of incoming.values()) {
    const existing = sessions.get(session.id);
    if (
      existing?.state === "active" &&
      session.state === "active" &&
      JSON.stringify(existing.access) !== JSON.stringify(session.access)
    ) {
      postSessionRevocation(session.id, "session access changed without an approved upgrade");
      await stopSession(session.id, { removeSession: true });
      continue;
    }
    const merged = { ...existing, ...session, rememberedGrant: session.rememberedGrant === true || existing?.rememberedGrant === true };
    sessions.set(session.id, merged);
    if (session.state === "revoked" || session.state === "pending") {
      await stopSession(session.id, { removeSession: session.state === "revoked" });
      if (session.state === "pending") { sessions.set(session.id, merged); await maybeAutoApprove(merged); }
    } else if (!relaySockets.has(session.id)) {
      // A relay credential is intentionally memory-only. A resurrected worker
      // cannot reconnect an old active task, so remove its authority instead.
      await stopSession(session.id, { removeSession: true });
      postSessionRevocation(session.id, "extension relay state was lost");
    }
  }
  const incomingAccess = new Map();
  for (const raw of Array.isArray(message.pendingAccess) ? message.pendingAccess : []) {
    const request = normalizeAccessRequest(raw);
    if (request) incomingAccess.set(request.id, request);
  }
  accessRequests.clear();
  for (const [id, request] of incomingAccess) accessRequests.set(id, request);
  for (const id of [...approvedAccessRequests.keys()]) {
    if (!incomingAccess.has(id)) approvedAccessRequests.delete(id);
  }
  if (hasRecoveryInventory) {
    await cleanupOrphanedSessionRecovery(new Set([...incoming.keys(), ...reconnecting.keys()]));
  }
}

function sameSessionIdentity(left, right) {
  return (
    !!left &&
    !!right &&
    left.id === right.id &&
    left.controllerId === right.controllerId &&
    left.controllerName === right.controllerName &&
    left.taskLabel === right.taskLabel &&
    left.createdAt === right.createdAt &&
    left.expiresAt === right.expiresAt &&
    JSON.stringify(left.capabilities) === JSON.stringify(right.capabilities)
    && JSON.stringify(left.route) === JSON.stringify(right.route)
  );
}

async function handleAccessPending(message) {
  const request = normalizeAccessRequest(message);
  if (request) accessRequests.set(request.id, request);
}

async function rejectAccessUpdate(sessionId, reason) {
  if (validId(sessionId)) {
    postSessionRevocation(sessionId, reason);
    await stopSession(sessionId, { removeSession: true });
  }
}

async function handleAccessUpdated(message) {
  const session = normalizeSession(message, "active");
  const request = accessRequests.get(message?.accessRequestId);
  const approval = approvedAccessRequests.get(message?.accessRequestId);
  const known = session ? sessions.get(session.id) : null;
  if (
    !session ||
    !request ||
    !approval ||
    request.sessionId !== session.id ||
    approval.id !== request.id ||
    !sameSessionIdentity(known, session) ||
    JSON.stringify(request.requestedAccess) !== JSON.stringify(session.access)
  ) {
    await rejectAccessUpdate(message?.session?.id ?? request?.sessionId, "session access changed without the exact popup-approved upgrade");
    return;
  }
  const anchorId = sessionAnchors.get(session.id);
  if (Number.isInteger(anchorId)) {
    try {
      await chrome.tabs.update(anchorId, { url: sessionPageUrl(session) });
    } catch {
      await rejectAccessUpdate(session.id, "session access page could not be updated");
      return;
    }
  }
  const groupId = sessionGroups.get(session.id);
  if (Number.isInteger(groupId)) {
    try {
      await chrome.tabGroups.update(groupId, { title: taskGroupTitle(session), color: taskGroupColor(session) });
    } catch {
      await rejectAccessUpdate(session.id, "session access indicator could not be updated");
      return;
    }
  }
  sessions.set(session.id, session);
  accessRequests.delete(request.id);
  approvedAccessRequests.delete(request.id);
  await syncAndPersistSessionTabs(session.id);
}

function handleAccessDeclined(message) {
  if (!validId(message?.accessRequestId)) return;
  accessRequests.delete(message.accessRequestId);
  approvedAccessRequests.delete(message.accessRequestId);
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
  await maybeAutoApprove(session);
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
async function handleSessionResuming(message) {
  const sessionUpdate = normalizeSession(message, "reconnecting");
  if (!sessionUpdate || typeof message?.relayUrl !== "string" || relaySockets.has(sessionUpdate?.id)) return;
  let known = sessions.get(sessionUpdate.id);
  if (!known) {
    const recoveryFailure = await restoreSessionRecovery(sessionUpdate);
    if (recoveryFailure) {
      postSessionRevocation(sessionUpdate.id, `browser recovery ${recoveryFailure}`);
      return;
    }
    known = sessions.get(sessionUpdate.id);
  }
  if (known?.state !== "reconnecting" || !sameSessionAuthority(known, sessionUpdate)) {
    postSessionRevocation(sessionUpdate.id, "browser recovery authority changed");
    await stopSession(sessionUpdate.id, { removeSession: true });
    return;
  }
  sessions.set(sessionUpdate.id, { ...known, ...sessionUpdate, rememberedGrant: known.rememberedGrant === true });
  await openSessionRelay(sessionUpdate.id, message.relayUrl);
  await updateSessionPageState(sessionUpdate.id, "active");
}

async function handleSessionStopped(message) {
  const session = normalizeSession(message);
  if (!session) {
    return;
  }
  approvedSessions.delete(session.id);
  await stopSession(session.id, { removeSession: true });
}
async function enumerableBrowserTabs(sessionId, scope) {
  const session = validId(sessionId) && sessionIsActive(sessionId) ? sessions.get(sessionId) : null;
  const tabs = await chrome.tabs.query({});
  return tabs
    .filter((tab) => {
      if (!Number.isInteger(tab.id) || isSessionPageTab(tab) || typeof tab.url !== "string") return false;
      if (scope === "session") return !!session && tabOwners.get(tab.id) === sessionId;
      if (tab.url === "about:blank") return true;
      try {
        const url = new URL(tab.url);
        return url.protocol === "http:" || url.protocol === "https:";
      } catch {
        return false;
      }
    })
    .map((tab) => {
      const accessState = classifyTabAccess(
        tabOwners,
        session ? sessionId : undefined,
        tab.id,
        sessionCanAdoptTab(session, tab),
      );
      return { tabId: tab.id, title: tab.title || "Untitled tab", url: tab.url, ...accessState };
    });
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
    case "listTabs":
      if (typeof message.requestId === "string") {
        postNative({
          version: PROTOCOL_VERSION,
          type: "tabsListed",
          requestId: message.requestId,
          tabs: await enumerableBrowserTabs(message.sessionId, message.scope === "session" ? "session" : "all"),
        });
      }
      return;
    case "claimTab":
      if (typeof message.requestId === "string" && validId(message.sessionId) && Number.isInteger(message.tabId)) {
        try {
          const session = sessions.get(message.sessionId);
          const tab = await chrome.tabs.get(message.tabId);
          if (!sessionIsActive(message.sessionId) || !sessionCanAdoptTab(session, tab)) {
            throw new Error("This tab requires an additional access approval.");
          }
          await shareTab(message.sessionId, message.tabId);
          const record = (await enumerableBrowserTabs(message.sessionId, "session")).find(({ tabId }) => tabId === message.tabId);
          if (!record) throw new Error("The claimed tab is no longer available.");
          postNative({ version: PROTOCOL_VERSION, type: "tabClaimed", requestId: message.requestId, sessionId: message.sessionId, tabId: message.tabId, ok: true, tab: record });
        } catch (error) {
          postNative({ version: PROTOCOL_VERSION, type: "tabClaimed", requestId: message.requestId, sessionId: message.sessionId, tabId: message.tabId, ok: false, error: error instanceof Error ? error.message : String(error) });
        }
      }
      return;
    case "snapshot":
      await handleNativeSnapshot(message);
      refreshBadge();
      return;
    case "sessionResuming":
      await handleSessionResuming(message);
      refreshBadge();
      return;
    case "sessionPending":
      await handleSessionPending(message);
      refreshBadge();
      return;
    case "sessionStarted":
      await handleSessionStarted(message);
      refreshBadge();
      return;
    case "accessPending":
      await handleAccessPending(message);
      refreshBadge();
      return;
    case "accessUpdated":
      await handleAccessUpdated(message);
      refreshBadge();
      return;
    case "accessDeclined":
      handleAccessDeclined(message);
      refreshBadge();
      return;
    case "sessionStopped":
      await handleSessionStopped(message);
      refreshBadge();
      return;
    case "enrollPending":
      if (validId(message.enrollmentId) && typeof message.profileName === "string" && typeof message.profileFingerprint === "string" && Number.isInteger(message.expiresAt)) {
        enrollmentRequests.set(message.enrollmentId, {
          enrollmentId: message.enrollmentId,
          profileName: message.profileName,
          profileFingerprint: message.profileFingerprint,
          expiresAt: message.expiresAt,
        });
        refreshBadge();
      }
      return;
    case "enrollResult": {
      const waiting = typeof message.requestId === "string" ? pendingEnrollConfirms.get(message.requestId) : undefined;
      if (waiting) {
        pendingEnrollConfirms.delete(message.requestId);
        waiting.resolve({ ok: message.ok === true, error: typeof message.error === "string" ? message.error : undefined });
      }
      if (message.ok === true || (typeof message.error === "string" && !/incorrect code$/.test(message.error))) enrollmentRequests.delete(message.enrollmentId);
      refreshBadge();
      return;
    }
    default:
      return;
  }
}

function suspendSessionsForNativeRecovery() {
  for (const [sessionId, session] of sessions) {
    if (session.state === "active") {
      closeRelaySocket(sessionId);
      const reconnecting = { ...session, state: "reconnecting" };
      sessions.set(sessionId, reconnecting);
      void updateSessionPageState(sessionId, "reconnecting");
    } else if (session.state === "revoked") {
      sessions.delete(sessionId);
    }
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
    if (nativeReconnectAllowed) suspendSessionsForNativeRecovery();
    else await stopAllSessions();
  } finally {
    if (!nativeReconnectAllowed) sessions.clear();
    approvedSessions.clear();
    accessRequests.clear();
    approvedAccessRequests.clear();
    enrollmentRequests.clear();
    for (const pending of pendingEnrollConfirms.values()) pending.resolve({ ok: false, error: "companion disconnected" });
    pendingEnrollConfirms.clear();
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

async function removeOrphanedSessionPages() {
  try {
    const recoveryRecords = await storedSessionRecoveryRecords();
    const retainedAnchors = new Set([...recoveryRecords.values()].map((record) => record.anchorId));
    const tabs = await chrome.tabs.query({});
    await Promise.all(
      tabs
        .filter((tab) => isSessionPageTab(tab) && !retainedAnchors.has(tab.id))
        .map((tab) => chrome.tabs.remove(tab.id).catch(() => {})),
    );
  } catch {
    // Browser startup may not expose tabs until the first window exists.
  }
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
  const dispatchNativeMessage = createSerialNativeMessageHandler(
    (message) => handleNativeMessage(message, port, generation),
    () => terminateNativeConnection(port, generation),
  );
  port.onMessage.addListener((message) => {
    void dispatchNativeMessage(message);
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
  try {
    const tabs = await chrome.tabs.query({});
    return tabs
      .filter((tab) => Number.isInteger(tab.id) && tabOwners.get(tab.id) === sessionId && !isSessionPageTab(tab))
      .map(toRelayTabInfo);
  } catch {
    return [];
  }
}

async function syncAndPersistSessionTabs(sessionId) {
  if (!sessionIsActive(sessionId)) {
    return;
  }
  sendRelay(sessionId, { type: "tabs", tabs: await sessionRelayTabs(sessionId) });
  await persistSessionRecovery(sessionId);
}

async function syncActiveRelaySessions() {
  await Promise.all([...readyRelaySessions].map((sessionId) => syncAndPersistSessionTabs(sessionId)));
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
  if (!isCurrentRelaySocketFailure(current, socket, runtimeSuspending)) {
    return;
  }
  if (socket) {
    failedRelaySockets.add(socket);
  }
  const wasReady = readyRelaySessions.has(sessionId);
  reportRelayFailure(sessionId, error);
  if (current === socket) {
    closeRelaySocket(sessionId);
  }
  const session = sessions.get(sessionId);
  if (wasReady && nativeReconnectAllowed && session && (session.state === "active" || session.state === "reconnecting")) {
    sessions.set(sessionId, { ...session, state: "reconnecting" });
    await updateSessionPageState(sessionId, "reconnecting");
    refreshBadge();
    return;
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
  if (relaySockets.get(sessionId) !== socket || !sessions.has(sessionId)) {
    throw new Error("The local relay was removed during startup.");
  }
  const session = sessions.get(sessionId);
  try {
    const firstTab =
      session.state !== "reconnecting" && session.access.tabIds.length > 0
        ? await chrome.tabs.get(session.access.tabIds[0])
        : null;
    readyRelaySessions.add(sessionId);
    if (session.state !== "reconnecting") {
      if (firstTab) {
        await ensureSessionGroup(sessionId, firstTab.windowId);
        for (const tabId of session.access.tabIds) {
          await claimAndGroupTab(sessionId, tabId);
        }
        await syncAndPersistSessionTabs(sessionId);
      } else {
        await ensureSessionGroup(sessionId);
        await persistSessionRecovery(sessionId);
      }
    }
    if (!reportRelayReady(sessionId, relayUrl)) {
      throw new Error("Native Messaging companion disconnected before relay readiness.");
    }
  } catch (error) {
    readyRelaySessions.delete(sessionId);
    throw error;
  }
  if (relaySockets.get(sessionId) !== socket || !sessions.has(sessionId)) {
    throw new Error("The local relay was removed during startup.");
  }
  sessions.set(sessionId, { ...session, state: "active" });
  return true;
}

async function handleRelayClose(sessionId, socket, ready) {
  const disposition = relaySocketCloseDisposition(
    relaySockets.get(sessionId),
    socket,
    ready,
    runtimeSuspending,
  );
  if (disposition === "ignore") {
    return;
  }
  if (disposition === "startupFailure") {
    await failRelaySession(sessionId, socket, "The local relay closed before readiness.");
    return;
  }
  await failRelaySession(sessionId, socket, "The local relay disconnected.");
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
  if (!sessionIsActive(sessionId)) {
    throw new Error("Only an active task session can control tabs.");
  }
  let tab = await chrome.tabs.get(tabId);
  if (!sessionOwnsTab(tabOwners, sessionId, tabId)) {
    const session = sessions.get(sessionId);
    if (!sessionCanAdoptTab(session, tab)) {
      throw new Error("This tab is outside the session's approved tab, domain, or full-access grant.");
    }
    await claimAndGroupTab(sessionId, tabId);
    tab = await chrome.tabs.get(tabId);
  }
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

async function ensureSessionGroup(sessionId, windowId = null, allowReconnecting = false) {
  const session = sessions.get(sessionId);
  if (!session) {
    throw new Error("The task session is no longer available.");
  }

  const knownGroupId = sessionGroups.get(sessionId);
  const knownAnchorId = sessionAnchors.get(sessionId);
  if (Number.isInteger(knownGroupId) && Number.isInteger(knownAnchorId)) {
    try {
      const anchor = await chrome.tabs.get(knownAnchorId);
      await requireSessionGroupInWindow(sessionId, knownGroupId, anchor.windowId);
      if (anchor.groupId !== knownGroupId) {
        await chrome.tabs.group({ tabIds: [knownAnchorId], groupId: knownGroupId });
      }
      return knownGroupId;
    } catch {
      sessionAnchors.delete(sessionId);
      sessionGroups.delete(sessionId);
    }
  }

  const inFlight = creatingSessionGroups.get(sessionId);
  if (inFlight) {
    return await inFlight;
  }

  let resolveCreation;
  let rejectCreation;
  const creation = new Promise((resolve, reject) => {
    resolveCreation = resolve;
    rejectCreation = reject;
  });
  void creation.catch(() => {});
  creatingSessionGroups.set(sessionId, creation);
  let anchorId = null;
  let groupId = sessionGroups.get(sessionId);
  try {
    const anchor = await chrome.tabs.create({
      url: sessionPageUrl(session),
      active: false,
      ...(Number.isInteger(windowId) ? { windowId } : {}),
    });
    if (!Number.isInteger(anchor.id)) {
      throw new Error("Browser did not return a session tab ID.");
    }
    anchorId = anchor.id;

    if (Number.isInteger(groupId)) {
      await requireSessionGroupInWindow(sessionId, groupId, anchor.windowId);
      await chrome.tabs.group({ tabIds: [anchorId], groupId });
    } else {
      groupId = await chrome.tabs.group({ tabIds: [anchorId], createProperties: { windowId: anchor.windowId } });
    }
    await chrome.tabGroups.update(groupId, {
      title: taskGroupTitle(session),
      color: taskGroupColor(session),
    });
    if (!sessionIsActive(sessionId) && !(allowReconnecting && sessions.get(sessionId)?.state === "reconnecting")) {
      throw new Error("Task session stopped while its group was being created.");
    }
    sessionAnchors.set(sessionId, anchorId);
    sessionGroups.set(sessionId, groupId);
    resolveCreation(groupId);
    return groupId;
  } catch (error) {
    if (Number.isInteger(anchorId)) {
      try {
        await chrome.tabs.ungroup([anchorId]);
      } catch {
        // The browser may already have removed the group.
      }
      try {
        await chrome.tabs.remove(anchorId);
      } catch {
        // The browser may already have removed the anchor.
      }
    }
    rejectCreation(error);
    throw error;
  } finally {
    if (creatingSessionGroups.get(sessionId) === creation) {
      creatingSessionGroups.delete(sessionId);
    }
  }
}

async function claimAndGroupTab(sessionId, tabId) {
  if (!Number.isInteger(tabId)) {
    throw new Error("No tab was selected.");
  }
  if (!sessionIsActive(sessionId)) {
    throw new Error("Only an active task session can control tabs.");
  }

  let claimed = false;
  try {
    const tab = await chrome.tabs.get(tabId);
    if (isSessionPageTab(tab)) {
      throw new Error("The Agent Tab Bridge session page is not a shareable browser tab.");
    }
    const claim = claimTab(tabOwners, sessionId, tabId);
    if (!claim.ok) {
      throw new Error("This tab is already shared with another task session.");
    }
    claimed = true;
    const groupId = await ensureSessionGroup(sessionId, tab.windowId);
    await requireSessionGroupInWindow(sessionId, groupId, tab.windowId);
    if (tab.groupId !== groupId) {
      await chrome.tabs.group({ tabIds: [tabId], groupId });
    }
  } catch (error) {
    if (claimed) {
      releaseTab(tabOwners, sessionId, tabId);
    }
    throw error;
  }
}

async function shareTab(sessionId, tabId) {
  await claimAndGroupTab(sessionId, tabId);
  await syncAndPersistSessionTabs(sessionId);
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
    if (inFlight.sessionId !== sessionId) {
      throw new Error("This tab is already shared with another task session.");
    }
    return await inFlight.promise;
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

  const record = { sessionId, promise: attaching };
  attachingTabs.set(tabId, record);
  try {
    return await attaching;
  } finally {
    if (attachingTabs.get(tabId) === record) {
      attachingTabs.delete(tabId);
    }
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
  if (notifyRelay && sessionIsActive(sessionId)) {
    sendRelay(sessionId, { type: "detached", tabId, reason });
    await syncAndPersistSessionTabs(sessionId);
  }
}

async function unshareTab(sessionId, tabId) {
  if (!sessionOwnsTab(tabOwners, sessionId, tabId)) {
    throw new Error("This tab is not shared with the selected task session.");
  }
  await revokeTabAccess(sessionId, tabId, "user removed shared tab", { notifyRelay: false });
  await syncAndPersistSessionTabs(sessionId);
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

    const groupId = sessionGroups.get(sessionId);
    const anchorId = sessionAnchors.get(sessionId);
    if (Number.isInteger(groupId)) {
      try {
        const groupTabs = await chrome.tabs.query({ groupId });
        const groupTabIds = groupTabs
          .map((tab) => tab.id)
          .filter((tabId) => Number.isInteger(tabId));
        if (groupTabIds.length > 0) {
          await chrome.tabs.ungroup(groupTabIds);
        }
      } catch {
        // The browser may already have removed the group.
      }
    }
    sessionGroups.delete(sessionId);
    sessionAnchors.delete(sessionId);
    if (Number.isInteger(anchorId)) {
      try {
        await chrome.tabs.remove(anchorId);
      } catch {
        // The browser may already have removed the anchor.
      }
    }
    await removeSessionRecovery(sessionId);
    if (removeSession) {
      sessions.delete(sessionId);
      approvedSessions.delete(sessionId);
      for (const [requestId, request] of accessRequests) {
        if (request.sessionId === sessionId) {
          accessRequests.delete(requestId);
          approvedAccessRequests.delete(requestId);
        }
      }
    }
  })();
  stoppingSessions.set(sessionId, task);
  try {
    await task;
  } finally {
    stoppingSessions.delete(sessionId);
    refreshBadge();
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
  sessionAnchors.clear();
  tabOwners.clear();
  approvedSessions.clear();
  await cleanupOrphanedSessionRecovery();
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
        const session = sessions.get(sessionId);
        if (!sessionAllowsUrl(session, message.url)) {
          throw new Error("Opening this URL is outside the session's approved domain or full-access grant.");
        }
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
        await syncAndPersistSessionTabs(sessionId);
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
  accessRequests.clear();
  approvedAccessRequests.clear();
  enrollmentRequests.clear();
  for (const pending of pendingEnrollConfirms.values()) pending.resolve({ ok: false, error: "companion disconnected" });
  pendingEnrollConfirms.clear();
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
  await standingGrantsReady;
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
      .filter((session) => session.state === "reconnecting" || sessionIsActive(session.id))
      .map(sessionDto),
    pendingAccess: [...accessRequests.values()].map((request) => {
      const session = sessions.get(request.sessionId);
      return {
        ...request,
        delta: { ...request.delta, tabIds: [...request.delta.tabIds], domains: [...request.delta.domains] },
        requestedAccess: { ...request.requestedAccess, tabIds: [...request.requestedAccess.tabIds], domains: [...request.requestedAccess.domains] },
        taskLabel: session?.taskLabel ?? "Unnamed task",
        controllerId: session?.controllerId ?? "",
        controllerName: session?.controllerName ?? "Unnamed controller",
        machineLabel: session?.machineLabel,
        route: session?.route,
        currentAccess: session ? { ...session.access, tabIds: [...session.access.tabIds], domains: [...session.access.domains] } : null,
      };
    }),
    pendingEnrollments: [...enrollmentRequests.values()].filter((request) => request.expiresAt > Date.now()).map((request) => ({ ...request, id: request.enrollmentId })),
    enrolledProfiles: enrolledProfiles.map((profile) => ({ ...profile, id: profile.principalId })),
    standingGrants: standingGrants.map((grant) => ({ ...grant, id: grant.controllerId, level: grant.route.accessCeiling.level, domains: [...grant.route.accessCeiling.domains], route: { ...grant.route, accessCeiling: { ...grant.route.accessCeiling, tabIds: [...grant.route.accessCeiling.tabIds], domains: [...grant.route.accessCeiling.domains] } } })),
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
      case "connectCompanion":
        nativeReconnectAllowed = true;
        if (!nativePort) {
          await connectNative();
        }
        sendResponse({ ok: true });
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
        await standingGrantsReady;
        approveSessionNow(session);
        if (message.remember === true) await rememberGrant(session);
        sendResponse({ ok: true });
        return;
      }
      case "revokeGrant": {
        await standingGrantsReady;
        if (!validId(message.controllerId)) throw new Error("No standing grant was selected.");
        standingGrants = standingGrants.filter((grant) => grant.controllerId !== message.controllerId);
        await saveStandingGrants();
        sendResponse({ ok: true });
        return;
      }
      case "revokeProfile": {
        await standingGrantsReady;
        const profile = enrolledProfiles.find((record) => record.name === message.profileName);
        if (!profile) throw new Error("This agent profile is not enrolled.");
        postNative({ version: PROTOCOL_VERSION, type: "revokeProfile", requestId: newRequestId(), profileName: profile.name });
        standingGrants = standingGrants.filter((grant) => grant.controllerId !== profile.principalId);
        await saveStandingGrants();
        sendResponse({ ok: true });
        return;
      }
      case "approveAccess": {
        const request = accessRequests.get(message.accessRequestId);
        if (!request) throw new Error("This access upgrade is not awaiting approval.");
        if (approvedAccessRequests.has(request.id)) throw new Error("This access upgrade approval is already pending.");
        approvedAccessRequests.set(request.id, request);
        try {
          postNative({
            version: PROTOCOL_VERSION,
            type: "approveAccess",
            requestId: newRequestId(),
            accessRequestId: request.id,
            sessionId: request.sessionId,
            requestedAccess: { ...request.requestedAccess, tabIds: [...request.requestedAccess.tabIds], domains: [...request.requestedAccess.domains] },
          });
        } catch (error) {
          approvedAccessRequests.delete(request.id);
          throw error;
        }
        sendResponse({ ok: true });
        return;
      }
      case "declineAccess": {
        const request = accessRequests.get(message.accessRequestId);
        if (!request) throw new Error("This access upgrade is not awaiting approval.");
        postNative({
          version: PROTOCOL_VERSION,
          type: "declineAccess",
          requestId: newRequestId(),
          accessRequestId: request.id,
          sessionId: request.sessionId,
        });
        accessRequests.delete(request.id);
        approvedAccessRequests.delete(request.id);
        sendResponse({ ok: true });
        refreshBadge();
        return;
      }
      case "confirmEnrollment": {
        const request = enrollmentRequests.get(message.enrollmentId);
        if (!request) throw new Error("This enrollment is not awaiting a code.");
        if (typeof message.code !== "string" || !/^\d{6}$/.test(message.code)) throw new Error("Enter the 6-digit code shown by the requesting agent.");
        const requestId = newRequestId();
        const outcome = new Promise((resolve) => {
          pendingEnrollConfirms.set(requestId, { resolve });
          setTimeout(() => {
            if (pendingEnrollConfirms.delete(requestId)) resolve({ ok: false, error: "companion did not answer" });
          }, 5000);
        });
        postNative({
          version: PROTOCOL_VERSION,
          type: "confirmEnrollment",
          requestId,
          enrollmentId: request.enrollmentId,
          code: message.code,
        });
        const result = await outcome;
        refreshBadge();
        if (!result.ok) throw new Error(result.error ?? "enrollment failed");
        sendResponse({ ok: true, profileName: request.profileName });
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
  void (async () => {
    if (typeof changeInfo.url === "string") {
      const ownerSessionId = tabOwners.get(tabId);
      const ownerSession = ownerSessionId ? sessions.get(ownerSessionId) : null;
      if (
        ownerSession?.access.level === "domains" &&
        !ownerSession.access.tabIds.includes(tabId) &&
        !sessionAllowsUrl(ownerSession, changeInfo.url)
      ) {
        await revokeTabAccess(ownerSessionId, tabId, "tab left its approved domains");
        await syncActiveRelaySessions();
        return;
      }
    }
    if (typeof changeInfo.groupId === "number") {
      const anchorSessionId = [...sessionAnchors.entries()].find(([, anchorId]) => anchorId === tabId)?.[0];
      if (anchorSessionId) {
        const groupId = sessionGroups.get(anchorSessionId);
        if (
          sessionIsActive(anchorSessionId) &&
          Number.isInteger(groupId) &&
          changeInfo.groupId !== groupId &&
          !revokingTabs.has(tabId)
        ) {
          revokingTabs.add(tabId);
          try {
            await chrome.tabs.group({ tabIds: [tabId], groupId });
          } finally {
            revokingTabs.delete(tabId);
          }
        }
      } else {
        const ownerSessionId = tabOwners.get(tabId);
        const groupOwnerSessionId = [...sessionGroups.entries()].find(([, groupId]) => groupId === changeInfo.groupId)?.[0];
        if (ownerSessionId) {
          if (!creatingSessionGroups.has(ownerSessionId) && sessionGroups.get(ownerSessionId) !== changeInfo.groupId) {
            if (!revokingTabs.has(tabId)) {
              revokingTabs.add(tabId);
              try {
                if (groupOwnerSessionId && groupOwnerSessionId !== ownerSessionId) {
                  await chrome.tabs.ungroup([tabId]);
                }
                await revokeTabAccess(ownerSessionId, tabId, "tab left its task group");
              } catch {
                releaseTab(tabOwners, ownerSessionId, tabId);
              } finally {
                revokingTabs.delete(tabId);
              }
            }
          }
        } else if (groupOwnerSessionId && !revokingTabs.has(tabId)) {
          if (!sessionIsActive(groupOwnerSessionId)) {
            await chrome.tabs.ungroup([tabId]).catch(() => {});
          } else {
            const claim = claimTab(tabOwners, groupOwnerSessionId, tabId);
            if (!claim.ok) {
              // Ownership is exclusive. Do not let a tab owned by another session
              // cross-claim merely because it was dragged over this group.
              await chrome.tabs.ungroup([tabId]).catch(() => {});
            }
          }
        }
      }
    }
    await syncActiveRelaySessions();
  })().catch(() => {});
});

chrome.tabs.onCreated.addListener((tab) => {
  void cleanupOrphanedRecoveryGroup(tab.groupId).then(() => syncActiveRelaySessions()).catch(() => {});
});

chrome.tabs.onRemoved.addListener((tabId) => {
  const anchorSessionId = [...sessionAnchors.entries()].find(([, anchorId]) => anchorId === tabId)?.[0];
  if (anchorSessionId) {
    sessionAnchors.delete(anchorSessionId);
    const session = sessions.get(anchorSessionId);
    const groupId = sessionGroups.get(anchorSessionId);
    if (!runtimeSuspending && nativeState === "connected" && session?.state === "active" && Number.isInteger(groupId)) {
      void chrome.tabGroups.get(groupId)
        .then((group) => ensureSessionGroup(anchorSessionId, group.windowId))
        .then(() => persistSessionRecovery(anchorSessionId))
        .catch(() => {});
    }
  }
  const sessionId = tabOwners.get(tabId);
  attachedTabs.delete(tabId);
  if (sessionId) {
    releaseTab(tabOwners, sessionId, tabId);
  }
  void syncActiveRelaySessions().catch(() => {});
});


chrome.tabGroups.onCreated.addListener((group) => {
  void cleanupOrphanedRecoveryGroup(group.id).catch(() => {});
});

chrome.tabGroups.onRemoved.addListener((group) => {
  const sessionId = [...sessionGroups.entries()].find(([, groupId]) => groupId === group.id)?.[0];
  if (!sessionId) {
    return;
  }
  void stopSession(sessionId, { removeSession: true })
    .then(() => postSessionRevocation(sessionId, "task session group was removed"))
    .catch(() => {});
});

async function initializeExtension() {
  await removeOrphanedSessionPages();
  await connectNative();
}

chrome.runtime.onSuspend.addListener(() => {
  runtimeSuspending = true;
});
chrome.runtime.onSuspendCanceled.addListener(() => {
  runtimeSuspending = false;
  for (const [sessionId, socket] of relaySockets) {
    if (socket.readyState === WebSocket.CLOSED) {
      void failRelaySession(sessionId, socket, "The local relay closed during canceled extension suspension.").catch(() => {});
    }
  }
});
chrome.runtime.onStartup.addListener(() => void initializeExtension().catch(() => {}));
chrome.runtime.onInstalled.addListener(() => void initializeExtension().catch(() => {}));
void initializeExtension().catch(() => {});

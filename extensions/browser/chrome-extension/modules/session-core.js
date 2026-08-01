import {
  AGENT_TAB_BRIDGE_RELAY_PROTOCOL as RELAY_PROTOCOL,
  AGENT_TAB_BRIDGE_TOKEN_PROTOCOL_PREFIX as RELAY_TOKEN_PROTOCOL_PREFIX,
  buildRelayWsProtocols,
  reconnectDelayMs,
} from "./relay-core.js";

export {
  RELAY_PROTOCOL,
  RELAY_TOKEN_PROTOCOL_PREFIX,
  buildRelayWsProtocols,
  reconnectDelayMs,
};

/**
 * Parse the ephemeral loopback URL supplied over authenticated Native Messaging.
 * The token is returned only for constructing the immediately-opened WebSocket;
 * callers must never persist or expose it.
 */
export function parseRelayPairingUrl(raw) {
  const value = String(raw ?? "").trim();
  const separator = value.indexOf("#");
  if (separator <= 0 || separator !== value.lastIndexOf("#")) {
    return null;
  }

  const relayUrl = value.slice(0, separator);
  const token = value.slice(separator + 1);
  if (!/^[A-Za-z0-9_-]+$/.test(token)) {
    return null;
  }

  let parsed;
  try {
    parsed = new URL(relayUrl);
  } catch {
    return null;
  }

  const port = Number.parseInt(parsed.port, 10);
  if (
    parsed.protocol !== "ws:" ||
    parsed.hostname !== "127.0.0.1" ||
    !Number.isInteger(port) ||
    port < 1 ||
    port > 65_535 ||
    parsed.pathname !== "/extension" ||
    parsed.search ||
    parsed.username ||
    parsed.password
  ) {
    return null;
  }

  return { relayUrl: parsed.toString(), token };
}


/** A group is authorized only by its recorded numeric ID, never its title. */
export function sessionOwnsGroup(sessionGroups, sessionId, groupId) {
  return Number.isInteger(groupId) && typeof sessionId === "string" && sessionGroups.get(sessionId) === groupId;
}

/** Whether the supplied tab is still authorized for this exact session. */
export function sessionOwnsTab(tabOwners, sessionId, tabId) {
  return Number.isInteger(tabId) && typeof sessionId === "string" && tabOwners.get(tabId) === sessionId;
}

/**
 * Atomically claim an unowned tab for a session. A claim for its current owner
 * is idempotent, while a claim from another session never changes ownership.
 */
export function claimTab(tabOwners, sessionId, tabId) {
  if (!Number.isInteger(tabId) || typeof sessionId !== "string" || !sessionId) {
    return { ok: false };
  }
  const currentOwner = tabOwners.get(tabId);
  if (currentOwner && currentOwner !== sessionId) {
    return { ok: false, ownerSessionId: currentOwner };
  }
  tabOwners.set(tabId, sessionId);
  return { ok: true };
}

/** Release a tab only when the requesting session remains its owner. */
export function releaseTab(tabOwners, sessionId, tabId) {
  if (!sessionOwnsTab(tabOwners, sessionId, tabId)) {
    return false;
  }
  tabOwners.delete(tabId);
  return true;
}

/** Return every owned tab and clear each claim for the stopped session. */
export function releaseSessionTabs(tabOwners, sessionId) {
  const tabIds = [];
  for (const [tabId, ownerSessionId] of tabOwners) {
    if (ownerSessionId === sessionId) {
      tabIds.push(tabId);
      tabOwners.delete(tabId);
    }
  }
  return tabIds;
}

/** List current tab ids for one session without granting ownership by title. */
export function sessionTabIds(tabOwners, sessionId) {
  const tabIds = [];
  for (const [tabId, ownerSessionId] of tabOwners) {
    if (ownerSessionId === sessionId) {
      tabIds.push(tabId);
    }
  }
  return tabIds;
}
/** Describe ownership and whether a session can claim a tab without new approval. */
export function classifyTabAccess(tabOwners, sessionId, tabId, canAdopt) {
  const owner = tabOwners.get(tabId);
  if (typeof sessionId === "string" && owner === sessionId) {
    return { ownership: "currentSession", claimability: "alreadyShared" };
  }
  if (typeof owner === "string") {
    return { ownership: "otherSession", claimability: "blocked" };
  }
  return {
    ownership: "unclaimed",
    claimability: canAdopt ? "claimable" : "approvalRequired",
  };
}


function sameArray(left, right) {
  return Array.isArray(left) && Array.isArray(right) && left.length === right.length && left.every((value, index) => value === right[index]);
}

function sameAccess(left, right) {
  return !!left && !!right && left.level === right.level && sameArray(left.tabIds, right.tabIds) && sameArray(left.domains, right.domains);
}

function sameRoute(left, right) {
  return !!left && !!right &&
    left.kind === right.kind &&
    left.endpointId === right.endpointId &&
    left.controllerPrincipalId === right.controllerPrincipalId &&
    left.routePolicy === right.routePolicy &&
    sameAccess(left.accessCeiling, right.accessCeiling) &&
    left.hubId === right.hubId &&
    left.routeId === right.routeId &&
    left.streamId === right.streamId;
}

/** Name the first authority-bearing field that differs, or null for an exact match. */
export function sessionAuthorityMismatchField(left, right) {
  if (!left || !right) return "record";
  if (left.id !== right.id) return "id";
  if (left.controllerId !== right.controllerId) return "controllerId";
  if (left.controllerName !== right.controllerName) return "controllerName";
  if (left.taskLabel !== right.taskLabel) return "taskLabel";
  if (left.createdAt !== right.createdAt) return "createdAt";
  if (left.expiresAt !== right.expiresAt) return "expiresAt";
  if (!sameArray(left.capabilities, right.capabilities)) return "capabilities";
  if (!sameAccess(left.access, right.access)) return "access";
  if (!sameRoute(left.route, right.route)) return "route";
  return null;
}

/** Compare every authority-bearing field while deliberately ignoring lifecycle state. */
export function sameSessionAuthority(left, right) {
  return sessionAuthorityMismatchField(left, right) === null;
}

/**
 * A host may transition only the exact popup-approved pending session to
 * active. Display text, expiry, controller, requested capability, access
 * scope, and route are authority-bearing and must remain unchanged.
 */
export function matchesSessionAuthority(pending, active) {
  return (
    pending?.state === "pending" &&
    active?.state === "active" &&
    sameSessionAuthority(pending, active)
  );
}

export function makeSessionRecoveryRecord(session, groupId, anchorId, tabIds) {
  if (
    !session ||
    !Number.isInteger(groupId) ||
    groupId < 0 ||
    !Number.isInteger(anchorId) ||
    anchorId < 0 ||
    !Array.isArray(tabIds) ||
    tabIds.some((tabId) => !Number.isInteger(tabId) || tabId < 0) ||
    new Set(tabIds).size !== tabIds.length
  ) {
    return null;
  }
  return {
    version: 1,
    session,
    groupId,
    anchorId,
    tabIds: [...tabIds].sort((left, right) => left - right),
  };
}

export function validateSessionRecoveryRecord(value, resumedSession) {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).length !== 5 ||
    !["version", "session", "groupId", "anchorId", "tabIds"].every((key) => Object.hasOwn(value, key)) ||
    value.version !== 1 ||
    !["active", "reconnecting"].includes(value.session?.state) ||
    resumedSession?.state !== "reconnecting" ||
    !sameSessionAuthority(value.session, resumedSession)
  ) {
    return null;
  }
  return makeSessionRecoveryRecord(value.session, value.groupId, value.anchorId, value.tabIds);
}

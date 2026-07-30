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

/**
 * A host may transition only the exact popup-approved pending session to
 * active. Display text, expiry, controller, and requested capability are all
 * authority-bearing for that approval and must remain unchanged.
 */
export function matchesSessionAuthority(pending, active) {
  return (
    !!pending &&
    !!active &&
    pending.state === "pending" &&
    active.state === "active" &&
    pending.id === active.id &&
    pending.controllerId === active.controllerId &&
    pending.controllerName === active.controllerName &&
    pending.taskLabel === active.taskLabel &&
    pending.createdAt === active.createdAt &&
    pending.expiresAt === active.expiresAt &&
    Array.isArray(pending.capabilities) &&
    Array.isArray(active.capabilities) &&
    pending.capabilities.length === active.capabilities.length &&
    pending.capabilities.every((capability, index) => capability === active.capabilities[index])
  );
}

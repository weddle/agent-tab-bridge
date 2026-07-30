// Pure helpers for the Agent Tab Bridge extension. They do not use chrome.* so
// pairing and protocol behavior remains independently testable.

/** The tab group that forms the visible consent boundary. */
export const AGENT_TAB_GROUP_TITLE = "Agent Tabs";
export const AGENT_TAB_BRIDGE_RELAY_PROTOCOL = "agent-tab-bridge-relay";
export const AGENT_TAB_BRIDGE_TOKEN_PROTOCOL_PREFIX = "agent-tab-bridge-token.";

const CHROME_GROUP_COLORS = {
  grey: [128, 128, 128],
  blue: [66, 133, 244],
  red: [219, 68, 55],
  yellow: [244, 180, 0],
  green: [15, 157, 88],
  pink: [233, 30, 99],
  purple: [156, 39, 176],
  cyan: [0, 188, 212],
  orange: [255, 112, 32],
};

/**
 * Parse the one-time loopback pairing value handed off by the relay CLI.
 * Only a token-bearing local extension endpoint is accepted; the fragment is
 * deliberately excluded from the resulting WebSocket URL.
 */
export function parsePairingString(raw) {
  const pairing = String(raw ?? "").trim();
  const hashIndex = pairing.indexOf("#");
  if (hashIndex <= 0) {
    return null;
  }

  const relayUrl = pairing.slice(0, hashIndex);
  const token = pairing.slice(hashIndex + 1);
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

/** Build WebSocket subprotocols without putting the relay secret in the URL. */
export function buildRelayWsProtocols(token) {
  return [
    AGENT_TAB_BRIDGE_RELAY_PROTOCOL,
    `${AGENT_TAB_BRIDGE_TOKEN_PROTOCOL_PREFIX}${token}`,
  ];
}

/** Exponential reconnect backoff: 1s, 2s, 4s ... capped at 30s. */
export function reconnectDelayMs(attempt) {
  const capped = Math.min(Math.max(0, attempt), 5);
  return Math.min(1000 * 2 ** capped, 30_000);
}

/** Map a hex color to the closest Chrome tab-group color name. */
export function nearestGroupColor(hex) {
  const match = /^#?([0-9a-f]{6})$/i.exec(String(hex ?? "").trim());
  if (!match) {
    return "blue";
  }
  const value = Number.parseInt(match[1], 16);
  const r = (value >> 16) & 0xff;
  const g = (value >> 8) & 0xff;
  const b = value & 0xff;
  let best = "blue";
  let bestDistance = Number.POSITIVE_INFINITY;
  for (const [name, [cr, cg, cb]] of Object.entries(CHROME_GROUP_COLORS)) {
    const distance = (r - cr) ** 2 + (g - cg) ** 2 + (b - cb) ** 2;
    if (distance < bestDistance) {
      bestDistance = distance;
      best = name;
    }
  }
  return best;
}

/** Normalize a chrome.tabs.Tab into the relay's tab-info shape. */
export function toRelayTabInfo(tab) {
  return {
    tabId: tab.id,
    url: tab.url ?? "",
    title: tab.title ?? "",
    active: tab.active === true,
  };
}

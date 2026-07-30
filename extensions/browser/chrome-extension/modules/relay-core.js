// Pure helpers for the Agent Tab Bridge extension. They do not use chrome.* so
// relay protocol behavior remains independently testable.

export const AGENT_TAB_BRIDGE_RELAY_PROTOCOL = "agent-tab-bridge-relay";
export const AGENT_TAB_BRIDGE_TOKEN_PROTOCOL_PREFIX = "agent-tab-bridge-token.";



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


/** Normalize a chrome.tabs.Tab into the relay's tab-info shape. */
export function toRelayTabInfo(tab) {
  return {
    tabId: tab.id,
    url: tab.url ?? "",
    title: tab.title ?? "",
    active: tab.active === true,
  };
}

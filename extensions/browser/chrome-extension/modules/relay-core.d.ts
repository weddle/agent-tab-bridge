// Types for the extension's pure-logic module (the runtime is plain ESM JS so
// it can load unbundled in Brave). Kept in sync with relay-core.js.

export function buildRelayWsProtocols(token: string): string[];

export function reconnectDelayMs(attempt: number): number;
export function isCurrentRelaySocketFailure<T>(
  currentSocket: T | undefined,
  failedSocket: T | null,
  runtimeSuspending?: boolean,
): boolean;
export function relaySocketCloseDisposition<T>(
  currentSocket: T | undefined,
  closedSocket: T,
  ready: boolean,
  runtimeSuspending?: boolean,
): "ignore" | "startupFailure" | "disconnect";


export function toRelayTabInfo(tab: {
  id: number;
  url?: string;
  title?: string;
  active?: boolean;
}): { tabId: number; url: string; title: string; active: boolean };

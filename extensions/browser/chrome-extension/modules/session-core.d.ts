export const RELAY_PROTOCOL: string;
export const RELAY_TOKEN_PROTOCOL_PREFIX: string;

export function parseRelayPairingUrl(raw: unknown): { relayUrl: string; token: string } | null;
export function buildRelayWsProtocols(token: string): string[];
export function reconnectDelayMs(attempt: number): number;

export function sessionOwnsGroup(sessionGroups: Map<string, number>, sessionId: string, groupId: number): boolean;
export function sessionOwnsTab(tabOwners: Map<number, string>, sessionId: string, tabId: number): boolean;
export function claimTab(
  tabOwners: Map<number, string>,
  sessionId: string,
  tabId: number,
): { ok: boolean; ownerSessionId?: string };
export function releaseTab(tabOwners: Map<number, string>, sessionId: string, tabId: number): boolean;
export function releaseSessionTabs(tabOwners: Map<number, string>, sessionId: string): number[];
export function sessionTabIds(tabOwners: Map<number, string>, sessionId: string): number[];
export type TabAccessState = {
  ownership: "unclaimed" | "currentSession" | "otherSession";
  claimability: "alreadyShared" | "claimable" | "approvalRequired" | "blocked";
};
export function classifyTabAccess(
  tabOwners: Map<number, string>,
  sessionId: string | undefined,
  tabId: number,
  canAdopt: boolean,
): TabAccessState;


export type SessionAuthorityRecord = {
  id: string;
  controllerId: string;
  controllerName: string;
  taskLabel: string;
  capabilities: string[];
  access: {
    level: "selectedTabs" | "domains" | "full";
    tabIds: number[];
    domains: string[];
  };
  createdAt: number;
  expiresAt: number | null;
  state: "pending" | "active" | "reconnecting" | "revoked";
  route: Record<string, unknown>;
};
export function sessionAuthorityMismatchField(left: SessionAuthorityRecord, right: SessionAuthorityRecord): string | null;
export function sameSessionAuthority(left: SessionAuthorityRecord, right: SessionAuthorityRecord): boolean;
export function matchesSessionAuthority(
  pending: SessionAuthorityRecord,
  active: SessionAuthorityRecord,
): boolean;
export type SessionRecoveryRecord = {
  version: 1;
  session: SessionAuthorityRecord;
  groupId: number;
  anchorId: number;
  tabIds: number[];
};
export function makeSessionRecoveryRecord(
  session: SessionAuthorityRecord,
  groupId: number,
  anchorId: number,
  tabIds: number[],
): SessionRecoveryRecord | null;
export function validateSessionRecoveryRecord(
  value: unknown,
  resumedSession: SessionAuthorityRecord,
): SessionRecoveryRecord | null;

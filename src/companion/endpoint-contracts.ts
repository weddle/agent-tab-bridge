import { isSessionAccess, type SessionAccess } from "./session-access.js";

/** Approved endpoint/session recovery grace: approximately two minutes. */
export const ENDPOINT_RECOVERY_GRACE_MS = 2 * 60_000;

/** Stable IDs are SPKI fingerprints; principal IDs use this same representation. */
export type MachineId = string;
export type EndpointId = string;
export type PrincipalId = string;

export interface MachineIdentity {
  machineId: MachineId;
}

/** One browser-profile consent authority, identified by its pinned extension key. */
export interface EndpointIdentity {
  endpointId: EndpointId;
  extensionId: string;
  extensionFingerprint: PrincipalId;
  publicKeySpki: string;
  label: string;
  pinnedAt: number;
}

export type RouteKind = "local" | "routed";
export type RoutePolicy = "localOnly" | "routed";

/**
 * Provenance attached to every authority-bearing record. Hub, route, and stream
 * IDs are deliberately present now and remain null until the routed path ships.
 */
export interface RouteProvenance {
  kind: RouteKind;
  endpointId: EndpointId;
  controllerPrincipalId: PrincipalId;
  routePolicy: RoutePolicy;
  accessCeiling: SessionAccess;
  hubId: string | null;
  routeId: string | null;
  streamId: string | null;
}

export interface RouteAwareSessionRecord {
  id: string;
  controllerPrincipalId: PrincipalId;
  displayControllerName: string;
  taskLabel: string;
  requestedCapabilities: readonly "cdp"[];
  access: SessionAccess;
  createdAt: number;
  expiresAt: number | null;
  state: "pending" | "active" | "reconnecting" | "revoked";
  route: RouteProvenance;
}

/** Browser-owned remembered authority. A grant is never route-agnostic. */
export interface StandingGrantRecord {
  version: 2;
  controllerPrincipalId: PrincipalId;
  controllerName: string;
  route: RouteProvenance;
  createdAt: number;
}

const fingerprint = (value: unknown): value is string => typeof value === "string" && /^sha256\/[A-Za-z0-9+/=_-]+$/.test(value) && value.length <= 256;
const identifier = (value: unknown): value is string => typeof value === "string" && value.length > 0 && value.length <= 256;
const nullableIdentifier = (value: unknown): value is string | null => value === null || identifier(value);

export function localRouteProvenance(endpointId: EndpointId, controllerPrincipalId: PrincipalId, accessCeiling: SessionAccess): RouteProvenance {
  return { kind: "local", endpointId, controllerPrincipalId, routePolicy: "localOnly", accessCeiling, hubId: null, routeId: null, streamId: null };
}

export function isRouteProvenance(value: unknown): value is RouteProvenance {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const route = value as Record<string, unknown>;
  if (Object.keys(route).length !== 8 || !["kind", "endpointId", "controllerPrincipalId", "routePolicy", "accessCeiling", "hubId", "routeId", "streamId"].every((key) => Object.hasOwn(route, key))) return false;
  if (!fingerprint(route.endpointId) || !fingerprint(route.controllerPrincipalId) || !isSessionAccess(route.accessCeiling) || !nullableIdentifier(route.hubId) || !nullableIdentifier(route.routeId) || !nullableIdentifier(route.streamId)) return false;
  return (route.kind === "local" && route.routePolicy === "localOnly" && route.hubId === null && route.routeId === null && route.streamId === null)
    || (route.kind === "routed" && route.routePolicy === "routed");
}

export function sameRouteProvenance(left: RouteProvenance, right: RouteProvenance): boolean {
  const leftBytes = canonicalRouteAwareRecord(left);
  const rightBytes = canonicalRouteAwareRecord(right);
  return leftBytes.byteLength === rightBytes.byteLength && leftBytes.every((byte, index) => byte === rightBytes[index]);
}

/**
 * Deterministic UTF-8 JSON for every route-bearing DTO. Callers validate their
 * enclosing record first; this rejects a malformed route rather than signing it.
 */
export function canonicalRouteAwareRecord(value: RouteProvenance | RouteAwareSessionRecord | StandingGrantRecord): Uint8Array {
  const route = "route" in value ? value.route : value;
  if (!isRouteProvenance(route)) throw new TypeError("invalid route provenance");
  return new TextEncoder().encode(canonicalJson(value));
}

function canonicalJson(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) throw new TypeError("canonical DTO numbers must be safe integers");
    return String(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (!value || typeof value !== "object") throw new TypeError("canonical DTO contains an unsupported value");
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`).join(",")}}`;
}

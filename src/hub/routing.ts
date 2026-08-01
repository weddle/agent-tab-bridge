export const HUB_OPAQUE_ROUTE_TYPE = "opaqueRoute" as const;
export const HUB_MAX_ACTIVE_ROUTES = 1_024;

export interface RoutedBrokerAddress {
  machineId: string;
  endpointId: string;
  principalId: string;
  stableSessionKey: string;
}

export interface HubOpaqueRouteEnvelope {
  type: typeof HUB_OPAQUE_ROUTE_TYPE;
  direction: "request" | "response" | "close";
  routeId: string;
  streamId: string;
  address: RoutedBrokerAddress;
  /** Opaque base64url bytes. The hub routes but never decodes this field. */
  payload: string;
}

const fingerprint = (value: unknown): value is string => typeof value === "string" && /^sha256\/[A-Za-z0-9+/=_-]{1,249}$/.test(value);
const identifier = (value: unknown): value is string => typeof value === "string" && /^[A-Za-z0-9._:-]{1,256}$/.test(value);
const payload = (value: unknown): value is string => typeof value === "string" && value.length > 0 && value.length <= 1_398_104 && /^[A-Za-z0-9_-]+$/.test(value);

export function isRoutedBrokerAddress(value: unknown): value is RoutedBrokerAddress {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const address = value as Record<string, unknown>;
  return Object.keys(address).length === 4 && Object.hasOwn(address, "machineId") && Object.hasOwn(address, "endpointId") && Object.hasOwn(address, "principalId") && Object.hasOwn(address, "stableSessionKey") && fingerprint(address.machineId) && fingerprint(address.endpointId) && fingerprint(address.principalId) && identifier(address.stableSessionKey);
}

/** Parses only routing metadata. Callers at the hub MUST NOT decode `payload`. */
export function parseHubOpaqueRoute(frame: Uint8Array): HubOpaqueRouteEnvelope | undefined {
  let value: unknown;
  try { value = JSON.parse(Buffer.from(frame).toString("utf8")); } catch { return undefined; }
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  const envelope = value as Record<string, unknown>;
  if (Object.keys(envelope).length !== 6 || envelope.type !== HUB_OPAQUE_ROUTE_TYPE || (envelope.direction !== "request" && envelope.direction !== "response" && envelope.direction !== "close") || !identifier(envelope.routeId) || !identifier(envelope.streamId) || !isRoutedBrokerAddress(envelope.address) || !payload(envelope.payload)) return undefined;
  return envelope as unknown as HubOpaqueRouteEnvelope;
}

export function encodeHubOpaqueRoute(envelope: HubOpaqueRouteEnvelope): Buffer {
  if (!isRoutedBrokerAddress(envelope.address) || !identifier(envelope.routeId) || !identifier(envelope.streamId) || !payload(envelope.payload)) throw new TypeError("invalid opaque route envelope");
  return Buffer.from(JSON.stringify(envelope), "utf8");
}

/** Endpoints, never the hub router, recover the opaque bytes. */
export function decodeOpaqueRoutePayload(envelope: HubOpaqueRouteEnvelope): Buffer { return Buffer.from(envelope.payload, "base64url"); }
export function encodeOpaqueRoutePayload(payload: Uint8Array): string { return Buffer.from(payload).toString("base64url"); }

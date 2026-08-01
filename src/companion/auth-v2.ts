import { generateKeyPairSync, randomBytes } from "node:crypto";
import { fingerprintSpki } from "./identity.js";
import { isSessionAccess, type SessionAccess } from "./session-access.js";
import type { EndpointId, MachineId, PrincipalId } from "./endpoint-contracts.js";

export const AUTH_V2_PROTOCOL_VERSION = 2 as const;
export const AUTH_V2_CIPHER_SUITE = "P-256/SHA-256" as const;
export const AUTH_V2_MAX_CLOCK_SKEW_MS = 60_000;

export interface AuthV2RequestedAuthority {
  scope: SessionAccess | null;
  ttlMs: number | null;
  stableSessionKey: string | null;
}

export interface AuthV2Transcript {
  protocolVersion: typeof AUTH_V2_PROTOCOL_VERSION;
  cipherSuite: typeof AUTH_V2_CIPHER_SUITE;
  controller: { principalId: PrincipalId; publicKeySpki: string; role: "controller" };
  edge: { machineId: MachineId; principalId: PrincipalId; publicKeySpki: string; role: "edge" };
  endpointId: EndpointId;
  controllerEphemeralPublicKey: string;
  edgeEphemeralPublicKey: string;
  controllerNonce: string;
  edgeNonce: string;
  authority: AuthV2RequestedAuthority;
  expiresAt: number;
  hubId: string | null;
  routeId: string | null;
  streamId: string | null;
}

const fingerprint = (value: unknown): value is string => typeof value === "string" && /^sha256\/[A-Za-z0-9+/=_-]+$/.test(value) && value.length <= 256;
const base64Url = (value: unknown): value is string => typeof value === "string" && value.length > 0 && value.length <= 8192 && /^[A-Za-z0-9_-]+$/.test(value);
const nullableIdentifier = (value: unknown): value is string | null => value === null || (typeof value === "string" && value.length > 0 && value.length <= 256);

export function createAuthV2Nonce(): string { return randomBytes(32).toString("base64url"); }

/** Fresh P-256 public material reserved for the authenticated ECDH channel. */
export function createAuthV2EphemeralPublicKey(): string {
  const { publicKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1", publicKeyEncoding: { type: "spki", format: "der" }, privateKeyEncoding: { type: "pkcs8", format: "der" } });
  return Buffer.from(publicKey).toString("base64url");
}

export function isAuthV2RequestedAuthority(value: unknown): value is AuthV2RequestedAuthority {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const authority = value as Record<string, unknown>;
  const ttlMs = authority.ttlMs;
  return Object.keys(authority).length === 3 && Object.hasOwn(authority, "scope") && Object.hasOwn(authority, "ttlMs") && Object.hasOwn(authority, "stableSessionKey") && (authority.scope === null || isSessionAccess(authority.scope)) && (ttlMs === null || (typeof ttlMs === "number" && Number.isSafeInteger(ttlMs) && ttlMs > 0 && ttlMs <= 24 * 60 * 60_000)) && (authority.stableSessionKey === null || (typeof authority.stableSessionKey === "string" && authority.stableSessionKey.length > 0 && authority.stableSessionKey.length <= 128));
}

export function isAuthV2Transcript(value: unknown): value is AuthV2Transcript {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const transcript = value as Record<string, unknown>;
  const keys = ["protocolVersion", "cipherSuite", "controller", "edge", "endpointId", "controllerEphemeralPublicKey", "edgeEphemeralPublicKey", "controllerNonce", "edgeNonce", "authority", "expiresAt", "hubId", "routeId", "streamId"];
  const expiresAt = transcript.expiresAt;
  if (Object.keys(transcript).length !== keys.length || !keys.every((key) => Object.hasOwn(transcript, key)) || transcript.protocolVersion !== AUTH_V2_PROTOCOL_VERSION || transcript.cipherSuite !== AUTH_V2_CIPHER_SUITE || !fingerprint(transcript.endpointId) || !base64Url(transcript.controllerEphemeralPublicKey) || !base64Url(transcript.edgeEphemeralPublicKey) || !base64Url(transcript.controllerNonce) || !base64Url(transcript.edgeNonce) || !isAuthV2RequestedAuthority(transcript.authority) || typeof expiresAt !== "number" || !Number.isSafeInteger(expiresAt) || expiresAt <= 0 || !nullableIdentifier(transcript.hubId) || !nullableIdentifier(transcript.routeId) || !nullableIdentifier(transcript.streamId)) return false;
  const controller = transcript.controller as Record<string, unknown> | null;
  const edge = transcript.edge as Record<string, unknown> | null;
  return !!controller && typeof controller === "object" && !Array.isArray(controller) && Object.keys(controller).length === 3 && controller.role === "controller" && fingerprint(controller.principalId) && base64Url(controller.publicKeySpki)
    && !!edge && typeof edge === "object" && !Array.isArray(edge) && Object.keys(edge).length === 4 && edge.role === "edge" && fingerprint(edge.machineId) && fingerprint(edge.principalId) && edge.machineId === edge.principalId && base64Url(edge.publicKeySpki);
}

/** Canonical UTF-8 bytes signed by both static P-256 principals. */
export function canonicalAuthV2Transcript(transcript: AuthV2Transcript): Uint8Array {
  if (!isAuthV2Transcript(transcript)) throw new TypeError("invalid v2 auth transcript");
  try {
    if (fingerprintSpki(transcript.controller.publicKeySpki) !== transcript.controller.principalId || fingerprintSpki(transcript.edge.publicKeySpki) !== transcript.edge.principalId) throw new TypeError("v2 auth transcript static fingerprint mismatch");
  } catch { throw new TypeError("invalid v2 auth transcript static key"); }
  return new TextEncoder().encode(canonicalJson(transcript));
}

function canonicalJson(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) throw new TypeError("canonical transcript numbers must be safe integers");
    return String(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (!value || typeof value !== "object") throw new TypeError("canonical transcript contains an unsupported value");
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`).join(",")}}`;
}

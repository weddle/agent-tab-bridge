/** Versioned control messages exchanged over the Chrome Native Messaging pipe. */

export const NATIVE_PROTOCOL_VERSION = 1 as const;
export const NATIVE_MAX_FRAME_BYTES = 1024 * 1024;
export const MAX_TASK_LABEL_LENGTH = 128;
export const MAX_DISPLAY_NAME_LENGTH = 128;
export const MAX_REQUEST_ID_LENGTH = 128;
export const MAX_SESSION_ID_LENGTH = 128;
export const MAX_TTL_MS = 24 * 60 * 60 * 1000;
export const MAX_CAPABILITIES = 1;
export const SUPPORTED_CAPABILITIES = ["cdp"] as const;
export type Capability = (typeof SUPPORTED_CAPABILITIES)[number];

export type SessionState = "pending" | "active" | "revoked";
export interface SessionRecord {
  id: string;
  controllerPrincipalId: string;
  displayControllerName: string;
  taskLabel: string;
  requestedCapabilities: Capability[];
  createdAt: number;
  expiresAt: number;
  state: SessionState;
}
export interface SessionApproval {
  sessionId: string;
  controllerPrincipalId: string;
  displayControllerName: string;
  taskLabel: string;
  requestedCapabilities: Capability[];
  ttlMs: number;
}
export interface SharedTabRecord { tabId: number; title: string; url: string; }

/** The extension's first handshake message. Nonces are random base64url values. */
export interface HelloMessage {
  version: typeof NATIVE_PROTOCOL_VERSION; type: "hello"; requestId?: string;
  role: "extension"; extensionId: string; extensionPublicKey: string; extensionNonce: string;
}
/** Challenge binds both identities, roles, protocol version, and both nonces. */
export interface HelloChallengeMessage {
  version: typeof NATIVE_PROTOCOL_VERSION; type: "helloChallenge"; requestId?: string;
  role: "companion"; companionId: string; companionPublicKey: string;
  extensionId: string; extensionPublicKey: string; extensionNonce: string; companionNonce: string; signature: string;
}
/** Proof signs the canonical transcript represented by all fields below. */
export interface HelloProofMessage {
  version: typeof NATIVE_PROTOCOL_VERSION; type: "helloProof"; requestId?: string;
  role: "extension"; extensionId: string; extensionPublicKey: string; companionId: string;
  companionPublicKey: string; extensionNonce: string; companionNonce: string; signature: string;
}
export interface ApproveSessionMessage extends SessionApproval { version: typeof NATIVE_PROTOCOL_VERSION; type: "approveSession"; requestId?: string; }
export interface RevokeSessionMessage { version: typeof NATIVE_PROTOCOL_VERSION; type: "revokeSession"; requestId?: string; sessionId: string; reason?: string; }
export interface RevokeDeviceMessage { version: typeof NATIVE_PROTOCOL_VERSION; type: "revokeDevice"; requestId: string; }

export interface RelayReadyMessage { version: typeof NATIVE_PROTOCOL_VERSION; type: "relayReady"; requestId?: string; sessionId: string; relayUrl: string; }
export interface RelayFailedMessage { version: typeof NATIVE_PROTOCOL_VERSION; type: "relayFailed"; requestId?: string; sessionId: string; error: string; }
export interface TrustedMessage { version: typeof NATIVE_PROTOCOL_VERSION; type: "trusted"; requestId?: string; companionPrincipalId: string; extensionFingerprint: string; }
export interface SnapshotMessage { version: typeof NATIVE_PROTOCOL_VERSION; type: "snapshot"; requestId?: string; pending: SessionRecord[]; active: SessionRecord[]; sharedTabs: SharedTabRecord[]; }
export interface SessionPendingMessage { version: typeof NATIVE_PROTOCOL_VERSION; type: "sessionPending"; requestId?: string; session: SessionRecord; }
export interface SessionStartedMessage { version: typeof NATIVE_PROTOCOL_VERSION; type: "sessionStarted"; requestId?: string; session: SessionRecord; relayUrl?: string; }
export interface SessionStoppedMessage { version: typeof NATIVE_PROTOCOL_VERSION; type: "sessionStopped"; requestId?: string; session: SessionRecord; reason?: string; }

export type ExtensionToHostMessage = HelloMessage | HelloProofMessage | ApproveSessionMessage | RevokeSessionMessage | RevokeDeviceMessage | RelayReadyMessage | RelayFailedMessage;

export type HostToExtensionMessage = HelloChallengeMessage | TrustedMessage | SnapshotMessage | SessionPendingMessage | SessionStartedMessage | SessionStoppedMessage;
export type NativeMessage = ExtensionToHostMessage | HostToExtensionMessage;

export interface HandshakeTranscript {
  extensionId: string; extensionPublicKey: string; extensionNonce: string;
  companionId: string; companionPublicKey: string; companionNonce: string;
}

export class NativeProtocolError extends Error {
  constructor(message: string) { super(message); this.name = "NativeProtocolError"; }
}
const isRecord = (value: unknown): value is Record<string, unknown> => !!value && typeof value === "object" && !Array.isArray(value);
const isString = (value: unknown, max = 512): value is string => typeof value === "string" && value.length > 0 && value.length <= max;
const isInteger = (value: unknown): value is number => typeof value === "number" && Number.isInteger(value);
const isBase64 = (value: unknown): value is string => isString(value, 8192) && /^[A-Za-z0-9+/_-]+={0,2}$/.test(value);
const keysExactly = (value: Record<string, unknown>, required: readonly string[], optional: readonly string[] = []): boolean => {
  const allowed = new Set([...required, ...optional]);
  return required.every((key) => Object.prototype.hasOwnProperty.call(value, key)) && Object.keys(value).every((key) => allowed.has(key));
};
const hasVersionAndType = (value: Record<string, unknown>, type: string, required: readonly string[], optional: readonly string[] = []) => value.version === NATIVE_PROTOCOL_VERSION && value.type === type && keysExactly(value, ["version", "type", ...required], ["requestId", ...optional]);
const validRequestId = (value: unknown): value is string => value === undefined || (isString(value, MAX_REQUEST_ID_LENGTH) && /^[A-Za-z0-9._:-]+$/.test(value));
const validId = (value: unknown, max = MAX_SESSION_ID_LENGTH): value is string => isString(value, max) && /^[A-Za-z0-9._:-]+$/.test(value);
const validPrincipalId = (value: unknown): value is string => isString(value, 256) && /^sha256\/[A-Za-z0-9+/=_-]+$/.test(value);
const validDisplay = (value: unknown): value is string => isString(value, MAX_DISPLAY_NAME_LENGTH);
const validLabel = (value: unknown): value is string => isString(value, MAX_TASK_LABEL_LENGTH);
const validCapabilities = (value: unknown): value is Capability[] => Array.isArray(value) && value.length <= MAX_CAPABILITIES && new Set(value).size === value.length && value.every((item) => item === "cdp");

export function validateSessionRecord(value: unknown): value is SessionRecord {
  if (!isRecord(value) || !keysExactly(value, ["id", "controllerPrincipalId", "displayControllerName", "taskLabel", "requestedCapabilities", "createdAt", "expiresAt", "state"])) return false;
  return validId(value.id) && isString(value.controllerPrincipalId, 256) && validDisplay(value.displayControllerName) && validLabel(value.taskLabel) && validCapabilities(value.requestedCapabilities) && isInteger(value.createdAt) && isInteger(value.expiresAt) && value.expiresAt > value.createdAt && value.expiresAt - value.createdAt <= MAX_TTL_MS && (value.state === "pending" || value.state === "active" || value.state === "revoked");
}
export function assertSessionRecord(value: unknown): SessionRecord { if (!validateSessionRecord(value)) throw new NativeProtocolError("invalid session record"); return value; }
export function validateSessionApproval(value: unknown): value is SessionApproval {
  if (!isRecord(value) || !keysExactly(value, ["sessionId", "controllerPrincipalId", "displayControllerName", "taskLabel", "requestedCapabilities", "ttlMs"])) return false;
  return validId(value.sessionId) && isString(value.controllerPrincipalId, 256) && validDisplay(value.displayControllerName) && validLabel(value.taskLabel) && validCapabilities(value.requestedCapabilities) && isInteger(value.ttlMs) && value.ttlMs > 0 && value.ttlMs <= MAX_TTL_MS;
}
function validateSharedTab(value: unknown): value is SharedTabRecord { return isRecord(value) && keysExactly(value, ["tabId", "title", "url"]) && isInteger(value.tabId) && value.tabId >= 0 && isString(value.title, 4096) && isString(value.url, 8192); }
function validHandshakeFields(value: Record<string, unknown>, role: "extension" | "companion"): boolean {
  const required = ["role", "extensionId", "extensionPublicKey", "companionId", "companionPublicKey", "extensionNonce", "companionNonce", "signature"];
  return keysExactly(value, ["version", "type", ...required], ["requestId"]) && value.role === role && validId(value.extensionId, 256) && validPrincipalId(value.companionId) && isBase64(value.extensionPublicKey) && isBase64(value.companionPublicKey) && isBase64(value.extensionNonce) && isBase64(value.companionNonce) && isBase64(value.signature) && (() => { try { return Buffer.from(value.signature as string, "base64url").length === 64; } catch { return false; } })();
}
export function validateNativeMessage(value: unknown): value is NativeMessage {
  if (!isRecord(value) || value.version !== NATIVE_PROTOCOL_VERSION || typeof value.type !== "string" || !validRequestId(value.requestId)) return false;
  switch (value.type) {
    case "hello": return hasVersionAndType(value, "hello", ["role", "extensionId", "extensionPublicKey", "extensionNonce"]) && value.role === "extension" && validId(value.extensionId, 256) && isBase64(value.extensionPublicKey) && isBase64(value.extensionNonce);
    case "helloChallenge": return hasVersionAndType(value, "helloChallenge", ["role", "companionId", "companionPublicKey", "extensionId", "extensionPublicKey", "extensionNonce", "companionNonce", "signature"]) && validHandshakeFields(value, "companion");
    case "helloProof": return hasVersionAndType(value, "helloProof", ["role", "extensionId", "extensionPublicKey", "companionId", "companionPublicKey", "extensionNonce", "companionNonce", "signature"]) && validHandshakeFields(value, "extension");
    case "approveSession": return hasVersionAndType(value, "approveSession", ["sessionId", "controllerPrincipalId", "displayControllerName", "taskLabel", "requestedCapabilities", "ttlMs"]) && validateSessionApproval({ sessionId: value.sessionId, controllerPrincipalId: value.controllerPrincipalId, displayControllerName: value.displayControllerName, taskLabel: value.taskLabel, requestedCapabilities: value.requestedCapabilities, ttlMs: value.ttlMs });
    case "revokeDevice": return hasVersionAndType(value, "revokeDevice", []) && typeof value.requestId === "string" && value.requestId.length > 0;
    case "revokeSession": return hasVersionAndType(value, "revokeSession", ["sessionId"], ["reason"]) && validId(value.sessionId) && (value.reason === undefined || isString(value.reason, 256));
    case "relayReady": return hasVersionAndType(value, "relayReady", ["sessionId", "relayUrl"]) && validId(value.sessionId) && isString(value.relayUrl, 8192) && /^ws:\/\/127\.0\.0\.1(?::\d+)?\//.test(value.relayUrl);
    case "relayFailed": return hasVersionAndType(value, "relayFailed", ["sessionId", "error"]) && validId(value.sessionId) && isString(value.error, 512);
    case "trusted": return hasVersionAndType(value, "trusted", ["companionPrincipalId", "extensionFingerprint"]) && validPrincipalId(value.companionPrincipalId) && validPrincipalId(value.extensionFingerprint);
    case "snapshot": return hasVersionAndType(value, "snapshot", ["pending", "active", "sharedTabs"]) && Array.isArray(value.pending) && Array.isArray(value.active) && Array.isArray(value.sharedTabs) && value.pending.every(validateSessionRecord) && value.active.every(validateSessionRecord) && value.sharedTabs.every(validateSharedTab);
    case "sessionPending": return hasVersionAndType(value, "sessionPending", ["session"]) && validateSessionRecord(value.session);
    case "sessionStarted": return hasVersionAndType(value, "sessionStarted", ["session"], ["relayUrl"]) && validateSessionRecord(value.session) && (value.relayUrl === undefined || isString(value.relayUrl, 8192));
    case "sessionStopped": return hasVersionAndType(value, "sessionStopped", ["session"], ["reason"]) && validateSessionRecord(value.session) && (value.reason === undefined || isString(value.reason, 256));
    default: return false;
  }
}
/** Canonical bytes signed by both peers; no caller-controlled role/type fields are trusted. */
export function canonicalHandshakeTranscript(fields: HandshakeTranscript): Uint8Array {
  if (!validId(fields.extensionId, 256) || !validPrincipalId(fields.companionId) || !isBase64(fields.extensionPublicKey) || !isBase64(fields.companionPublicKey) || !isBase64(fields.extensionNonce) || !isBase64(fields.companionNonce)) throw new NativeProtocolError("invalid handshake transcript");
  const canonical = JSON.stringify({ companionId: fields.companionId, companionNonce: fields.companionNonce, companionPublicKey: fields.companionPublicKey, extensionId: fields.extensionId, extensionNonce: fields.extensionNonce, extensionPublicKey: fields.extensionPublicKey, protocolVersion: NATIVE_PROTOCOL_VERSION, roles: ["extension", "companion"] });
  return new TextEncoder().encode(canonical);
}
export function parseNativeMessage(input: string | Uint8Array | unknown): NativeMessage | null {
  let value: unknown = input;
  if (typeof input === "string" || input instanceof Uint8Array) { try { value = JSON.parse(typeof input === "string" ? input : new TextDecoder().decode(input)); } catch { return null; } }
  return validateNativeMessage(value) ? value : null;
}
export function assertNativeMessage(value: unknown): NativeMessage { const message = parseNativeMessage(value); if (!message) throw new NativeProtocolError("invalid native messaging protocol message"); return message; }

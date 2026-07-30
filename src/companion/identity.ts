import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes, sign, verify, type KeyObject } from "node:crypto";
import { applicationSupportPath, atomicWritePrivateJson, readPrivateJson, type ApplicationSupportOptions, type CompanionStateStore, type PinnedExtensionIdentity } from "./state.js";
import { canonicalHandshakeTranscript, type HandshakeTranscript, type HelloChallengeMessage, type HelloMessage, type HelloProofMessage, NATIVE_PROTOCOL_VERSION } from "./native-protocol.js";

export type IdentityKind = "companion" | "controller";
export interface StoredIdentity { version: typeof NATIVE_PROTOCOL_VERSION; kind: IdentityKind; principalId: string; publicKeySpki: string; privateKeyPkcs8: string; createdAt: number; }
export interface IdentityStatus { version: typeof NATIVE_PROTOCOL_VERSION; kind: IdentityKind; principalId: string; publicKeySpki: string; fingerprint: string; createdAt: number; }
export interface IdentityKeypair { principalId: string; publicKeySpki: string; privateKeyPkcs8: string; fingerprint: string; }
const b64 = (value: Uint8Array): string => Buffer.from(value).toString("base64url");
const bytes = (value: string): Buffer => Buffer.from(value, "base64url");
function privateKey(value: string | KeyObject): KeyObject { return typeof value === "string" ? createPrivateKey({ key: bytes(value), format: "der", type: "pkcs8" }) : value; }
function publicKey(value: string | KeyObject): KeyObject { return typeof value === "string" ? createPublicKey({ key: bytes(value), format: "der", type: "spki" }) : value; }
function canonicalPublicKey(value: string | KeyObject): Buffer { return publicKey(value).export({ type: "spki", format: "der" }) as Buffer; }
function keyPairMatches(identity: StoredIdentity): boolean {
  try {
    const derived = createPublicKey(privateKey(identity.privateKeyPkcs8)).export({ type: "spki", format: "der" }) as Buffer;
    return Buffer.compare(derived, canonicalPublicKey(identity.publicKeySpki)) === 0;
  } catch { return false; }
}
/** SHA-256 SPKI fingerprint in the conventional sha256/base64 form. */
export function fingerprintSpki(publicKeySpki: string | Uint8Array): string {
  const der = typeof publicKeySpki === "string" ? canonicalPublicKey(publicKeySpki) : canonicalPublicKey(createPublicKey({ key: Buffer.from(publicKeySpki), format: "der", type: "spki" }));
  return `sha256/${createHash("sha256").update(der).digest("base64")}`;
}
/** Principal used by same-host controllers, derived solely from the authenticated broker secret. */
export function deriveControllerPrincipalId(brokerSecret: string): string { return `sha256/${createHash("sha256").update(brokerSecret, "utf8").digest("base64")}`; }
export function generateIdentity(kind: IdentityKind = "companion"): IdentityKeypair { const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1", publicKeyEncoding: { type: "spki", format: "der" }, privateKeyEncoding: { type: "pkcs8", format: "der" } }); const publicKeySpki = b64(publicKey); const privateKeyPkcs8 = b64(privateKey); return { principalId: fingerprintSpki(publicKeySpki), publicKeySpki, privateKeyPkcs8, fingerprint: fingerprintSpki(publicKeySpki) }; }
export function createBrokerSecret(bytesLength = 32): string { if (!Number.isInteger(bytesLength) || bytesLength < 32 || bytesLength > 64) throw new RangeError("broker secret length must be 32..64 bytes"); return randomBytes(bytesLength).toString("base64url"); }
export function signTranscript(privateKeyPkcs8: string | KeyObject, transcript: Uint8Array): string { return sign("sha256", Buffer.from(transcript), { key: privateKey(privateKeyPkcs8), dsaEncoding: "ieee-p1363" }).toString("base64url"); }
export function verifyTranscript(publicKeySpki: string | KeyObject, transcript: Uint8Array, signature: string): boolean { try { const sig = bytes(signature); return sig.length === 64 && verify("sha256", Buffer.from(transcript), { key: publicKey(publicKeySpki), dsaEncoding: "ieee-p1363" }, sig); } catch { return false; } }
export function signHandshakeTranscript(privateKeyPkcs8: string | KeyObject, fields: HandshakeTranscript): string { return signTranscript(privateKeyPkcs8, canonicalHandshakeTranscript(fields)); }
export function verifyHandshakeTranscript(publicKeySpki: string | KeyObject, fields: HandshakeTranscript, signature: string): boolean { return verifyTranscript(publicKeySpki, canonicalHandshakeTranscript(fields), signature); }
export function createHandshakeNonce(): string { return randomBytes(32).toString("base64url"); }

function validStoredIdentity(value: unknown): value is StoredIdentity { if (!value || typeof value !== "object" || Array.isArray(value)) return false; const item = value as Record<string, unknown>; return item.version === NATIVE_PROTOCOL_VERSION && (item.kind === "companion" || item.kind === "controller") && typeof item.principalId === "string" && item.principalId.startsWith("sha256/") && typeof item.publicKeySpki === "string" && typeof item.privateKeyPkcs8 === "string" && typeof item.createdAt === "number" && Number.isInteger(item.createdAt); }
/** Load/create one persistent identity. Private key bytes are only present in StoredIdentity. */
export class IdentityStore {
  readonly filePath: string; readonly kind: IdentityKind; private identity: StoredIdentity | undefined;
  constructor(kind: IdentityKind = "companion", options: ApplicationSupportOptions & { fileName?: string } = {}) { this.kind = kind; this.filePath = applicationSupportPath(options.fileName ?? `${kind}-identity.json`, options); }
  async load(): Promise<StoredIdentity | undefined> { if (this.identity) return structuredClone(this.identity); const value = await readPrivateJson<unknown>(this.filePath); if (value === undefined) return undefined; if (!validStoredIdentity(value) || value.kind !== this.kind || !keyPairMatches(value) || fingerprintSpki(value.publicKeySpki) !== value.principalId) throw new Error("invalid identity record"); this.identity = structuredClone(value); return structuredClone(value); }
  async loadOrCreate(): Promise<StoredIdentity> { const existing = await this.load(); if (existing) return existing; const generated = generateIdentity(this.kind); const record: StoredIdentity = { version: NATIVE_PROTOCOL_VERSION, kind: this.kind, principalId: generated.principalId, publicKeySpki: generated.publicKeySpki, privateKeyPkcs8: generated.privateKeyPkcs8, createdAt: Date.now() }; await atomicWritePrivateJson(this.filePath, record); this.identity = record; return structuredClone(record); }
  async save(identity: StoredIdentity): Promise<void> { if (!validStoredIdentity(identity) || identity.kind !== this.kind || !keyPairMatches(identity) || fingerprintSpki(identity.publicKeySpki) !== identity.principalId) throw new TypeError("invalid identity"); await atomicWritePrivateJson(this.filePath, identity); this.identity = structuredClone(identity); }
  async status(): Promise<IdentityStatus | undefined> { const identity = await this.load(); return identity ? { version: identity.version, kind: identity.kind, principalId: identity.principalId, publicKeySpki: identity.publicKeySpki, fingerprint: fingerprintSpki(identity.publicKeySpki), createdAt: identity.createdAt } : undefined; }
}

/** Host-side challenge/proof verifier with first-key pinning. */
export class HostIdentityHandshake {
  private readonly pending = new Map<string, { transcript: HandshakeTranscript; challenge: HelloChallengeMessage }>();
  constructor(private readonly identityStore: IdentityStore, private readonly stateStore?: CompanionStateStore) {}
  async createChallenge(hello: HelloMessage): Promise<HelloChallengeMessage> { const companion = await this.identityStore.loadOrCreate(); const companionNonce = createHandshakeNonce(); const transcript: HandshakeTranscript = { extensionId: hello.extensionId, extensionPublicKey: hello.extensionPublicKey, extensionNonce: hello.extensionNonce, companionId: companion.principalId, companionPublicKey: companion.publicKeySpki, companionNonce }; const challenge: HelloChallengeMessage = { version: NATIVE_PROTOCOL_VERSION, type: "helloChallenge", role: "companion", companionId: companion.principalId, companionPublicKey: companion.publicKeySpki, extensionId: hello.extensionId, extensionPublicKey: hello.extensionPublicKey, extensionNonce: hello.extensionNonce, companionNonce, signature: signHandshakeTranscript(companion.privateKeyPkcs8, transcript) }; this.pending.set(hello.extensionNonce, { transcript, challenge }); return challenge; }
  async verifyProof(proof: HelloProofMessage): Promise<PinnedExtensionIdentity> { const item = this.pending.get(proof.extensionNonce); if (!item || !verifyHandshakeTranscript(item.transcript.companionPublicKey, item.transcript, item.challenge.signature) || proof.companionId !== item.transcript.companionId || proof.companionPublicKey !== item.transcript.companionPublicKey || proof.extensionId !== item.transcript.extensionId || proof.extensionPublicKey !== item.transcript.extensionPublicKey || proof.companionNonce !== item.transcript.companionNonce || !verifyHandshakeTranscript(proof.extensionPublicKey, item.transcript, proof.signature)) throw new Error("invalid extension handshake proof"); this.pending.delete(proof.extensionNonce); const pinned: PinnedExtensionIdentity = { extensionId: proof.extensionId, publicKeySpki: proof.extensionPublicKey, fingerprint: fingerprintSpki(proof.extensionPublicKey), pinnedAt: Date.now() }; if (this.stateStore) await this.stateStore.pinExtension(pinned); return pinned; }
}

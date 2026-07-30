export type ExtensionIdentity = {
  key: "extension";
  version: 1;
  createdAt: number;
  publicKey: CryptoKey;
  privateKey: CryptoKey;
  publicKeySpki: string;
};

export type PinnedCompanion = {
  key: "companion";
  id: string;
  publicKeySpki: string;
  name: string | null;
  pinnedAt: number;
};

export function toBase64Url(bytes: ArrayBuffer | Uint8Array): string;
export function fromBase64Url(value: string): Uint8Array;
export function fingerprintSpki(publicKeySpki: string): Promise<string>;
export function verifyExtensionIdentity(identity: unknown): Promise<boolean>;

export function loadExtensionIdentity(): Promise<ExtensionIdentity>;
export function pinCompanion(companion: {
  id: string;
  publicKeySpki: string;
  name?: string | null;
}): Promise<PinnedCompanion>;
export function loadPinnedCompanion(): Promise<PinnedCompanion | null>;
export function forgetPinnedCompanion(): Promise<void>;
export function nativeProofTranscript(fields: {
  companionId: string;
  companionNonce: string;
  companionPublicKey: string;
  extensionId: string;
  extensionNonce: string;
  extensionPublicKey: string;
}): Uint8Array;
export function signNativeProof(
  identity: ExtensionIdentity,
  fields: Parameters<typeof nativeProofTranscript>[0],
): Promise<string>;
export function verifyNativeChallenge(
  companionPublicKey: string,
  signature: string,
  fields: Parameters<typeof nativeProofTranscript>[0],
): Promise<boolean>;

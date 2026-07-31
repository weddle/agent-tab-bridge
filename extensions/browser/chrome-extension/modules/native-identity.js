// Persistent WebCrypto identity for the extension side of Native Messaging.
// The private P-256 key is imported non-extractable before it is placed in
// IndexedDB; only its SPKI public key is ever exchanged with the companion.

export const NATIVE_PROTOCOL_VERSION = 2;
const DATABASE_NAME = "agent-tab-bridge";
const DATABASE_VERSION = 1;
const IDENTITY_STORE = "identity";
const IDENTITY_KEY = "extension";
const COMPANION_KEY = "companion";

function requestResult(request) {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("IndexedDB request failed."));
  });
}

function transactionResult(transaction) {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = () => resolve();
    transaction.onabort = () => reject(transaction.error ?? new Error("IndexedDB transaction aborted."));
    transaction.onerror = () => reject(transaction.error ?? new Error("IndexedDB transaction failed."));
  });
}

async function openDatabase() {
  const request = indexedDB.open(DATABASE_NAME, DATABASE_VERSION);
  request.onupgradeneeded = () => {
    const database = request.result;
    if (!database.objectStoreNames.contains(IDENTITY_STORE)) {
      database.createObjectStore(IDENTITY_STORE, { keyPath: "key" });
    }
  };
  return await requestResult(request);
}

async function readRecord(key) {
  const database = await openDatabase();
  try {
    const transaction = database.transaction(IDENTITY_STORE, "readonly");
    const result = await requestResult(transaction.objectStore(IDENTITY_STORE).get(key));
    await transactionResult(transaction);
    return result ?? null;
  } finally {
    database.close();
  }
}

async function writeRecord(record) {
  const database = await openDatabase();
  try {
    const transaction = database.transaction(IDENTITY_STORE, "readwrite");
    transaction.objectStore(IDENTITY_STORE).put(record);
    await transactionResult(transaction);
  } finally {
    database.close();
  }
}

async function deleteRecord(key) {
  const database = await openDatabase();
  try {
    const transaction = database.transaction(IDENTITY_STORE, "readwrite");
    transaction.objectStore(IDENTITY_STORE).delete(key);
    await transactionResult(transaction);
  } finally {
    database.close();
  }
}


function bytesToBase64(bytes) {
  let binary = "";
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  for (let index = 0; index < view.length; index += 0x8000) {
    binary += String.fromCharCode(...view.subarray(index, index + 0x8000));
  }
  return btoa(binary);
}

export function toBase64Url(bytes) {
  return bytesToBase64(bytes).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

export function fromBase64Url(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]*$/.test(value)) {
    throw new Error("Expected base64url data.");
  }
  const padded = value.replaceAll("-", "+").replaceAll("_", "/") + "=".repeat((4 - (value.length % 4)) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}
function hasExactKeys(value, keys) {
  return (
    !!value &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.keys(value).length === keys.length &&
    keys.every((key) => Object.hasOwn(value, key))
  );
}

function isP256Key(key, type, extractable, usage) {
  return (
    key instanceof CryptoKey &&
    key.type === type &&
    key.extractable === extractable &&
    key.algorithm?.name === "ECDSA" &&
    key.algorithm?.namedCurve === "P-256" &&
    key.usages.length === 1 &&
    key.usages[0] === usage
  );
}

async function importP256PublicKey(publicKeySpki) {
  return await crypto.subtle.importKey(
    "spki",
    fromBase64Url(publicKeySpki),
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"],
  );
}

/** Stable SHA-256 SPKI fingerprint compatible with the Native Messaging host. */
export async function fingerprintSpki(publicKeySpki) {
  const digest = await crypto.subtle.digest("SHA-256", fromBase64Url(publicKeySpki));
  return `sha256/${bytesToBase64(new Uint8Array(digest))}`;
}

/**
 * Prove a persisted extension public/private pair still corresponds before
 * allowing it to authenticate a Native Messaging companion.
 */
export async function verifyExtensionIdentity(identity) {
  try {
    if (
      !hasExactKeys(identity, ["key", "version", "createdAt", "publicKey", "privateKey", "publicKeySpki"]) ||
      identity.key !== IDENTITY_KEY ||
      identity.version !== 1 ||
      !Number.isSafeInteger(identity.createdAt) ||
      identity.createdAt <= 0 ||
      !isP256Key(identity.publicKey, "public", true, "verify") ||
      !isP256Key(identity.privateKey, "private", false, "sign") ||
      typeof identity.publicKeySpki !== "string"
    ) {
      return false;
    }

    const exportedSpki = toBase64Url(new Uint8Array(await crypto.subtle.exportKey("spki", identity.publicKey)));
    if (exportedSpki !== identity.publicKeySpki) {
      return false;
    }
    const publicKey = await importP256PublicKey(identity.publicKeySpki);
    const transcript = new TextEncoder().encode("agent-tab-bridge extension identity proof v1");
    const signature = new Uint8Array(
      await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, identity.privateKey, transcript),
    );
    return (
      signature.byteLength === 64 &&
      (await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, publicKey, signature, transcript))
    );
  } catch {
    return false;
  }
}

async function verifyPinnedCompanion(companion) {
  try {
    if (
      !hasExactKeys(companion, ["key", "id", "publicKeySpki", "name", "pinnedAt"]) ||
      companion.key !== COMPANION_KEY ||
      typeof companion.id !== "string" ||
      typeof companion.publicKeySpki !== "string" ||
      !(companion.name === null || (typeof companion.name === "string" && companion.name.length <= 128)) ||
      !Number.isSafeInteger(companion.pinnedAt) ||
      companion.pinnedAt <= 0
    ) {
      return false;
    }
    await importP256PublicKey(companion.publicKeySpki);
    return companion.id === (await fingerprintSpki(companion.publicKeySpki));
  } catch {
    return false;
  }
}


/** Load the stable identity or generate and persist a non-exportable private key. */
export async function loadExtensionIdentity() {
  const existing = await readRecord(IDENTITY_KEY);
  if (await verifyExtensionIdentity(existing)) {
    return existing;
  }

  const generated = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  const [publicKeySpki, privateKeyPkcs8] = await Promise.all([
    crypto.subtle.exportKey("spki", generated.publicKey),
    crypto.subtle.exportKey("pkcs8", generated.privateKey),
  ]);
  try {
    const [publicKey, privateKey] = await Promise.all([
      crypto.subtle.importKey(
        "spki",
        publicKeySpki,
        { name: "ECDSA", namedCurve: "P-256" },
        true,
        ["verify"],
      ),
      crypto.subtle.importKey(
        "pkcs8",
        privateKeyPkcs8,
        { name: "ECDSA", namedCurve: "P-256" },
        false,
        ["sign"],
      ),
    ]);
    const identity = {
      key: IDENTITY_KEY,
      version: 1,
      createdAt: Date.now(),
      publicKey,
      privateKey,
      publicKeySpki: toBase64Url(new Uint8Array(publicKeySpki)),
    };
    if (!(await verifyExtensionIdentity(identity))) {
      throw new Error("Generated extension identity did not prove its key pair.");
    }
    await writeRecord(identity);
    return identity;
  } finally {
    new Uint8Array(privateKeyPkcs8).fill(0);
  }
}


/** First local Native Messaging contact pins the companion's verified SPKI permanently. */
export async function pinCompanion(companion) {
  if (
    !companion ||
    typeof companion.id !== "string" ||
    typeof companion.publicKeySpki !== "string"
  ) {
    throw new Error("Companion challenge omitted a stable identity.");
  }
  try {
    await importP256PublicKey(companion.publicKeySpki);
  } catch {
    throw new Error("Companion challenge contained an invalid P-256 SPKI.");
  }
  const fingerprint = await fingerprintSpki(companion.publicKeySpki);
  if (companion.id !== fingerprint) {
    throw new Error("Companion challenge identity does not match its SPKI fingerprint.");
  }

  const existing = await readRecord(COMPANION_KEY);
  if (existing) {
    if (!(await verifyPinnedCompanion(existing))) {
      throw new Error("The stored Native Messaging companion identity is invalid.");
    }
    if (existing.id !== fingerprint || existing.publicKeySpki !== companion.publicKeySpki) {
      throw new Error("The Native Messaging companion identity does not match the pinned companion.");
    }
    return existing;
  }

  const pinned = {
    key: COMPANION_KEY,
    id: fingerprint,
    publicKeySpki: companion.publicKeySpki,
    name: typeof companion.name === "string" && companion.name.length <= 128 ? companion.name : null,
    pinnedAt: Date.now(),
  };
  if (!(await verifyPinnedCompanion(pinned))) {
    throw new Error("Companion identity could not be verified before pinning.");
  }
  await writeRecord(pinned);
  return pinned;
}

export async function loadPinnedCompanion() {
  const companion = await readRecord(COMPANION_KEY);
  if (companion === null) {
    return null;
  }
  if (!(await verifyPinnedCompanion(companion))) {
    throw new Error("The stored Native Messaging companion identity is invalid.");
  }
  return companion;
}

/** Remove the local companion pin after the user explicitly revokes trust. */
export async function forgetPinnedCompanion() {
  await deleteRecord(COMPANION_KEY);
}

/** Canonical transcript agreed with src/companion/native-protocol.ts. */
export function nativeProofTranscript({
  companionId,
  companionNonce,
  companionPublicKey,
  extensionId,
  extensionNonce,
  extensionPublicKey,
}) {
  return new TextEncoder().encode(
    JSON.stringify({
      companionId,
      companionNonce,
      companionPublicKey,
      extensionId,
      extensionNonce,
      extensionPublicKey,
      protocolVersion: NATIVE_PROTOCOL_VERSION,
      roles: ["extension", "companion"],
    }),
  );
}

/** Sign the canonical transcript as a 64-byte IEEE P1363 P-256 signature. */
export async function signNativeProof(identity, fields) {
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    identity.privateKey,
    nativeProofTranscript(fields),
  );
  const rawSignature = new Uint8Array(signature);
  if (rawSignature.byteLength !== 64) {
    throw new Error("WebCrypto did not produce a P-256 P1363 signature.");
  }
  return toBase64Url(rawSignature);
}

/** Verify the companion's raw P1363 challenge proof before accepting its pin. */
export async function verifyNativeChallenge(companionPublicKey, signature, fields) {
  try {
    const rawSignature = fromBase64Url(signature);
    if (rawSignature.byteLength !== 64) {
      return false;
    }
    const publicKey = await crypto.subtle.importKey(
      "spki",
      fromBase64Url(companionPublicKey),
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
    return await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      publicKey,
      rawSignature,
      nativeProofTranscript(fields),
    );
  } catch {
    return false;
  }
}

import { createCipheriv, createDecipheriv, createHash, createPublicKey, diffieHellman, generateKeyPairSync, hkdfSync, randomBytes, type KeyObject } from "node:crypto";
import { fingerprintSpki, signTranscript, verifyTranscript, type StoredIdentity } from "../identity.js";

/**
 * WP10 — E2E session channel library.
 *
 * Signed-ephemeral-ECDH handshake -> HKDF-SHA256 -> directional AES-256-GCM.
 * Static P-256 keys only ever SIGN (identity.ts signTranscript/verifyTranscript,
 * ieee-p1363); they never perform ECDH. Fresh P-256 ephemerals per channel; both
 * sides sign the complete ephemeral exchange plus the caller-supplied canonical
 * context (WP1 schema bytes, opaque here), domain-separated by role. Frame keys
 * are bound to the whole transcript via the HKDF salt.
 *
 * Zero I/O: handshake messages and frames are values a transport moves.
 * Zeroization is best-effort: Buffers this library owns are zero-filled when
 * superseded, but GC copies and KeyObject internals cannot be scrubbed.
 */

export const CHANNEL_PROTOCOL_VERSION = "atb-channel-v1" as const;
export const CHANNEL_CIPHER_SUITE = "ECDH-P256-HKDF-SHA256-AES-256-GCM-P256SIG" as const;
/** Hard ceiling for one frame's plaintext; callers may configure lower, never higher. */
export const CHANNEL_MAX_FRAME_BYTES = 65_536;
/** Wire overhead per frame: 14-byte header (AAD) + 16-byte GCM tag. */
export const CHANNEL_FRAME_OVERHEAD_BYTES = 30;
export const CHANNEL_DEFAULT_FRAMES_PER_EPOCH = 2 ** 24;

const FRAME_HEADER_BYTES = 14;
const FRAME_VERSION = 1;
const MAX_EPOCH = 0xffff_ffff;
const MAX_CLOSE_REASON_CHARS = 1024;
const FRAME_DATA = 1;
const FRAME_CLOSE = 2;
const FRAME_REKEY = 3;

export type ChannelRole = "initiator" | "responder";
export type ChannelState = "open" | "local-closed" | "peer-closed" | "closed" | "failed";
export type ChannelFailureCode =
  | "protocol-downgrade"
  | "context-mismatch"
  | "key-mismatch"
  | "handshake-state"
  | "tampered-frame"
  | "replayed-frame"
  | "reordered-frame"
  | "frame-too-large"
  | "channel-closed"
  | "counter-exhausted";
export class ChannelFailure extends Error {
  constructor(readonly code: ChannelFailureCode, message: string = code) { super(message); this.name = "ChannelFailure"; }
}

export interface ChannelEndpointOptions {
  /** Static P-256 identity; signs the handshake transcript, never keys ECDH. */
  readonly identity: StoredIdentity;
  /** Pinned static key the peer MUST prove; never taken from the wire. */
  readonly peerPublicKeySpki: string;
  /** Session X this channel addresses; bound into the signed transcript. */
  readonly sessionId: string;
  /** Canonical context bytes (WP1 schema). Opaque data here; both ends must hold identical bytes. */
  readonly context: Uint8Array;
  readonly maxFrameBytes?: number;
  /** Frames per direction epoch before an automatic rekey; small values are test hooks. */
  readonly framesPerEpoch?: number;
  /** Epoch ceiling before the channel fails terminally; test hook, defaults to the u32 wire maximum. */
  readonly maxEpoch?: number;
}
export interface ChannelHello { readonly protocolVersion: typeof CHANNEL_PROTOCOL_VERSION; readonly cipherSuite: typeof CHANNEL_CIPHER_SUITE; readonly sessionId: string; readonly ephemeralPublicKey: string; readonly nonce: string; }
export interface ChannelAccept { readonly protocolVersion: typeof CHANNEL_PROTOCOL_VERSION; readonly cipherSuite: typeof CHANNEL_CIPHER_SUITE; readonly sessionId: string; readonly ephemeralPublicKey: string; readonly nonce: string; readonly signature: string; }
export interface ChannelConfirm { readonly sessionId: string; readonly signature: string; }
export type ChannelReceipt =
  | { readonly type: "data"; readonly payload: Uint8Array }
  | { readonly type: "rekeyed" }
  | { readonly type: "closed"; readonly reason: string | null };
export interface InitiatedChannel { readonly hello: ChannelHello; complete(accept: ChannelAccept): { channel: SecureSessionChannel; confirm: ChannelConfirm }; }
export interface AcceptedChannel { readonly accept: ChannelAccept; complete(confirm: ChannelConfirm): SecureSessionChannel; }

const encoder = new TextEncoder();
const toB64 = (value: Uint8Array): string => Buffer.from(value).toString("base64url");
const base64Url = (value: unknown): value is string => typeof value === "string" && value.length > 0 && value.length <= 8192 && /^[A-Za-z0-9_-]+$/.test(value);

function canonicalJson(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) throw new TypeError("canonical channel numbers must be safe integers");
    return String(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (!value || typeof value !== "object") throw new TypeError("canonical channel value unsupported");
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`).join(",")}}`;
}

interface NormalizedOptions { identity: StoredIdentity; peerPublicKeySpki: string; peerFingerprint: string; localFingerprint: string; sessionId: string; context: Uint8Array; maxFrameBytes: number; framesPerEpoch: number; maxEpoch: number; }
function normalizeOptions(options: ChannelEndpointOptions): NormalizedOptions {
  const { identity, peerPublicKeySpki, sessionId, context } = options;
  if (!identity || typeof identity.publicKeySpki !== "string" || typeof identity.privateKeyPkcs8 !== "string") throw new TypeError("channel requires a stored static identity");
  if (typeof sessionId !== "string" || sessionId.length === 0 || sessionId.length > 256) throw new TypeError("sessionId must be 1..256 characters");
  if (!(context instanceof Uint8Array) || context.length === 0 || context.length > 65_536) throw new TypeError("context must be 1..65536 canonical bytes");
  const maxFrameBytes = options.maxFrameBytes ?? CHANNEL_MAX_FRAME_BYTES;
  if (!Number.isInteger(maxFrameBytes) || maxFrameBytes < 1 || maxFrameBytes > CHANNEL_MAX_FRAME_BYTES) throw new TypeError(`maxFrameBytes must be 1..${CHANNEL_MAX_FRAME_BYTES}`);
  const framesPerEpoch = options.framesPerEpoch ?? CHANNEL_DEFAULT_FRAMES_PER_EPOCH;
  if (!Number.isInteger(framesPerEpoch) || framesPerEpoch < 2 || framesPerEpoch > 2 ** 32) throw new TypeError("framesPerEpoch must be an integer in 2..2^32");
  const maxEpoch = options.maxEpoch ?? MAX_EPOCH;
  if (!Number.isInteger(maxEpoch) || maxEpoch < 0 || maxEpoch > MAX_EPOCH) throw new TypeError(`maxEpoch must be an integer in 0..${MAX_EPOCH}`);
  let peerFingerprint: string; let localFingerprint: string;
  try { peerFingerprint = fingerprintSpki(peerPublicKeySpki); localFingerprint = fingerprintSpki(identity.publicKeySpki); } catch { throw new TypeError("invalid static SPKI key"); }
  return { identity, peerPublicKeySpki, peerFingerprint, localFingerprint, sessionId, context: Uint8Array.from(context), maxFrameBytes, framesPerEpoch, maxEpoch };
}

function createEphemeral(): { publicKeySpki: string; privateKey: KeyObject | undefined } {
  const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  return { publicKeySpki: toB64(publicKey.export({ type: "spki", format: "der" }) as Buffer), privateKey };
}
function parseEphemeral(publicKeySpki: string): KeyObject {
  try {
    const key = createPublicKey({ key: Buffer.from(publicKeySpki, "base64url"), format: "der", type: "spki" });
    if (key.asymmetricKeyType !== "ec" || key.asymmetricKeyDetails?.namedCurve !== "prime256v1") throw new Error("wrong curve");
    return key;
  } catch { throw new ChannelFailure("key-mismatch", "peer ephemeral key is not a valid P-256 key"); }
}

/** Both static signatures cover this exact byte string; frame keys are HKDF-salted with its hash. */
function channelTranscript(fields: { sessionId: string; context: Uint8Array; initiator: { principalId: string; publicKeySpki: string }; responder: { principalId: string; publicKeySpki: string }; initiatorEphemeralPublicKey: string; responderEphemeralPublicKey: string; initiatorNonce: string; responderNonce: string }): Uint8Array {
  return encoder.encode(canonicalJson({
    type: "atb-channel-transcript-v1",
    protocolVersion: CHANNEL_PROTOCOL_VERSION,
    cipherSuite: CHANNEL_CIPHER_SUITE,
    sessionId: fields.sessionId,
    context: toB64(fields.context),
    initiator: fields.initiator,
    responder: fields.responder,
    initiatorEphemeralPublicKey: fields.initiatorEphemeralPublicKey,
    responderEphemeralPublicKey: fields.responderEphemeralPublicKey,
    initiatorNonce: fields.initiatorNonce,
    responderNonce: fields.responderNonce,
  }));
}
/** Role domain separation: an initiator signature can never be replayed as a responder's. */
function signatureBody(signer: ChannelRole, transcript: Uint8Array): Uint8Array {
  return encoder.encode(canonicalJson({ type: "atb-channel-signature-v1", signer, transcript: toB64(transcript) }));
}

function hkdf(ikm: Uint8Array, salt: Uint8Array, info: string, length: number): Buffer {
  return Buffer.from(hkdfSync("sha256", ikm, salt, info, length));
}

/** One direction's epoch-chained AEAD keys. Ratchets are one-way; superseded buffers are zero-filled (best-effort). */
class Direction {
  epoch = 0;
  counter = 0;
  private destroyed = false;
  private chain: Buffer;
  private key: Buffer;
  constructor(chain: Buffer, private readonly maxEpoch: number) { this.chain = chain; this.key = hkdf(chain, Buffer.alloc(0), "atb-channel-v1 aead-key", 32); }
  aeadKey(): Buffer {
    if (this.destroyed) throw new ChannelFailure("channel-closed", "direction key material already destroyed");
    return this.key;
  }
  ratchet(): void {
    if (this.destroyed) throw new ChannelFailure("channel-closed", "direction key material already destroyed");
    if (this.epoch >= this.maxEpoch) { this.destroy(); throw new ChannelFailure("counter-exhausted", "epoch space exhausted; establish a fresh channel"); }
    const next = hkdf(this.chain, Buffer.alloc(0), "atb-channel-v1 rekey", 32);
    this.chain.fill(0);
    this.key.fill(0);
    this.chain = next;
    this.key = hkdf(next, Buffer.alloc(0), "atb-channel-v1 aead-key", 32);
    this.epoch += 1;
    this.counter = 0;
  }
  destroy(): void {
    this.destroyed = true;
    this.chain.fill(0);
    this.key.fill(0);
  }
}

function deriveDirections(sharedSecret: Buffer, transcript: Uint8Array, role: ChannelRole, maxEpoch: number): { send: Direction; recv: Direction } {
  const master = hkdf(sharedSecret, createHash("sha256").update(transcript).digest(), "atb-channel-v1 master", 32);
  sharedSecret.fill(0);
  const initiatorToResponder = new Direction(hkdf(master, Buffer.alloc(0), "atb-channel-v1 i2r", 32), maxEpoch);
  const responderToInitiator = new Direction(hkdf(master, Buffer.alloc(0), "atb-channel-v1 r2i", 32), maxEpoch);
  master.fill(0);
  return role === "initiator" ? { send: initiatorToResponder, recv: responderToInitiator } : { send: responderToInitiator, recv: initiatorToResponder };
}

function frameHeader(type: number, epoch: number, counter: number): Buffer {
  const header = Buffer.alloc(FRAME_HEADER_BYTES);
  header[0] = FRAME_VERSION;
  header[1] = type;
  header.writeUInt32BE(epoch, 2);
  header.writeBigUInt64BE(BigInt(counter), 6);
  return header;
}
/** Deterministic nonce: keys are unique per direction+epoch, so (epoch, counter) never repeats under one key. */
function frameNonce(epoch: number, counter: number): Buffer {
  const nonce = Buffer.alloc(12);
  nonce.writeUInt32BE(epoch, 0);
  nonce.writeBigUInt64BE(BigInt(counter), 4);
  return nonce;
}

/**
 * WP10 -> WP11 contract: an authenticated duplex byte stream to session X.
 * `send`/`close` return ordered frames for the transport; `receive` consumes one
 * peer frame. A transport EOF without a `closed` receipt is a truncation, never a
 * clean shutdown — `state` says which side has authenticated its close; call
 * `abort()` on transport EOF/error to terminalize without emitting bytes.
 */
export class SecureSessionChannel {
  readonly role: ChannelRole;
  readonly sessionId: string;
  readonly localFingerprint: string;
  readonly peerFingerprint: string;
  private readonly sendDirection: Direction;
  private readonly recvDirection: Direction;
  private readonly maxFrameBytes: number;
  private readonly framesPerEpoch: number;
  private readonly maxEpoch: number;
  private localClosed = false;
  private peerClosed = false;
  private failed = false;

  /** @internal — construct via initiateChannel/acceptChannel. */
  constructor(role: ChannelRole, options: NormalizedOptions, sharedSecret: Buffer, transcript: Uint8Array) {
    this.role = role;
    this.sessionId = options.sessionId;
    this.localFingerprint = options.localFingerprint;
    this.peerFingerprint = options.peerFingerprint;
    this.maxFrameBytes = options.maxFrameBytes;
    this.framesPerEpoch = options.framesPerEpoch;
    this.maxEpoch = options.maxEpoch;
    const directions = deriveDirections(sharedSecret, transcript, role, options.maxEpoch);
    this.sendDirection = directions.send;
    this.recvDirection = directions.recv;
  }

  get state(): ChannelState {
    if (this.failed) return "failed";
    if (this.localClosed && this.peerClosed) return "closed";
    if (this.localClosed) return "local-closed";
    if (this.peerClosed) return "peer-closed";
    return "open";
  }

  /** Ordered frames for the transport: usually one, two when an automatic rekey precedes the data. */
  send(payload: Uint8Array): Uint8Array[] {
    this.assertSendOpen();
    if (!(payload instanceof Uint8Array)) throw new TypeError("payload must be bytes");
    if (payload.length > this.maxFrameBytes) throw new ChannelFailure("frame-too-large", `payload exceeds ${this.maxFrameBytes} bytes; chunk before sending`);
    const frames: Uint8Array[] = [];
    if (this.sendDirection.counter >= this.framesPerEpoch - 1) frames.push(this.sealRekey());
    frames.push(this.seal(FRAME_DATA, payload));
    return frames;
  }

  /** Explicit rekey of the send direction; the frame itself is authenticated under the old epoch. */
  rekey(): Uint8Array {
    this.assertSendOpen();
    return this.sealRekey();
  }

  /** Authenticated close of the send direction. The peer may keep sending until it closes too. */
  close(reason?: string): Uint8Array[] {
    this.assertSendOpen();
    if (reason !== undefined && (typeof reason !== "string" || reason.length > MAX_CLOSE_REASON_CHARS)) throw new TypeError(`close reason must be a string of at most ${MAX_CLOSE_REASON_CHARS} characters`);
    const payload = encoder.encode(reason ?? "");
    if (payload.length > this.maxFrameBytes) throw new ChannelFailure("frame-too-large", "close reason exceeds the frame bound");
    const frames: Uint8Array[] = [];
    if (this.sendDirection.counter >= this.framesPerEpoch - 1) frames.push(this.sealRekey());
    frames.push(this.seal(FRAME_CLOSE, payload));
    this.localClosed = true;
    this.sendDirection.destroy();
    return frames;
  }

  /** Idempotent terminalization for transport EOF/error: emits nothing, discards key material. */
  abort(): void {
    if (this.failed || (this.localClosed && this.peerClosed)) return;
    this.fail();
  }

  receive(frame: Uint8Array): ChannelReceipt {
    if (this.failed) throw new ChannelFailure("channel-closed", "channel terminally failed");
    if (this.peerClosed) throw new ChannelFailure("channel-closed", "peer already sent an authenticated close");
    if (!(frame instanceof Uint8Array) || frame.length < FRAME_HEADER_BYTES + 16) throw new ChannelFailure("tampered-frame", "frame shorter than header plus tag");
    if (frame.length > FRAME_HEADER_BYTES + this.maxFrameBytes + 16) throw new ChannelFailure("frame-too-large", "frame exceeds the negotiated bound");
    const bytes = Buffer.isBuffer(frame) ? frame : Buffer.from(frame.buffer, frame.byteOffset, frame.byteLength);
    const header = bytes.subarray(0, FRAME_HEADER_BYTES);
    const type = header[1];
    if (header[0] !== FRAME_VERSION || (type !== FRAME_DATA && type !== FRAME_CLOSE && type !== FRAME_REKEY)) throw new ChannelFailure("tampered-frame", "unknown frame version or type");
    const epoch = header.readUInt32BE(2);
    const counter = header.readBigUInt64BE(6);
    const expected = this.recvDirection;
    if (epoch < expected.epoch || (epoch === expected.epoch && counter < BigInt(expected.counter))) throw new ChannelFailure("replayed-frame", "frame counter regressed: replay rejected");
    if (epoch > expected.epoch || counter > BigInt(expected.counter)) throw new ChannelFailure("reordered-frame", "frame counter skipped ahead: reordering rejected");
    let payload: Buffer;
    try {
      const decipher = createDecipheriv("aes-256-gcm", expected.aeadKey(), frameNonce(epoch, expected.counter));
      decipher.setAAD(header);
      decipher.setAuthTag(bytes.subarray(bytes.length - 16));
      payload = Buffer.concat([decipher.update(bytes.subarray(FRAME_HEADER_BYTES, bytes.length - 16)), decipher.final()]);
    } catch { throw new ChannelFailure("tampered-frame", "frame failed authenticated decryption"); }
    if (type === FRAME_REKEY) {
      if (expected.epoch >= this.maxEpoch) { this.fail(); throw new ChannelFailure("counter-exhausted", "peer rekeyed past the epoch limit; channel failed terminally"); }
      expected.ratchet();
      return { type: "rekeyed" };
    }
    if (type === FRAME_CLOSE) {
      this.peerClosed = true;
      expected.destroy();
      return { type: "closed", reason: payload.length > 0 ? payload.toString("utf8") : null };
    }
    expected.counter += 1;
    return { type: "data", payload: new Uint8Array(payload) };
  }

  private assertSendOpen(): void {
    if (this.failed) throw new ChannelFailure("channel-closed", "channel terminally failed");
    if (this.localClosed) throw new ChannelFailure("channel-closed", "send direction already closed");
  }
  private fail(): void {
    this.failed = true;
    this.sendDirection.destroy();
    this.recvDirection.destroy();
  }
  private seal(type: number, payload: Uint8Array): Uint8Array {
    const direction = this.sendDirection;
    const header = frameHeader(type, direction.epoch, direction.counter);
    const cipher = createCipheriv("aes-256-gcm", direction.aeadKey(), frameNonce(direction.epoch, direction.counter));
    cipher.setAAD(header);
    const ciphertext = Buffer.concat([cipher.update(payload), cipher.final()]);
    direction.counter += 1;
    return Buffer.concat([header, ciphertext, cipher.getAuthTag()]);
  }
  private sealRekey(): Uint8Array {
    if (this.sendDirection.epoch >= this.maxEpoch) { this.fail(); throw new ChannelFailure("counter-exhausted", "epoch space exhausted; establish a fresh channel"); }
    const frame = this.seal(FRAME_REKEY, new Uint8Array(0));
    this.sendDirection.ratchet();
    return frame;
  }
}

/** Initiator side. Emit `hello`, feed the peer's `accept` to `complete`, transport the returned `confirm`. */
export function initiateChannel(options: ChannelEndpointOptions): InitiatedChannel {
  const normalized = normalizeOptions(options);
  const ephemeral = createEphemeral();
  const nonce = toB64(randomBytes(32));
  const hello: ChannelHello = { protocolVersion: CHANNEL_PROTOCOL_VERSION, cipherSuite: CHANNEL_CIPHER_SUITE, sessionId: normalized.sessionId, ephemeralPublicKey: ephemeral.publicKeySpki, nonce };
  let completed = false;
  return {
    hello,
    complete(accept: ChannelAccept) {
      if (completed) throw new ChannelFailure("handshake-state", "handshake already completed");
      if (accept.protocolVersion !== CHANNEL_PROTOCOL_VERSION || accept.cipherSuite !== CHANNEL_CIPHER_SUITE) throw new ChannelFailure("protocol-downgrade");
      if (accept.sessionId !== normalized.sessionId) throw new ChannelFailure("context-mismatch", "accept addresses a different session");
      if (!base64Url(accept.ephemeralPublicKey) || !base64Url(accept.nonce) || !base64Url(accept.signature)) throw new ChannelFailure("key-mismatch", "malformed accept message");
      const peerEphemeral = parseEphemeral(accept.ephemeralPublicKey);
      const transcript = channelTranscript({
        sessionId: normalized.sessionId,
        context: normalized.context,
        initiator: { principalId: normalized.localFingerprint, publicKeySpki: normalized.identity.publicKeySpki },
        responder: { principalId: normalized.peerFingerprint, publicKeySpki: normalized.peerPublicKeySpki },
        initiatorEphemeralPublicKey: hello.ephemeralPublicKey,
        responderEphemeralPublicKey: accept.ephemeralPublicKey,
        initiatorNonce: hello.nonce,
        responderNonce: accept.nonce,
      });
      if (!verifyTranscript(normalized.peerPublicKeySpki, signatureBody("responder", transcript), accept.signature)) throw new ChannelFailure("key-mismatch", "responder signature does not verify against the pinned static key");
      const ephemeralPrivate = ephemeral.privateKey;
      if (!ephemeralPrivate) throw new ChannelFailure("handshake-state", "handshake already completed");
      const sharedSecret = diffieHellman({ privateKey: ephemeralPrivate, publicKey: peerEphemeral });
      completed = true;
      ephemeral.privateKey = undefined;
      const confirm: ChannelConfirm = { sessionId: normalized.sessionId, signature: signTranscript(normalized.identity.privateKeyPkcs8, signatureBody("initiator", transcript)) };
      return { channel: new SecureSessionChannel("initiator", normalized, sharedSecret, transcript), confirm };
    },
  };
}

/** Responder side. The channel is released only after the initiator's `confirm` signature verifies. */
export function acceptChannel(options: ChannelEndpointOptions, hello: ChannelHello): AcceptedChannel {
  const normalized = normalizeOptions(options);
  if (hello.protocolVersion !== CHANNEL_PROTOCOL_VERSION || hello.cipherSuite !== CHANNEL_CIPHER_SUITE) throw new ChannelFailure("protocol-downgrade");
  if (hello.sessionId !== normalized.sessionId) throw new ChannelFailure("context-mismatch", "hello addresses a different session");
  if (!base64Url(hello.ephemeralPublicKey) || !base64Url(hello.nonce)) throw new ChannelFailure("key-mismatch", "malformed hello message");
  let peerEphemeral: KeyObject | undefined = parseEphemeral(hello.ephemeralPublicKey);
  const ephemeral = createEphemeral();
  const nonce = toB64(randomBytes(32));
  const transcript = channelTranscript({
    sessionId: normalized.sessionId,
    context: normalized.context,
    initiator: { principalId: normalized.peerFingerprint, publicKeySpki: normalized.peerPublicKeySpki },
    responder: { principalId: normalized.localFingerprint, publicKeySpki: normalized.identity.publicKeySpki },
    initiatorEphemeralPublicKey: hello.ephemeralPublicKey,
    responderEphemeralPublicKey: ephemeral.publicKeySpki,
    initiatorNonce: hello.nonce,
    responderNonce: nonce,
  });
  const accept: ChannelAccept = { protocolVersion: CHANNEL_PROTOCOL_VERSION, cipherSuite: CHANNEL_CIPHER_SUITE, sessionId: normalized.sessionId, ephemeralPublicKey: ephemeral.publicKeySpki, nonce, signature: signTranscript(normalized.identity.privateKeyPkcs8, signatureBody("responder", transcript)) };
  let completed = false;
  return {
    accept,
    complete(confirm: ChannelConfirm) {
      if (completed) throw new ChannelFailure("handshake-state", "handshake already completed");
      if (confirm.sessionId !== normalized.sessionId) throw new ChannelFailure("context-mismatch", "confirm addresses a different session");
      if (!base64Url(confirm.signature)) throw new ChannelFailure("key-mismatch", "malformed confirm message");
      if (!verifyTranscript(normalized.peerPublicKeySpki, signatureBody("initiator", transcript), confirm.signature)) throw new ChannelFailure("key-mismatch", "initiator signature does not verify against the pinned static key");
      const ephemeralPrivate = ephemeral.privateKey;
      if (!ephemeralPrivate || !peerEphemeral) throw new ChannelFailure("handshake-state", "handshake already completed");
      const sharedSecret = diffieHellman({ privateKey: ephemeralPrivate, publicKey: peerEphemeral });
      completed = true;
      ephemeral.privateKey = undefined;
      peerEphemeral = undefined;
      return new SecureSessionChannel("responder", normalized, sharedSecret, transcript);
    },
  };
}

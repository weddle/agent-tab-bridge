import { describe, expect, it } from "vitest";
import { generateIdentity, type StoredIdentity } from "../identity.js";
import { AUTH_V2_CIPHER_SUITE, AUTH_V2_PROTOCOL_VERSION, canonicalAuthV2Transcript, createAuthV2EphemeralPublicKey, createAuthV2Nonce } from "../auth-v2.js";
import { acceptChannel, ChannelFailure, CHANNEL_CIPHER_SUITE, CHANNEL_PROTOCOL_VERSION, initiateChannel, type ChannelEndpointOptions, type SecureSessionChannel } from "./index.js";

const encoder = new TextEncoder();
// Mutate a non-final base64url character (every bit of it lands in the decoded
// bytes; the final character's low bits are discarded by lenient decoders).
const flipChar = (value: string): string => `${value.slice(0, 10)}${value[10] === "A" ? "B" : "A"}${value.slice(11)}`;
const SESSION_ID = "session-1";

function identity(): StoredIdentity {
  const generated = generateIdentity();
  return { version: 1, kind: "companion", principalId: generated.principalId, publicKeySpki: generated.publicKeySpki, privateKeyPkcs8: generated.privateKeyPkcs8, createdAt: 0 };
}

/** Real WP1 canonical context bytes: the channel binds them opaquely, WP8 owns their meaning. */
function wp1Context(controller: StoredIdentity, edge: StoredIdentity, streamId: string): Uint8Array {
  return canonicalAuthV2Transcript({
    protocolVersion: AUTH_V2_PROTOCOL_VERSION,
    cipherSuite: AUTH_V2_CIPHER_SUITE,
    controller: { principalId: controller.principalId, publicKeySpki: controller.publicKeySpki, role: "controller" },
    edge: { machineId: edge.principalId, principalId: edge.principalId, publicKeySpki: edge.publicKeySpki, role: "edge" },
    endpointId: edge.principalId,
    controllerEphemeralPublicKey: createAuthV2EphemeralPublicKey(),
    edgeEphemeralPublicKey: createAuthV2EphemeralPublicKey(),
    controllerNonce: createAuthV2Nonce(),
    edgeNonce: createAuthV2Nonce(),
    authority: { scope: null, ttlMs: null, stableSessionKey: null },
    expiresAt: 4_000_000_000_000,
    hubId: "hub-1",
    routeId: "route-1",
    streamId,
  });
}

interface Establishment { a: SecureSessionChannel; b: SecureSessionChannel; controller: StoredIdentity; edge: StoredIdentity; context: Uint8Array; }
function establish(overrides: Partial<Pick<ChannelEndpointOptions, "framesPerEpoch" | "maxEpoch" | "maxFrameBytes">> = {}): Establishment {
  const controller = identity();
  const edge = identity();
  const context = wp1Context(controller, edge, "stream-1");
  const init = initiateChannel({ identity: controller, peerPublicKeySpki: edge.publicKeySpki, sessionId: SESSION_ID, context, ...overrides });
  const accepted = acceptChannel({ identity: edge, peerPublicKeySpki: controller.publicKeySpki, sessionId: SESSION_ID, context, ...overrides }, init.hello);
  const { channel: a, confirm } = init.complete(accepted.accept);
  return { a, b: accepted.complete(confirm), controller, edge, context };
}

describe("secure session channel handshake", () => {
  it("establishes an authenticated duplex byte stream bound to WP1 canonical context and session", () => {
    const { a, b, controller, edge } = establish();
    expect(a.sessionId).toBe(SESSION_ID);
    expect(a.peerFingerprint).toBe(edge.principalId);
    expect(a.localFingerprint).toBe(controller.principalId);
    expect(b.peerFingerprint).toBe(controller.principalId);
    expect(a.state).toBe("open");
    const [toEdge] = a.send(encoder.encode("Target.getTargets"));
    expect(b.receive(toEdge)).toEqual({ type: "data", payload: encoder.encode("Target.getTargets") });
    const [toController] = b.send(encoder.encode("targetInfos"));
    expect(a.receive(toController)).toEqual({ type: "data", payload: encoder.encode("targetInfos") });
    const [empty] = a.send(new Uint8Array(0));
    expect(b.receive(empty)).toEqual({ type: "data", payload: new Uint8Array(0) });
  });

  it("rejects a peer presenting the wrong static key, in either direction", () => {
    const controller = identity();
    const edge = identity();
    const impostor = identity();
    const context = wp1Context(controller, edge, "stream-1");
    const init = initiateChannel({ identity: controller, peerPublicKeySpki: edge.publicKeySpki, sessionId: SESSION_ID, context });
    const impostorAccept = acceptChannel({ identity: impostor, peerPublicKeySpki: controller.publicKeySpki, sessionId: SESSION_ID, context }, init.hello);
    expect(() => init.complete(impostorAccept.accept)).toThrow(expect.objectContaining({ code: "key-mismatch" }));

    // An initiator claiming the pinned controller key without its private key: the
    // transcript matches, so rejection happens at the confirm signature.
    const forgedInit = initiateChannel({ identity: { ...controller, privateKeyPkcs8: impostor.privateKeyPkcs8 }, peerPublicKeySpki: edge.publicKeySpki, sessionId: SESSION_ID, context });
    const accepted = acceptChannel({ identity: edge, peerPublicKeySpki: controller.publicKeySpki, sessionId: SESSION_ID, context }, forgedInit.hello);
    const { confirm } = forgedInit.complete(accepted.accept);
    expect(() => accepted.complete(confirm)).toThrow(expect.objectContaining({ code: "key-mismatch" }));
  });

  it("rejects a tampered ephemeral signature and a substituted ephemeral key", () => {
    const controller = identity();
    const edge = identity();
    const context = wp1Context(controller, edge, "stream-1");
    const options = { identity: controller, peerPublicKeySpki: edge.publicKeySpki, sessionId: SESSION_ID, context };
    const responderOptions = { identity: edge, peerPublicKeySpki: controller.publicKeySpki, sessionId: SESSION_ID, context };

    const init = initiateChannel(options);
    const accepted = acceptChannel(responderOptions, init.hello);
    const flipped = flipChar(accepted.accept.signature);
    expect(() => init.complete({ ...accepted.accept, signature: flipped })).toThrow(expect.objectContaining({ code: "key-mismatch" }));

    const init2 = initiateChannel(options);
    const accepted2 = acceptChannel(responderOptions, init2.hello);
    const foreignEphemeral = initiateChannel(options).hello.ephemeralPublicKey;
    expect(() => init2.complete({ ...accepted2.accept, ephemeralPublicKey: foreignEphemeral })).toThrow(expect.objectContaining({ code: "key-mismatch" }));

    const init3 = initiateChannel(options);
    const accepted3 = acceptChannel(responderOptions, init3.hello);
    const { confirm } = init3.complete(accepted3.accept);
    const flippedConfirm = flipChar(confirm.signature);
    expect(() => accepted3.complete({ ...confirm, signature: flippedConfirm })).toThrow(expect.objectContaining({ code: "key-mismatch" }));
  });

  it("rejects canonical-context substitution between the two endpoints", () => {
    const controller = identity();
    const edge = identity();
    const init = initiateChannel({ identity: controller, peerPublicKeySpki: edge.publicKeySpki, sessionId: SESSION_ID, context: wp1Context(controller, edge, "stream-1") });
    const accepted = acceptChannel({ identity: edge, peerPublicKeySpki: controller.publicKeySpki, sessionId: SESSION_ID, context: wp1Context(controller, edge, "stream-2") }, init.hello);
    expect(() => init.complete(accepted.accept)).toThrow(expect.objectContaining({ code: "key-mismatch" }));
  });

  it("rejects protocol downgrade, session mismatch, reused handshakes, and malformed options", () => {
    const controller = identity();
    const edge = identity();
    const context = wp1Context(controller, edge, "stream-1");
    const options = { identity: controller, peerPublicKeySpki: edge.publicKeySpki, sessionId: SESSION_ID, context };
    const responderOptions = { identity: edge, peerPublicKeySpki: controller.publicKeySpki, sessionId: SESSION_ID, context };

    const init = initiateChannel(options);
    expect(() => acceptChannel(responderOptions, { ...init.hello, protocolVersion: "atb-channel-v0" as never })).toThrow(expect.objectContaining({ code: "protocol-downgrade" }));
    expect(() => acceptChannel(responderOptions, { ...init.hello, cipherSuite: `${CHANNEL_CIPHER_SUITE}-EXPORT` as never })).toThrow(expect.objectContaining({ code: "protocol-downgrade" }));
    expect(() => acceptChannel({ ...responderOptions, sessionId: "session-2" }, init.hello)).toThrow(expect.objectContaining({ code: "context-mismatch" }));

    const accepted = acceptChannel(responderOptions, init.hello);
    expect(() => init.complete({ ...accepted.accept, protocolVersion: "atb-channel-v0" as never })).toThrow(expect.objectContaining({ code: "protocol-downgrade" }));
    const { confirm } = init.complete(accepted.accept);
    expect(() => init.complete(accepted.accept)).toThrow(expect.objectContaining({ code: "handshake-state" }));
    accepted.complete(confirm);
    expect(() => accepted.complete(confirm)).toThrow(expect.objectContaining({ code: "handshake-state" }));

    expect(() => initiateChannel({ ...options, context: new Uint8Array(0) })).toThrow(TypeError);
    expect(() => initiateChannel({ ...options, framesPerEpoch: 1 })).toThrow(TypeError);
    expect(() => initiateChannel({ ...options, sessionId: "" })).toThrow(TypeError);
  });
});

describe("secure session channel frames", () => {
  it("rejects a replayed frame — a replayed request re-consuming a standing grant is the canonical attack", () => {
    const { a, b } = establish();
    const [grantConsumingRequest] = a.send(encoder.encode('{"consume":"standing-grant"}'));
    expect(b.receive(grantConsumingRequest)).toEqual({ type: "data", payload: encoder.encode('{"consume":"standing-grant"}') });
    expect(() => b.receive(grantConsumingRequest)).toThrow(ChannelFailure);
    expect(() => b.receive(grantConsumingRequest)).toThrow(expect.objectContaining({ code: "replayed-frame" }));
  });

  it("rejects reordered counters and resumes cleanly once order is restored", () => {
    const { a, b } = establish();
    const [first] = a.send(encoder.encode("first"));
    const [second] = a.send(encoder.encode("second"));
    expect(() => b.receive(second)).toThrow(expect.objectContaining({ code: "reordered-frame" }));
    expect(b.receive(first)).toEqual({ type: "data", payload: encoder.encode("first") });
    expect(b.receive(second)).toEqual({ type: "data", payload: encoder.encode("second") });
  });

  it("rejects tampered frames and frames sealed under another channel's keys", () => {
    const { a, b } = establish();
    const [frame] = a.send(encoder.encode("payload"));
    const tampered = Uint8Array.from(frame);
    tampered[tampered.length - 20] ^= 0x01;
    expect(() => b.receive(tampered)).toThrow(expect.objectContaining({ code: "tampered-frame" }));

    const other = establish();
    const [foreign] = other.a.send(encoder.encode("payload"));
    expect(() => b.receive(foreign)).toThrow(expect.objectContaining({ code: "tampered-frame" }));
    expect(b.receive(frame)).toEqual({ type: "data", payload: encoder.encode("payload") });
  });

  it("closes with authentication: no post-close frames, no truncation ambiguity, duplex half-close", () => {
    const { a, b } = establish();
    const [pending] = a.send(encoder.encode("in flight"));
    expect(b.receive(pending)).toEqual({ type: "data", payload: encoder.encode("in flight") });
    const [closeFrame] = a.close("task finished");
    expect(b.receive(closeFrame)).toEqual({ type: "closed", reason: "task finished" });
    expect(a.state).toBe("local-closed");
    expect(b.state).toBe("peer-closed");
    expect(() => a.send(encoder.encode("late"))).toThrow(expect.objectContaining({ code: "channel-closed" }));
    expect(() => a.rekey()).toThrow(expect.objectContaining({ code: "channel-closed" }));
    expect(() => a.close()).toThrow(expect.objectContaining({ code: "channel-closed" }));
    expect(() => b.receive(pending)).toThrow(expect.objectContaining({ code: "channel-closed" }));

    const [reply] = b.send(encoder.encode("still open this way"));
    expect(a.receive(reply)).toEqual({ type: "data", payload: encoder.encode("still open this way") });
    const [bClose] = b.close();
    expect(a.receive(bClose)).toEqual({ type: "closed", reason: null });
    expect(a.state).toBe("closed");
    expect(b.state).toBe("closed");
  });

  it("rekeys explicitly with continuity and rejects old-epoch frames and tampered rekeys", () => {
    const { a, b } = establish();
    const [preRekey] = a.send(encoder.encode("epoch zero"));
    expect(b.receive(preRekey)).toEqual({ type: "data", payload: encoder.encode("epoch zero") });

    const rekeyFrame = a.rekey();
    const tamperedRekey = Uint8Array.from(rekeyFrame);
    tamperedRekey[tamperedRekey.length - 1] ^= 0x01;
    expect(() => b.receive(tamperedRekey)).toThrow(expect.objectContaining({ code: "tampered-frame" }));
    expect(b.receive(rekeyFrame)).toEqual({ type: "rekeyed" });

    const [postRekey] = a.send(encoder.encode("epoch one"));
    expect(b.receive(postRekey)).toEqual({ type: "data", payload: encoder.encode("epoch one") });
    expect(() => b.receive(preRekey)).toThrow(expect.objectContaining({ code: "replayed-frame" }));
  });

  it("rekeys automatically on counter exhaustion without losing data", () => {
    const { a, b } = establish({ framesPerEpoch: 2 });
    const first = a.send(encoder.encode("frame 1"));
    expect(first).toHaveLength(1);
    expect(b.receive(first[0])).toEqual({ type: "data", payload: encoder.encode("frame 1") });

    const second = a.send(encoder.encode("frame 2"));
    expect(second).toHaveLength(2);
    expect(b.receive(second[0])).toEqual({ type: "rekeyed" });
    expect(b.receive(second[1])).toEqual({ type: "data", payload: encoder.encode("frame 2") });

    for (let round = 3; round <= 6; round += 1) {
      const frames = a.send(encoder.encode(`frame ${round}`));
      const receipts = frames.map((frame) => b.receive(frame));
      expect(receipts.at(-1)).toEqual({ type: "data", payload: encoder.encode(`frame ${round}`) });
    }
  });

  it("fails terminally on epoch exhaustion before any frame is sealed", () => {
    const { a, b } = establish({ framesPerEpoch: 2, maxEpoch: 0 });
    const first = a.send(encoder.encode("frame 1"));
    expect(first).toHaveLength(1);
    expect(b.receive(first[0])).toEqual({ type: "data", payload: encoder.encode("frame 1") });
    // The next send requires an automatic rekey past maxEpoch: the channel is
    // poisoned before anything is sealed, so no frame ever leaves under a
    // destroyed or zeroed key.
    expect(() => a.send(encoder.encode("frame 2"))).toThrow(expect.objectContaining({ code: "counter-exhausted" }));
    expect(a.state).toBe("failed");
    expect(() => a.send(encoder.encode("frame 3"))).toThrow(expect.objectContaining({ code: "channel-closed" }));
    expect(() => a.rekey()).toThrow(expect.objectContaining({ code: "channel-closed" }));
    expect(() => a.close("late")).toThrow(expect.objectContaining({ code: "channel-closed" }));
    const [fromPeer] = b.send(encoder.encode("peer data"));
    expect(() => a.receive(fromPeer)).toThrow(expect.objectContaining({ code: "channel-closed" }));
  });

  it("fails terminally when the peer rekeys past the receive-side epoch limit", () => {
    const controller = identity();
    const edge = identity();
    const context = wp1Context(controller, edge, "stream-1");
    const init = initiateChannel({ identity: controller, peerPublicKeySpki: edge.publicKeySpki, sessionId: SESSION_ID, context });
    const accepted = acceptChannel({ identity: edge, peerPublicKeySpki: controller.publicKeySpki, sessionId: SESSION_ID, context, maxEpoch: 0 }, init.hello);
    const { channel: a, confirm } = init.complete(accepted.accept);
    const b = accepted.complete(confirm);
    const rekeyFrame = a.rekey();
    expect(() => b.receive(rekeyFrame)).toThrow(expect.objectContaining({ code: "counter-exhausted" }));
    expect(b.state).toBe("failed");
    expect(() => b.send(encoder.encode("x"))).toThrow(expect.objectContaining({ code: "channel-closed" }));
    expect(() => b.receive(rekeyFrame)).toThrow(expect.objectContaining({ code: "channel-closed" }));
  });

  it("aborts idempotently on transport failure without emitting frames", () => {
    const { a, b } = establish();
    const [inflight] = a.send(encoder.encode("sealed before abort"));
    a.abort();
    expect(a.state).toBe("failed");
    a.abort();
    expect(a.state).toBe("failed");
    expect(() => a.send(encoder.encode("x"))).toThrow(expect.objectContaining({ code: "channel-closed" }));
    expect(() => a.close()).toThrow(expect.objectContaining({ code: "channel-closed" }));
    expect(() => a.rekey()).toThrow(expect.objectContaining({ code: "channel-closed" }));
    const [reply] = b.send(encoder.encode("peer unaffected"));
    expect(() => a.receive(reply)).toThrow(expect.objectContaining({ code: "channel-closed" }));
    expect(b.receive(inflight)).toEqual({ type: "data", payload: encoder.encode("sealed before abort") });
  });

  it("bounds frame sizes in both directions", () => {
    const { a, b } = establish();
    expect(() => a.send(new Uint8Array(65_537))).toThrow(expect.objectContaining({ code: "frame-too-large" }));
    expect(() => b.receive(new Uint8Array(14 + 65_536 + 17))).toThrow(expect.objectContaining({ code: "frame-too-large" }));
    expect(() => b.receive(new Uint8Array(29))).toThrow(expect.objectContaining({ code: "tampered-frame" }));

    const small = establish({ maxFrameBytes: 8 });
    expect(() => small.a.close("a reason far larger than eight bytes")).toThrow(expect.objectContaining({ code: "frame-too-large" }));
    expect(small.a.state).toBe("open");
    const [closeFrame] = small.a.close("bye");
    expect(small.b.receive(closeFrame)).toEqual({ type: "closed", reason: "bye" });
  });
});

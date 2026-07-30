import { describe, expect, it } from "vitest";
import { encodeNativeFrame, NativeFramingError, NativeMessageDecoder } from "./native-framing.js";
import { parseNativeMessage } from "./native-protocol.js";

const hello = {
  version: 1 as const,
  type: "hello" as const,
  role: "extension" as const,
  extensionId: "extension-id",
  extensionPublicKey: "ZXh0ZW5zaW9uLWtleQ==",
  extensionNonce: "ZXh0ZW5zaW9uLW5vbmNl",
};

describe("Native Messaging framing contract", () => {
  it("reassembles arbitrarily fragmented frames and coalesced messages", () => {
    const first = encodeNativeFrame(hello);
    const second = encodeNativeFrame({ ...hello, requestId: "second" });
    const decoder = new NativeMessageDecoder();
    const received = [];

    for (const byte of Buffer.concat([first, second])) received.push(...decoder.feed(Uint8Array.of(byte)));

    expect(received).toEqual([hello, { ...hello, requestId: "second" }]);
    decoder.finish();
    expect(decoder.pendingBytes).toBe(0);
  });

  it("rejects malformed, oversized, and truncated frames deterministically", () => {
    const decoder = new NativeMessageDecoder();
    const malformed = Buffer.alloc(4);
    malformed.writeUInt32LE(2, 0);
    expect(() => decoder.feed(Buffer.concat([malformed, Buffer.from("{}")]))).toThrow(NativeFramingError);

    const truncated = new NativeMessageDecoder();
    const frame = encodeNativeFrame(hello);
    truncated.feed(frame.subarray(0, frame.length - 1));
    expect(() => truncated.finish()).toThrow(NativeFramingError);

    const oversized = Buffer.alloc(4);
    oversized.writeUInt32LE(1024 * 1024 + 1, 0);
    expect(() => new NativeMessageDecoder().feed(oversized)).toThrow(NativeFramingError);
  });

  it("keeps protocol validation at the transport edge", () => {
    expect(parseNativeMessage(JSON.stringify(hello))).toEqual(hello);
    expect(parseNativeMessage(JSON.stringify({ ...hello, version: 2 }))).toBeNull();
    expect(parseNativeMessage(JSON.stringify({ ...hello, unexpected: true }))).toBeNull();
    const approval = {
      version: 1 as const,
      type: "approveSession" as const,
      sessionId: "session-1",
      controllerPrincipalId: "controller-1",
      displayControllerName: "display",
      taskLabel: "task",
      requestedCapabilities: ["bookmarks"],
      ttlMs: 1_000,
    };
    expect(parseNativeMessage(JSON.stringify(approval))).toBeNull();
  });
});

import { describe, expect, it } from "vitest";
import { assertNativeMessage, MAX_TTL_MS, NATIVE_PROTOCOL_VERSION, validateNativeMessage, validateSessionRecord, type SessionRecord } from "./native-protocol.js";

const session = (overrides: Partial<SessionRecord> = {}): SessionRecord => ({ id: "task-1", controllerPrincipalId: "sha256/controller", displayControllerName: "CLI", taskLabel: "research", requestedCapabilities: ["cdp"], access: { level: "selectedTabs", tabIds: [], domains: [] }, createdAt: 10, expiresAt: 10 + 60_000, state: "pending", ...overrides });

describe("native protocol validation", () => {
  it("accepts v1 records and rejects oversized or malformed records", () => {
    expect(validateSessionRecord(session())).toBe(true);
    expect(validateSessionRecord(session({ expiresAt: null }))).toBe(true);
    expect(validateSessionRecord(session({ taskLabel: "x".repeat(129) }))).toBe(false);
    expect(validateSessionRecord(session({ expiresAt: 10 + MAX_TTL_MS + 1 }))).toBe(false);
    expect(validateSessionRecord(session({ requestedCapabilities: ["cdp", "cdp"] as ["cdp", "cdp"] }))).toBe(false);
    expect(validateSessionRecord({ ...session(), unexpected: true })).toBe(false);
  });
  it("requires version, role, and complete handshake transcript fields", () => {
    const hello = { version: NATIVE_PROTOCOL_VERSION, type: "hello", role: "extension", extensionId: "ext", extensionPublicKey: "aGVsbG8", extensionNonce: "bm9uY2U" } as const;
    expect(validateNativeMessage(hello)).toBe(true);
    expect(validateNativeMessage({ ...hello, version: 1 })).toBe(false);
    expect(validateNativeMessage({ ...hello, role: "companion" })).toBe(false);
    expect(() => assertNativeMessage({ ...hello, type: "nope" })).toThrow();
    const challenge = { version: NATIVE_PROTOCOL_VERSION, type: "helloChallenge", role: "companion", companionId: `sha256/${Buffer.alloc(32, 1).toString("base64")}`, companionPublicKey: "Y29tcA", extensionId: "ext", extensionPublicKey: "ZXh0", extensionNonce: "bm9uY2U", companionNonce: "Y29tcA", signature: "A".repeat(86) } as const;
    expect(validateNativeMessage(challenge)).toBe(true);
    expect(validateNativeMessage({ ...challenge, signature: undefined })).toBe(false);
    expect(validateNativeMessage({ version: NATIVE_PROTOCOL_VERSION, type: "revokeDevice", requestId: "forget-1" })).toBe(true);
    expect(validateNativeMessage({ version: NATIVE_PROTOCOL_VERSION, type: "revokeDevice", requestId: "" })).toBe(false);
    const approval = { version: NATIVE_PROTOCOL_VERSION, type: "approveSession", requestId: "approve-1", sessionId: "task-1", controllerPrincipalId: "sha256/controller", displayControllerName: "CLI", taskLabel: "research", requestedCapabilities: ["cdp"], expiresAt: null, access: { level: "domains", tabIds: [], domains: ["example.com"] } } as const;
    expect(validateNativeMessage(approval)).toBe(true);
    expect(validateNativeMessage({ ...approval, access: { level: "domains", tabIds: [], domains: ["https://example.com/path"] } })).toBe(false);
    expect(validateNativeMessage({ ...approval, unexpected: true })).toBe(false);
    const accessPending = {
      version: NATIVE_PROTOCOL_VERSION,
      type: "accessPending",
      request: {
        id: "access-1",
        sessionId: "task-1",
        delta: { kind: "domains", tabIds: [], domains: ["example.com"] },
        requestedAccess: { level: "domains", tabIds: [], domains: ["example.com"] },
        createdAt: 10,
      },
    } as const;
    expect(validateNativeMessage(accessPending)).toBe(true);
    expect(validateNativeMessage({ ...accessPending, request: { ...accessPending.request, createdAt: 0 } })).toBe(false);
  });
});

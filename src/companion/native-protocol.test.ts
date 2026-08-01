import { describe, expect, it } from "vitest";
import { assertNativeMessage, canonicalSessionRecord, MAX_TTL_MS, NATIVE_PROTOCOL_VERSION, validateNativeMessage, validateSessionRecord, type SessionRecord } from "./native-protocol.js";

const route = { kind: "local", endpointId: "sha256/endpoint", controllerPrincipalId: "sha256/controller", routePolicy: "localOnly", accessCeiling: { level: "selectedTabs", tabIds: [], domains: [] }, hubId: null, routeId: null, streamId: null } as const;
const session = (overrides: Partial<SessionRecord> = {}): SessionRecord => ({ id: "task-1", controllerPrincipalId: "sha256/controller", displayControllerName: "CLI", taskLabel: "research", requestedCapabilities: ["cdp"], access: { level: "selectedTabs", tabIds: [], domains: [] }, createdAt: 10, expiresAt: 10 + 60_000, state: "pending", route, ...overrides });

describe("native protocol validation", () => {
  it("accepts versioned records and rejects oversized or malformed records", () => {
    expect(validateSessionRecord(session())).toBe(true);
    expect(validateSessionRecord(session({ expiresAt: null }))).toBe(true);
    expect(validateSessionRecord(session({ taskLabel: "x".repeat(129) }))).toBe(false);
    expect(validateSessionRecord(session({ expiresAt: 10 + MAX_TTL_MS + 1 }))).toBe(false);
    expect(validateSessionRecord(session({ requestedCapabilities: ["cdp", "cdp"] as ["cdp", "cdp"] }))).toBe(false);
    expect(validateSessionRecord({ ...session(), unexpected: true })).toBe(false);
    expect(Buffer.compare(canonicalSessionRecord(session()), canonicalSessionRecord({ ...session(), route: { ...route } }))).toBe(0);
    expect(Buffer.compare(canonicalSessionRecord(session()), canonicalSessionRecord({ ...session(), route: { ...route, endpointId: "sha256/other" } }))).not.toBe(0);
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
    const approval = { version: NATIVE_PROTOCOL_VERSION, type: "approveSession", requestId: "approve-1", sessionId: "task-1", controllerPrincipalId: "sha256/controller", displayControllerName: "CLI", taskLabel: "research", requestedCapabilities: ["cdp"], expiresAt: null, access: { level: "domains", tabIds: [], domains: ["example.com"] }, route: { ...route, accessCeiling: { level: "domains", tabIds: [], domains: ["example.com"] } } } as const;
    expect(validateNativeMessage(approval)).toBe(true);
    expect(validateNativeMessage({ ...approval, access: { level: "domains", tabIds: [], domains: ["https://example.com/path"] } })).toBe(false);
    expect(validateNativeMessage({ ...approval, unexpected: true })).toBe(false);
    expect(validateNativeMessage({ version: NATIVE_PROTOCOL_VERSION, type: "revokeSession", sessionId: "task-1", reason: "user revoked" })).toBe(true);
    expect(validateNativeMessage({ version: NATIVE_PROTOCOL_VERSION, type: "revokeSession", sessionId: "task-1", unexpected: true })).toBe(false);
    expect(validateNativeMessage({ version: NATIVE_PROTOCOL_VERSION, type: "sessionResuming", session: session({ state: "reconnecting" }), relayUrl: "ws://127.0.0.1/extension#token" })).toBe(true);
    expect(validateNativeMessage({ version: NATIVE_PROTOCOL_VERSION, type: "sessionResuming", session: session({ state: "active" }), relayUrl: "ws://127.0.0.1/extension#token" })).toBe(false);
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
    const tab = { tabId: 42, title: "Example", url: "https://example.com/", ownership: "unclaimed", claimability: "claimable" } as const;
    expect(validateNativeMessage({ version: NATIVE_PROTOCOL_VERSION, type: "listTabs", requestId: "tabs-1", scope: "all", sessionId: "task-1" })).toBe(true);
    expect(validateNativeMessage({ version: NATIVE_PROTOCOL_VERSION, type: "listTabs", requestId: "tabs-2", scope: "session" })).toBe(false);
    expect(validateNativeMessage({ version: NATIVE_PROTOCOL_VERSION, type: "tabsListed", requestId: "tabs-1", tabs: [tab] })).toBe(true);
    expect(validateNativeMessage({ version: NATIVE_PROTOCOL_VERSION, type: "tabsListed", requestId: "tabs-1", tabs: [{ ...tab, ownership: "session-secret" }] })).toBe(false);
    expect(validateNativeMessage({ version: NATIVE_PROTOCOL_VERSION, type: "claimTab", requestId: "claim-1", sessionId: "task-1", tabId: 42 })).toBe(true);
    expect(validateNativeMessage({ version: NATIVE_PROTOCOL_VERSION, type: "tabClaimed", requestId: "claim-1", sessionId: "task-1", tabId: 42, ok: true, tab: { ...tab, ownership: "currentSession", claimability: "alreadyShared" } })).toBe(true);
    expect(validateNativeMessage({ version: NATIVE_PROTOCOL_VERSION, type: "enrollPending", enrollmentId: "enroll-1", profileName: "hermes-research", profileFingerprint: "sha256/abc", expiresAt: 10 })).toBe(true);
    expect(validateNativeMessage({ version: NATIVE_PROTOCOL_VERSION, type: "enrollPending", enrollmentId: "enroll-1", profileName: "bad/name", profileFingerprint: "sha256/abc", expiresAt: 10 })).toBe(false);
    expect(validateNativeMessage({ version: NATIVE_PROTOCOL_VERSION, type: "confirmEnrollment", requestId: "req-1", enrollmentId: "enroll-1", code: "123456" })).toBe(true);
    expect(validateNativeMessage({ version: NATIVE_PROTOCOL_VERSION, type: "confirmEnrollment", requestId: "req-1", enrollmentId: "enroll-1", code: "12345" })).toBe(false);
    expect(validateNativeMessage({ version: NATIVE_PROTOCOL_VERSION, type: "enrollResult", requestId: "req-1", enrollmentId: "enroll-1", ok: true, profileName: "hermes-research" })).toBe(true);
    expect(validateNativeMessage({ version: NATIVE_PROTOCOL_VERSION, type: "enrollResult", requestId: "req-1", enrollmentId: "enroll-1", ok: false, error: "incorrect code", unexpected: 1 })).toBe(false);
    expect(validateNativeMessage({ version: NATIVE_PROTOCOL_VERSION, type: "revokeProfile", requestId: "req-2", profileName: "hermes-research" })).toBe(true);
    expect(validateNativeMessage({ version: NATIVE_PROTOCOL_VERSION, type: "revokeProfile", requestId: "req-2", profileName: "bad/name" })).toBe(false);
    const snapshot = { version: NATIVE_PROTOCOL_VERSION, type: "snapshot", pending: [], active: [], reconnecting: [], sharedTabs: [], pendingAccess: [] } as const;
    expect(validateNativeMessage(snapshot)).toBe(true);
    expect(validateNativeMessage({ ...snapshot, reconnecting: [session({ state: "reconnecting" })] })).toBe(true);
    expect(validateNativeMessage({ ...snapshot, reconnecting: [session({ state: "active" })] })).toBe(false);
    expect(validateNativeMessage({ ...snapshot, active: [session({ state: "reconnecting" })] })).toBe(false);
    expect(validateNativeMessage({ ...snapshot, enrolledProfiles: [{ name: "hermes-research", principalId: "sha256/abc", enrolledAt: 10 }] })).toBe(true);
    expect(validateNativeMessage({ ...snapshot, enrolledProfiles: [{ name: "hermes-research", principalId: "not-a-fingerprint", enrolledAt: 10 }] })).toBe(false);
  });
});

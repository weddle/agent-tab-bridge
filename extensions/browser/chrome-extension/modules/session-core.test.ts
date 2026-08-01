import { describe, expect, it } from "vitest";
import {
  claimTab,
  classifyTabAccess,
  parseRelayPairingUrl,
  matchesSessionAuthority,
  makeSessionRecoveryRecord,

  releaseSessionTabs,
  releaseTab,
  sessionOwnsGroup,
  sessionOwnsTab,
  sessionTabIds,
  validateSessionRecoveryRecord,
} from "./session-core.js";

describe("Native Messaging session ownership", () => {
  it("keeps concurrent sessions' tab claims disjoint", () => {
    const owners = new Map<number, string>();
    expect(claimTab(owners, "session-a", 11)).toEqual({ ok: true });
    expect(claimTab(owners, "session-b", 11)).toEqual({
      ok: false,
      ownerSessionId: "session-a",
    });
    expect(claimTab(owners, "session-b", 12)).toEqual({ ok: true });
    expect(sessionTabIds(owners, "session-a")).toEqual([11]);
    expect(sessionTabIds(owners, "session-b")).toEqual([12]);
  });

  it("authorizes duplicate display titles only through the recorded group ID", () => {
    const groups = new Map<string, number>([
      ["session-a", 101],
      ["session-b", 202],
    ]);
    const duplicateTitle = "Agent Tab Bridge · Research";
    expect(duplicateTitle).toBe("Agent Tab Bridge · Research");
    expect(sessionOwnsGroup(groups, "session-a", 101)).toBe(true);
    expect(sessionOwnsGroup(groups, "session-b", 101)).toBe(false);
  });

  it("releases access only for its owner and tears down every tab on session stop", () => {
    const owners = new Map<number, string>([
      [21, "session-a"],
      [22, "session-a"],
      [23, "session-b"],
    ]);
    expect(releaseTab(owners, "session-b", 21)).toBe(false);
    expect(sessionOwnsTab(owners, "session-a", 21)).toBe(true);
    expect(releaseSessionTabs(owners, "session-a")).toEqual([21, 22]);
    expect(sessionOwnsTab(owners, "session-a", 21)).toBe(false);
    expect(sessionOwnsTab(owners, "session-b", 23)).toBe(true);
  });
  it("marks current, conflicting, claimable, and approval-gated tabs", () => {
    const owners = new Map<number, string>([
      [31, "session-a"],
      [32, "session-b"],
    ]);
    expect(classifyTabAccess(owners, "session-a", 31, true)).toEqual({
      ownership: "currentSession",
      claimability: "alreadyShared",
    });
    expect(classifyTabAccess(owners, "session-a", 32, true)).toEqual({
      ownership: "otherSession",
      claimability: "blocked",
    });
    expect(classifyTabAccess(owners, "session-a", 33, true)).toEqual({
      ownership: "unclaimed",
      claimability: "claimable",
    });
    expect(classifyTabAccess(owners, "session-a", 34, false)).toEqual({
      ownership: "unclaimed",
      claimability: "approvalRequired",
    });
  });

});

describe("popup approval authority", () => {
  const pending = {
    id: "session-a",
    controllerId: "sha256/controller",
    controllerName: "Local controller",
    taskLabel: "Research",
    capabilities: ["cdp"],
    access: { level: "selectedTabs", tabIds: [42], domains: [] },
    createdAt: 1_000,
    expiresAt: 61_000,
    state: "pending",
    route: { kind: "local", endpointId: "endpoint-a", controllerPrincipalId: "sha256/controller", routePolicy: "localOnly", accessCeiling: { level: "selectedTabs", tabIds: [42], domains: [] }, hubId: null, routeId: null, streamId: null },
  };

  it("permits only the exact approved pending record to become active", () => {
    expect(matchesSessionAuthority(pending, { ...pending, state: "active" })).toBe(true);
  });

  it("rejects every immutable-field substitution and duplicate active transition", () => {
    for (const replacement of [
      { id: "session-b" },
      { controllerId: "sha256/other" },
      { controllerName: "Other controller" },
      { taskLabel: "Other task" },
      { capabilities: [] },
      { access: { level: "selectedTabs", tabIds: [43], domains: [] } },
      { createdAt: 2_000 },
      { expiresAt: 62_000 },
      { route: { kind: "local", endpointId: "endpoint-b", routePolicy: "localOnly" } },
    ]) {
      expect(matchesSessionAuthority(pending, { ...pending, ...replacement, state: "active" })).toBe(false);
    }
    expect(matchesSessionAuthority(pending, { ...pending, state: "pending" })).toBe(false);
    expect(matchesSessionAuthority({ ...pending, state: "active" }, { ...pending, state: "active" })).toBe(false);
  });

  it("restores only an exact locally persisted authority and ownership record", () => {
    const active = { ...pending, state: "active" };
    const reconnecting = { ...pending, state: "reconnecting" };
    const record = makeSessionRecoveryRecord(active, 7, 11, [42]);
    expect(record).toEqual({
      version: 1,
      session: active,
      groupId: 7,
      anchorId: 11,
      tabIds: [42],
    });
    expect(validateSessionRecoveryRecord(record, reconnecting)).toEqual(record);
    const storageOrderedActive = {
      ...active,
      access: { domains: [], level: "selectedTabs", tabIds: [42] },
      route: { accessCeiling: { domains: [], level: "selectedTabs", tabIds: [42] }, controllerPrincipalId: "sha256/controller", endpointId: "endpoint-a", hubId: null, kind: "local", routeId: null, routePolicy: "localOnly", streamId: null },
    };
    const storageOrderedRecord = makeSessionRecoveryRecord(storageOrderedActive, 7, 11, [42]);
    expect(validateSessionRecoveryRecord(storageOrderedRecord, reconnecting)).not.toBeNull();
    expect(validateSessionRecoveryRecord(record, { ...reconnecting, taskLabel: "Substituted" })).toBeNull();
    expect(validateSessionRecoveryRecord({ ...record, tabIds: [42, 42] }, reconnecting)).toBeNull();
    expect(validateSessionRecoveryRecord({ ...record, extra: true }, reconnecting)).toBeNull();
  });
});

describe("ephemeral relay URLs", () => {
  it("accepts only a token-bearing local extension relay URL", () => {
    expect(parseRelayPairingUrl("ws://127.0.0.1:18797/extension#temporary-token")).toEqual({
      relayUrl: "ws://127.0.0.1:18797/extension",
      token: "temporary-token",
    });
  });

  it("rejects relay URLs that could escape the local relay boundary", () => {
    for (const value of [
      "",
      "wss://127.0.0.1:18797/extension#token",
      "ws://localhost:18797/extension#token",
      "ws://127.0.0.1:18797/other#token",
      "ws://127.0.0.1:18797/extension?debug=true#token",
      "ws://127.0.0.1:18797/extension#token#again",
    ]) {
      expect(parseRelayPairingUrl(value), value).toBeNull();
    }
  });
});

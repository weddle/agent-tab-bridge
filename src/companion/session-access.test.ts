import { describe, expect, it } from "vitest";
import {
  normalizeDomain,
  normalizeSessionAccess,
  normalizeSessionAccessDelta,
  upgradeSessionAccess,
} from "./session-access.js";

describe("session access authority", () => {
  it("normalizes selected tabs, domains, and full access deterministically", () => {
    expect(normalizeSessionAccess({ level: "selectedTabs", tabIds: [9, 3, 9], domains: [] })).toEqual({
      level: "selectedTabs",
      tabIds: [3, 9],
      domains: [],
    });
    expect(normalizeSessionAccess({ level: "domains", tabIds: [], domains: ["*.Example.com", "api.example.com", "example.com"] })).toEqual({
      level: "domains",
      tabIds: [],
      domains: ["api.example.com", "example.com"],
    });
    expect(normalizeSessionAccess({ level: "full", tabIds: [], domains: [] })).toEqual({ level: "full", tabIds: [], domains: [] });
    expect(normalizeDomain("*.Example.com")).toBe("example.com");
    expect(() => normalizeSessionAccess({ level: "full", tabIds: [1], domains: [] })).toThrow(/cannot include/);
  });

  it("permits only additive upgrades and preserves prior selected-tab authority", () => {
    const selected = { level: "selectedTabs", tabIds: [7], domains: [] } as const;
    const domains = upgradeSessionAccess(selected, normalizeSessionAccessDelta({ kind: "domains", tabIds: [], domains: ["example.com"] }));
    expect(domains).toEqual({ level: "domains", tabIds: [7], domains: ["example.com"] });
    expect(upgradeSessionAccess(domains, { kind: "tabs", tabIds: [8], domains: [] })).toEqual({
      level: "domains",
      tabIds: [7, 8],
      domains: ["example.com"],
    });
    expect(upgradeSessionAccess(domains, { kind: "full", tabIds: [], domains: [] })).toEqual({ level: "full", tabIds: [], domains: [] });
    expect(() => upgradeSessionAccess(domains, { kind: "domains", tabIds: [], domains: ["example.com"] })).toThrow(/does not add authority/);
  });
});

import { describe, expect, it } from "vitest";
import {
  FULL_ACCESS_CONSEQUENCE,
  claimedStringDetails,
  isLocalOnlyGrant,
  rememberedGrantLabel,
  renderClaimedString,
  renderHubConnectionStatus,
  renderPairingFailure,
  renderSessionState,
  renderRememberedGrantChip,
  renderRouteMarker,
  renderViaHubIdentity,
  renderStandingGrantScope,
  renderVerifiedIdentity,
  verifiedIdentityDetails,
} from "./ui-vocabulary.js";
describe("consent vocabulary renderers", () => {
  it("renders verified identities with an eight-character fingerprint and full value on demand", () => {
    const full = "sha256/abcdefghijklmnop";
    expect(renderVerifiedIdentity("den-server", full)).toBe("den-server · verified key sha256/abcdefgh");
    expect(verifiedIdentityDetails("den-server", full)).toMatchObject({
      text: "den-server · verified key sha256/abcdefgh",
      fullValue: full,
      ariaLabel: "den-server · verified key sha256/abcdefghijklmnop",
    });
  });

  it("quotes claims and marks them unverified without policy semantics", () => {
    expect(renderClaimedString("Research task")).toBe("“Research task” (unverified)");
    expect(claimedStringDetails("Research task")).toEqual({
      text: "“Research task” (unverified)",
      policyRelevant: false,
    });
  });
});

describe("reconnecting and hub vocabulary", () => {
  it("uses amber attention for reconnecting and does not treat it as active", () => {
    expect(renderHubConnectionStatus("unreachable")).toEqual({ state: "connecting", text: "unreachable" });
    expect(renderHubConnectionStatus("connected")).toEqual({ state: "connected", text: "connected" });
    expect(renderSessionState("reconnecting")).toEqual({ state: "connecting", text: "reconnecting" });
    expect(renderSessionState("active")).toEqual({ state: "connected", text: "active" });
  });

  it("names pairing failures with a fresh-code or refusal action", () => {
    expect(renderPairingFailure("wrong-code")).toContain("fresh code");
    expect(renderPairingFailure("key-mismatch")).toContain("refused");
    expect(renderPairingFailure("duplicate-identity")).toContain("already enrolled");
  });
  it("renders a remote via-hub identity and route marker without local-route vocabulary", () => {
    const session = { route: { kind: "routed", hubId: "sha256/hub-key" } };
    expect(renderViaHubIdentity(session)).toMatchObject({
      text: "VIA via home hub · Home hub · verified key sha256/hub-key",
    });
    expect(renderRouteMarker(session)).toBe(" ⟐");
    expect(renderRouteMarker({ route: { kind: "local" } })).toBe("");
  });
});

describe("local standing-grant presentation", () => {
  const grant = {
    version: 2,
    controllerId: "sha256/controller",
    route: {
      kind: "local",
      routePolicy: "localOnly",
      accessCeiling: { level: "domains", tabIds: [], domains: ["example.com"] },
    },
  };

  it("keeps migrated local-only grants in local vocabulary and exposes the remembered chip", () => {
    expect(isLocalOnlyGrant(grant)).toBe(true);
    expect(renderStandingGrantScope(grant)).toBe("Sites: example.com (including subdomains)");
    expect(renderStandingGrantScope(grant)).not.toContain("localOnly");
    expect(rememberedGrantLabel()).toBe("Remembered grant");
    expect(renderRememberedGrantChip(grant)).toBe(rememberedGrantLabel());
  });

  it("keeps the full-access consequence exact", () => {
    expect(FULL_ACCESS_CONSEQUENCE).toBe(
      "It can open any website and control tabs in this session's group; tabs outside the group stay outside it.",
    );
  });
});

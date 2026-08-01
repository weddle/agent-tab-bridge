import { describe, expect, it } from "vitest";
import {
  FULL_ACCESS_CONSEQUENCE,
  claimedStringDetails,
  isLocalOnlyGrant,
  rememberedGrantLabel,
  renderClaimedString,
  renderRememberedGrantChip,
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

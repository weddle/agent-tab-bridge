import { describe, expect, it } from "vitest";
import { accessWithinStandingGrant, isStandingGrant, localStandingGrantFor, migrateStandingGrants, rememberStandingGrant, routedStandingGrantFor } from "./standing-grants.js";

const endpointId = "sha256/endpoint";
const controllerId = "sha256/controller";
const localRoute = { kind: "local", endpointId, controllerPrincipalId: controllerId, routePolicy: "localOnly", accessCeiling: { level: "domains", tabIds: [], domains: ["example.com"] }, hubId: null, routeId: null, streamId: null } as const;
const routedRoute = { ...localRoute, kind: "routed", routePolicy: "routed", hubId: "sha256/hub", routeId: "route-1", streamId: "stream-1" } as const;

describe("standing grant route policy", () => {
  it("migrates legacy grants once into explicit local-only authority", () => {
    const legacy = [{ controllerId, controllerName: "Research", level: "domains", domains: ["example.com"], createdAt: 1 }];
    const migrated = migrateStandingGrants(legacy, endpointId);
    expect(migrated).toEqual([{ version: 2, controllerId, controllerName: "Research", route: localRoute, createdAt: 1 }]);
    expect(migrateStandingGrants(migrated, endpointId)).toEqual(migrated);
    expect(isStandingGrant(migrated[0])).toBe(true);
  });

  it("never finds or consumes a local-only migration for a routed request", () => {
    const [grant] = migrateStandingGrants([{ controllerId, controllerName: "Research", level: "domains", domains: ["example.com"], createdAt: 1 }], endpointId);
    const routed = { ...localRoute, kind: "routed" as const, routePolicy: "routed" as const, hubId: "hub-1", routeId: "route-1", streamId: "stream-1" };
    expect(localStandingGrantFor([grant], controllerId, routed)).toBeNull();
    expect(accessWithinStandingGrant({ level: "domains", tabIds: [], domains: ["example.com"] }, localStandingGrantFor([grant], controllerId, routed))).toBe(false);
    expect(accessWithinStandingGrant({ level: "domains", tabIds: [], domains: ["example.com"] }, localStandingGrantFor([grant], controllerId, localRoute))).toBe(true);
  });

  it("keeps remembered authority endpoint-bound and local-only", () => {
    const session = { controllerId, controllerName: "Research", route: localRoute, access: { level: "domains", tabIds: [], domains: ["example.com"] } };
    const [grant] = rememberStandingGrant([], session);
    expect(grant.route).toMatchObject({ endpointId, controllerPrincipalId: controllerId, routePolicy: "localOnly", hubId: null, routeId: null, streamId: null });
  });

  it("remembers remote authority by profile and hub, without allowing widening", () => {
    const session = { controllerId, controllerName: "Research", route: routedRoute, access: { level: "domains", tabIds: [], domains: ["example.com"] } };
    const [grant] = rememberStandingGrant([], session);
    expect(routedStandingGrantFor([grant], controllerId, routedRoute)).toBe(grant);
    expect(routedStandingGrantFor([grant], controllerId, { ...routedRoute, hubId: "sha256/other-hub" })).toBeNull();
    expect(accessWithinStandingGrant({ level: "domains", tabIds: [], domains: ["example.com"] }, grant)).toBe(true);
    expect(accessWithinStandingGrant({ level: "domains", tabIds: [], domains: ["other.example"] }, grant)).toBe(false);
  });

  it("does not widen remembered selected-tab scope", () => {
    const session = { controllerId, controllerName: "Research", route: routedRoute, access: { level: "selectedTabs", tabIds: [4], domains: [] } };
    const [grant] = rememberStandingGrant([], session);
    expect(accessWithinStandingGrant({ level: "selectedTabs", tabIds: [4], domains: [] }, grant)).toBe(true);
    expect(accessWithinStandingGrant({ level: "selectedTabs", tabIds: [5], domains: [] }, grant)).toBe(false);
  });
});

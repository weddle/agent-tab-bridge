import { describe, expect, it } from "vitest";
import { accessWithinStandingGrant, isStandingGrant, localStandingGrantFor, migrateStandingGrants, rememberStandingGrant } from "./standing-grants.js";

const endpointId = "sha256/endpoint";
const controllerId = "sha256/controller";
const localRoute = { kind: "local", endpointId, controllerPrincipalId: controllerId, routePolicy: "localOnly", accessCeiling: { level: "domains", tabIds: [], domains: ["example.com"] }, hubId: null, routeId: null, streamId: null } as const;

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
});

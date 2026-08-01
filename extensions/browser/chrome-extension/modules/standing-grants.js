function validAccess(value) {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).length !== 3 || !["level", "tabIds", "domains"].every((field) => Object.hasOwn(value, field)) || !["selectedTabs", "domains", "full"].includes(value.level) || !Array.isArray(value.tabIds) || !Array.isArray(value.domains) || value.tabIds.some((id) => !Number.isInteger(id) || id < 0) || value.domains.some((domain) => typeof domain !== "string")) return false;
  const tabIds = [...new Set(value.tabIds)].sort((left, right) => left - right);
  const domains = [...new Set(value.domains)].sort();
  return tabIds.length === value.tabIds.length && domains.length === value.domains.length && tabIds.every((id, index) => id === value.tabIds[index]) && domains.every((domain, index) => domain === value.domains[index]) && ((value.level === "selectedTabs" && domains.length === 0) || (value.level === "domains" && domains.length > 0) || (value.level === "full" && tabIds.length === 0 && domains.length === 0));
}

function validId(value) {
  return typeof value === "string" && value.length > 0 && value.length <= 256;
}

function validRoute(value) {
  return !!value && typeof value === "object" && !Array.isArray(value) && Object.keys(value).length === 8 && ["kind", "endpointId", "controllerPrincipalId", "routePolicy", "accessCeiling", "hubId", "routeId", "streamId"].every((field) => Object.hasOwn(value, field)) && validId(value.endpointId) && validId(value.controllerPrincipalId) && validAccess(value.accessCeiling) && ((value.kind === "local" && value.routePolicy === "localOnly" && value.hubId === null && value.routeId === null && value.streamId === null) || (value.kind === "routed" && value.routePolicy === "routed" && validId(value.hubId)));
}

function legacyGrant(value) {
  return !!value && typeof value === "object" && validId(value.controllerId) && typeof value.controllerName === "string" && (value.level === "selectedTabs" || value.level === "domains") && Array.isArray(value.domains) && value.domains.every((domain) => typeof domain === "string") && Number.isInteger(value.createdAt);
}

export function isStandingGrant(value) {
  return !!value && typeof value === "object" && !Array.isArray(value) && Object.keys(value).length === 5 && ["version", "controllerId", "controllerName", "route", "createdAt"].every((field) => Object.hasOwn(value, field)) && value.version === 2 && validId(value.controllerId) && typeof value.controllerName === "string" && validRoute(value.route) && value.route.controllerPrincipalId === value.controllerId && Number.isInteger(value.createdAt);
}

/** One-way, idempotent conversion: no v1 grant can acquire a routed policy. */
export function migrateStandingGrants(grants, endpointId) {
  if (!Array.isArray(grants) || !validId(endpointId)) return [];
  return grants.flatMap((grant) => {
    if (isStandingGrant(grant)) return [grant];
    if (!legacyGrant(grant)) return [];
    const accessCeiling = { level: grant.level, tabIds: [], domains: [...new Set(grant.domains)].sort() };
    return [{ version: 2, controllerId: grant.controllerId, controllerName: grant.controllerName, route: { kind: "local", endpointId, controllerPrincipalId: grant.controllerId, routePolicy: "localOnly", accessCeiling, hubId: null, routeId: null, streamId: null }, createdAt: grant.createdAt }];
  });
}

export function localStandingGrantFor(grants, controllerId, route) {
  if (!route || route.kind !== "local" || route.routePolicy !== "localOnly") return null;
  return grants.find((grant) => grant.controllerId === controllerId && grant.route.kind === "local" && grant.route.routePolicy === "localOnly" && grant.route.endpointId === route.endpointId && grant.route.controllerPrincipalId === route.controllerPrincipalId) ?? null;
}
export function routedStandingGrantFor(grants, controllerId, route) {
  if (!route || route.kind !== "routed" || route.routePolicy !== "routed" || !validId(route.hubId)) return null;
  return grants.find((grant) => grant.controllerId === controllerId && grant.route.kind === "routed" && grant.route.routePolicy === "routed" && grant.route.controllerPrincipalId === route.controllerPrincipalId && grant.route.hubId === route.hubId) ?? null;
}

export function accessWithinStandingGrant(access, grant) {
  if (!grant || !access || access.level === "full") return false;
  const ceiling = grant.route.accessCeiling;
  return access.level === "selectedTabs" || (access.level === "domains" && ceiling.level === "domains" && access.domains.every((domain) => ceiling.domains.includes(domain)));
}

export function rememberStandingGrant(grants, session) {
  const route = session?.route;
  if (!route || (route.kind !== "local" && route.kind !== "routed") || session.access?.level === "full" || (route.kind === "routed" && !validId(route.hubId))) return grants;
  const existing = route.kind === "routed" ? routedStandingGrantFor(grants, session.controllerId, route) : localStandingGrantFor(grants, session.controllerId, route);
  const priorDomains = existing?.route.accessCeiling.level === "domains" ? existing.route.accessCeiling.domains : [];
  const domains = session.access.level === "domains" ? [...new Set([...priorDomains, ...session.access.domains])].sort() : priorDomains;
  const level = session.access.level === "domains" || existing?.route.accessCeiling.level === "domains" ? "domains" : "selectedTabs";
  return [...grants.filter((grant) => grant.controllerId !== session.controllerId || (route.kind === "routed" ? grant.route.kind !== "routed" || grant.route.hubId !== route.hubId : grant.route.endpointId !== route.endpointId)), { version: 2, controllerId: session.controllerId, controllerName: session.controllerName, route: { ...route, accessCeiling: { level, tabIds: [], domains } }, createdAt: existing?.createdAt ?? Date.now() }];
}

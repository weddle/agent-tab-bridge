export const SESSION_ACCESS_LEVELS = ["selectedTabs", "domains", "full"] as const;
export type SessionAccessLevel = (typeof SESSION_ACCESS_LEVELS)[number];
export type SessionAccess = Readonly<{ level: SessionAccessLevel; tabIds: readonly number[]; domains: readonly string[] }>;
export type SessionAccessUpgradeKind = "tabs" | "domains" | "full";
export type SessionAccessDelta = Readonly<{ kind: SessionAccessUpgradeKind; tabIds: readonly number[]; domains: readonly string[] }>;

export const MAX_ACCESS_TAB_IDS = 64;
export const MAX_ACCESS_DOMAINS = 64;

function normalizedTabIds(values: readonly number[]): number[] {
  if (values.length > MAX_ACCESS_TAB_IDS || values.some((value) => !Number.isInteger(value) || value < 0)) {
    throw new Error(`tab IDs must be non-negative integers (maximum ${MAX_ACCESS_TAB_IDS})`);
  }
  return [...new Set(values)].sort((left, right) => left - right);
}

export function normalizeDomain(value: string): string {
  const raw = value.trim().toLowerCase().replace(/^\*\./, "").replace(/\.$/, "");
  if (!raw || raw.length > 253 || raw.includes("/") || raw.includes(":")) throw new Error(`invalid domain: ${value}`);
  let hostname: string;
  try { hostname = new URL(`https://${raw}`).hostname.toLowerCase().replace(/\.$/, ""); }
  catch { throw new Error(`invalid domain: ${value}`); }
  if (hostname !== raw || !/^[a-z0-9.-]+$/.test(hostname) || hostname.split(".").some((part) => !part || part.length > 63 || part.startsWith("-") || part.endsWith("-"))) {
    throw new Error(`invalid domain: ${value}`);
  }
  return hostname;
}

function normalizedDomains(values: readonly string[]): string[] {
  if (values.length > MAX_ACCESS_DOMAINS) throw new Error(`too many domains (maximum ${MAX_ACCESS_DOMAINS})`);
  return [...new Set(values.map(normalizeDomain))].sort();
}

export function normalizeSessionAccess(value: { level?: unknown; tabIds?: unknown; domains?: unknown } | undefined): SessionAccess {
  if (value?.tabIds !== undefined && !Array.isArray(value.tabIds)) throw new Error("session access tabIds must be an array");
  if (value?.domains !== undefined && !Array.isArray(value.domains)) throw new Error("session access domains must be an array");
  const level = value?.level ?? "selectedTabs";
  if (!SESSION_ACCESS_LEVELS.includes(level as SessionAccessLevel)) throw new Error("invalid session access level");
  const tabIds = normalizedTabIds(Array.isArray(value?.tabIds) ? value.tabIds as number[] : []);
  const domains = normalizedDomains(Array.isArray(value?.domains) ? value.domains as string[] : []);
  if (level === "selectedTabs" && domains.length) throw new Error("selected-tab access cannot include domains");
  if (level === "domains" && domains.length === 0) throw new Error("domain access requires at least one domain");
  if (level === "full" && (tabIds.length || domains.length)) throw new Error("full access cannot include tab or domain restrictions");
  return { level: level as SessionAccessLevel, tabIds, domains };
}

export function isSessionAccess(value: unknown): value is SessionAccess {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  if (Object.keys(record).length !== 3 || !Object.hasOwn(record, "level") || !Object.hasOwn(record, "tabIds") || !Object.hasOwn(record, "domains")) return false;
  try {
    const normalized = normalizeSessionAccess(record);
    return JSON.stringify(normalized) === JSON.stringify(value);
  } catch { return false; }
}

export function sameSessionAccess(left: SessionAccess, right: SessionAccess): boolean {
  return left.level === right.level && left.tabIds.length === right.tabIds.length && left.domains.length === right.domains.length && left.tabIds.every((value, index) => value === right.tabIds[index]) && left.domains.every((value, index) => value === right.domains[index]);
}

export function normalizeSessionAccessDelta(value: { kind?: unknown; tabIds?: unknown; domains?: unknown }): SessionAccessDelta {
  if (!value || (value.kind !== "tabs" && value.kind !== "domains" && value.kind !== "full")) throw new Error("invalid access upgrade kind");
  if (!Array.isArray(value.tabIds) || !Array.isArray(value.domains)) throw new Error("access upgrade lists are required");
  const tabIds = normalizedTabIds(value.tabIds as number[]);
  const domains = normalizedDomains(value.domains as string[]);
  if (value.kind === "tabs" && (tabIds.length === 0 || domains.length !== 0)) throw new Error("tab access upgrade requires tab IDs only");
  if (value.kind === "domains" && (domains.length === 0 || tabIds.length !== 0)) throw new Error("domain access upgrade requires domains only");
  if (value.kind === "full" && (tabIds.length !== 0 || domains.length !== 0)) throw new Error("full access upgrade cannot include restrictions");
  return { kind: value.kind, tabIds, domains };
}

export function isSessionAccessDelta(value: unknown): value is SessionAccessDelta {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  if (Object.keys(record).length !== 3 || !Object.hasOwn(record, "kind") || !Object.hasOwn(record, "tabIds") || !Object.hasOwn(record, "domains")) return false;
  try { return JSON.stringify(normalizeSessionAccessDelta(record)) === JSON.stringify(value); }
  catch { return false; }
}

export function upgradeSessionAccess(current: SessionAccess, deltaValue: SessionAccessDelta): SessionAccess {
  const delta = normalizeSessionAccessDelta(deltaValue);
  if (current.level === "full") throw new Error("session already has full access");
  if (delta.kind === "full") return { level: "full", tabIds: [], domains: [] };
  const tabIds = delta.kind === "tabs" ? [...current.tabIds, ...delta.tabIds] : [...current.tabIds];
  const domains = delta.kind === "domains" ? [...current.domains, ...delta.domains] : [...current.domains];
  const level = domains.length ? "domains" : "selectedTabs";
  const upgraded = normalizeSessionAccess({ level, tabIds, domains });
  if (sameSessionAccess(current, upgraded)) throw new Error("access upgrade does not add authority");
  return upgraded;
}

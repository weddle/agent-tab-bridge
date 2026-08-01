import { chmod, mkdir, open, readFile, rename, rm } from "node:fs/promises";
import { createHash, createPublicKey, randomBytes } from "node:crypto";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { validateSessionRecord, type SessionRecord } from "./native-protocol.js";
import { localRouteProvenance, type EndpointIdentity, type MachineIdentity } from "./endpoint-contracts.js";

export const APPLICATION_SUPPORT_NAME = "Agent Tab Bridge";
export const STATE_VERSION = 2 as const;
const LEGACY_STATE_VERSION = 1 as const;
export interface ApplicationSupportOptions { directory?: string; appName?: string; }
function validComponent(component: string): boolean { return component.length > 0 && component !== "." && component !== ".." && !component.includes("/") && !component.includes("\\") && !component.includes("\0"); }
export function applicationSupportDirectory(options: ApplicationSupportOptions = {}): string {
  const appName = options.appName ?? APPLICATION_SUPPORT_NAME;
  if (!validComponent(appName)) throw new TypeError("invalid application support name");
  return options.directory ? resolve(options.directory) : join(homedir(), "Library", "Application Support", appName);
}
export async function ensureApplicationSupportDirectory(options: ApplicationSupportOptions = {}): Promise<string> { const directory = applicationSupportDirectory(options); await mkdir(directory, { recursive: true, mode: 0o700 }); await chmod(directory, 0o700); return directory; }
export function applicationSupportPath(fileName: string, options: ApplicationSupportOptions = {}): string { if (!validComponent(fileName) || !fileName.endsWith(".json")) throw new TypeError("invalid application support file name"); return join(applicationSupportDirectory(options), fileName); }
export async function readPrivateJson<T>(filePath: string): Promise<T | undefined> { try { const value = JSON.parse(await readFile(filePath, "utf8")) as unknown; await chmod(filePath, 0o600); return value as T; } catch (error) { if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined; throw error; } }
export async function atomicWritePrivateJson(filePath: string, value: unknown): Promise<void> {
  if (!filePath.startsWith("/") || filePath.split(/[\\/]/).includes("..")) throw new TypeError("private file path must be absolute and traversal-free");
  const parent = dirname(filePath); await mkdir(parent, { recursive: true, mode: 0o700 }); await chmod(parent, 0o700);
  const base = filePath.slice(parent.length + 1); if (!validComponent(base)) throw new TypeError("invalid private file path");
  const temp = join(parent, `.${base}.${randomBytes(12).toString("hex")}.tmp`); const handle = await open(temp, "wx", 0o600);
  try { await handle.writeFile(JSON.stringify(value) + "\n", "utf8"); await handle.sync(); } finally { await handle.close(); }
  await chmod(temp, 0o600); try { await rename(temp, filePath); } catch (error) { await rm(temp, { force: true }); throw error; } await chmod(filePath, 0o600); const directoryHandle = await open(parent, "r"); try { await directoryHandle.sync(); } finally { await directoryHandle.close(); }
}

/** Input from the extension handshake. `label` is optional only for legacy callers. */
export interface PinnedExtensionIdentity { extensionId: string; publicKeySpki: string; fingerprint: string; pinnedAt: number; label?: string; }
export interface EnrolledProfile { name: string; principalId: string; publicKeySpki: string; enrolledAt: number; }
export interface EndpointGroupRecord { id: string; createdAt: number; }
export interface EndpointState { identity: EndpointIdentity; sessions: SessionRecord[]; groups: EndpointGroupRecord[]; }
export interface MachineState { identity: MachineIdentity; brokerSecret: string; enrollments: EnrolledProfile[]; }
/** Machine trust is not co-located with browser-profile authority. */
export interface CompanionState { version: typeof STATE_VERSION; machine: MachineState; endpoints: EndpointState[]; }
export interface CompanionStateStatus {
  version: typeof STATE_VERSION;
  machineId: string;
  endpoints: Array<{ endpointId: string; extensionId: string; extensionFingerprint: string; label: string; pinnedAt: number; publicKeySpkiFingerprint: string; sessions: SessionRecord[]; groups: EndpointGroupRecord[] }>;
  hasBrokerSecret: boolean;
}
type LegacyState = { version: typeof LEGACY_STATE_VERSION; companionPrincipalId: string; pinnedExtensions: Array<{ extensionId: string; publicKeySpki: string; fingerprint: string; pinnedAt: number }>; sessions: Array<Omit<SessionRecord, "route">>; brokerSecret: string; enrolledProfiles?: EnrolledProfile[]; };

function extensionFingerprint(publicKeySpki: string): string | undefined { try { const key = createPublicKey({ key: Buffer.from(publicKeySpki, "base64url"), format: "der", type: "spki" }); const der = key.export({ type: "spki", format: "der" }); return `sha256/${createHash("sha256").update(der).digest("base64")}`; } catch { return undefined; } }
function validFingerprint(value: unknown): value is string { return typeof value === "string" && /^sha256\/[A-Za-z0-9+/=_-]+$/.test(value) && value.length <= 256; }
function validEnrolledProfile(value: unknown): value is EnrolledProfile {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false; const profile = value as Record<string, unknown>;
  return typeof profile.name === "string" && /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(profile.name) && validFingerprint(profile.principalId) && typeof profile.publicKeySpki === "string" && profile.publicKeySpki.length > 0 && Number.isInteger(profile.enrolledAt);
}
function validEndpointIdentity(value: unknown): value is EndpointIdentity {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const identity = value as Record<string, unknown>;
  const fingerprint = typeof identity.publicKeySpki === "string" ? extensionFingerprint(identity.publicKeySpki) : undefined;
  return typeof identity.extensionId === "string" && identity.extensionId.length > 0 && identity.extensionId.length <= 256 && typeof identity.publicKeySpki === "string" && identity.publicKeySpki.length > 0 && validFingerprint(identity.endpointId) && identity.endpointId === fingerprint && identity.extensionFingerprint === fingerprint && typeof identity.label === "string" && identity.label.length > 0 && identity.label.length <= 128 && Number.isInteger(identity.pinnedAt);
}
function validEndpointState(value: unknown): value is EndpointState {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const endpoint = value as Record<string, unknown>;
  return validEndpointIdentity(endpoint.identity) && Array.isArray(endpoint.sessions) && endpoint.sessions.every(validateSessionRecord) && Array.isArray(endpoint.groups) && endpoint.groups.every((group) => !!group && typeof group === "object" && !Array.isArray(group) && typeof (group as Record<string, unknown>).id === "string" && Number.isInteger((group as Record<string, unknown>).createdAt));
}
function validState(value: unknown): value is CompanionState {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const state = value as Record<string, unknown>;
  if (state.version !== STATE_VERSION || !state.machine || typeof state.machine !== "object" || Array.isArray(state.machine) || !Array.isArray(state.endpoints)) return false;
  const machine = state.machine as Record<string, unknown>;
  return !!machine.identity && typeof machine.identity === "object" && !Array.isArray(machine.identity) && validFingerprint((machine.identity as Record<string, unknown>).machineId) && typeof machine.brokerSecret === "string" && Array.isArray(machine.enrollments) && machine.enrollments.every(validEnrolledProfile) && state.endpoints.every(validEndpointState) && new Set(state.endpoints.map((endpoint) => endpoint.identity.endpointId)).size === state.endpoints.length;
}
function validLegacyState(value: unknown): value is LegacyState {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const state = value as Record<string, unknown>;
  if (state.version !== LEGACY_STATE_VERSION || typeof state.companionPrincipalId !== "string" || state.companionPrincipalId.length > 256 || !Array.isArray(state.pinnedExtensions) || !Array.isArray(state.sessions) || typeof state.brokerSecret !== "string" || (state.enrolledProfiles !== undefined && (!Array.isArray(state.enrolledProfiles) || !state.enrolledProfiles.every(validEnrolledProfile)))) return false;
  return state.pinnedExtensions.every((item) => !!item && typeof item === "object" && !Array.isArray(item) && typeof (item as Record<string, unknown>).extensionId === "string" && typeof (item as Record<string, unknown>).publicKeySpki === "string" && extensionFingerprint((item as Record<string, unknown>).publicKeySpki as string) === (item as Record<string, unknown>).fingerprint && Number.isInteger((item as Record<string, unknown>).pinnedAt));
}
function emptyState(): CompanionState { return { version: STATE_VERSION, machine: { identity: { machineId: "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" }, brokerSecret: "", enrollments: [] }, endpoints: [] }; }
function migrateLegacyState(legacy: LegacyState): CompanionState {
  if (legacy.sessions.length > 0 && legacy.pinnedExtensions.length !== 1) throw new Error("cannot safely assign legacy sessions to an endpoint");
  const machineId = validFingerprint(legacy.companionPrincipalId) ? legacy.companionPrincipalId : "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  return {
    version: STATE_VERSION,
    machine: { identity: { machineId }, brokerSecret: legacy.brokerSecret, enrollments: legacy.enrolledProfiles ?? [] },
    endpoints: legacy.pinnedExtensions.map((identity, index) => ({
      identity: { endpointId: identity.fingerprint, extensionId: identity.extensionId, extensionFingerprint: identity.fingerprint, publicKeySpki: identity.publicKeySpki, label: identity.extensionId, pinnedAt: identity.pinnedAt },
      sessions: index === 0 ? legacy.sessions.map((session) => ({ ...session, route: localRouteProvenance(identity.fingerprint, session.controllerPrincipalId, session.access) })) : [],
      groups: [],
    })),
  };
}

export class CompanionStateStore {
  readonly filePath: string;
  private state: CompanionState | undefined;
  private writeTail = Promise.resolve();
  constructor(options: ApplicationSupportOptions & { fileName?: string } = {}) { this.filePath = applicationSupportPath(options.fileName ?? "state.json", options); }
  async load(): Promise<CompanionState> {
    if (this.state) return structuredClone(this.state);
    const value = await readPrivateJson<unknown>(this.filePath);
    if (value === undefined) this.state = emptyState();
    else if (validState(value)) this.state = structuredClone(value);
    else if (validLegacyState(value)) { this.state = migrateLegacyState(value); await atomicWritePrivateJson(this.filePath, this.state); }
    else throw new Error("invalid companion state");
    return structuredClone(this.state);
  }
  private async write<T>(operation: () => Promise<T>): Promise<T> {
    const next = this.writeTail.then(operation);
    this.writeTail = next.then(() => undefined, () => undefined);
    return await next;
  }
  async save(state: CompanionState): Promise<void> {
    await this.write(async () => {
      if (!validState(state)) throw new TypeError("invalid companion state");
      await atomicWritePrivateJson(this.filePath, state);
      this.state = structuredClone(state);
    });
  }
  async update(mutator: (state: CompanionState) => CompanionState | Promise<CompanionState>): Promise<CompanionState> {
    return await this.write(async () => {
      const next = await mutator(await this.load());
      if (!validState(next)) throw new TypeError("invalid companion state");
      await atomicWritePrivateJson(this.filePath, next);
      this.state = structuredClone(next);
      return structuredClone(next);
    });
  }
  async initializeMachine(machineId: string, brokerSecret: string): Promise<CompanionState> {
    if (!validFingerprint(machineId) || !brokerSecret) throw new TypeError("invalid machine identity");
    return await this.update((current) => ({ ...current, machine: { ...current.machine, identity: { machineId }, brokerSecret: current.machine.brokerSecret || brokerSecret } }));
  }
  async pinExtension(identity: PinnedExtensionIdentity): Promise<EndpointIdentity> {
    const fingerprint = extensionFingerprint(identity.publicKeySpki);
    if (!fingerprint || fingerprint !== identity.fingerprint || !identity.extensionId || !Number.isInteger(identity.pinnedAt)) throw new TypeError("invalid pinned extension identity");
    let endpoint: EndpointIdentity | undefined;
    await this.update((current) => {
      const existing = current.endpoints.find((item) => item.identity.extensionId === identity.extensionId && item.identity.endpointId === fingerprint);
      if (existing) {
        endpoint = existing.identity;
        return current;
      }
      endpoint = { endpointId: fingerprint, extensionId: identity.extensionId, extensionFingerprint: fingerprint, publicKeySpki: identity.publicKeySpki, label: identity.label?.trim() || identity.extensionId, pinnedAt: identity.pinnedAt };
      return { ...current, endpoints: [...current.endpoints, { identity: endpoint, sessions: [], groups: [] }] };
    });
    return structuredClone(endpoint!);
  }
  async unpinExtension(extensionId: string, fingerprint?: string): Promise<boolean> {
    let changed = false;
    await this.update((current) => {
      const endpoints = current.endpoints.filter((endpoint) => endpoint.identity.extensionId !== extensionId || (fingerprint !== undefined && endpoint.identity.endpointId !== fingerprint));
      changed = endpoints.length !== current.endpoints.length;
      return changed ? { ...current, endpoints } : current;
    });
    return changed;
  }
  async status(): Promise<CompanionStateStatus> {
    const state = await this.load();
    return { version: STATE_VERSION, machineId: state.machine.identity.machineId, endpoints: state.endpoints.map((endpoint) => ({ endpointId: endpoint.identity.endpointId, extensionId: endpoint.identity.extensionId, extensionFingerprint: endpoint.identity.extensionFingerprint, label: endpoint.identity.label, pinnedAt: endpoint.identity.pinnedAt, publicKeySpkiFingerprint: extensionFingerprint(endpoint.identity.publicKeySpki)!, sessions: structuredClone(endpoint.sessions), groups: structuredClone(endpoint.groups) })), hasBrokerSecret: state.machine.brokerSecret.length > 0 };
  }
}

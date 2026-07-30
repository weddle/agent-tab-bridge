import { chmod, mkdir, open, readFile, rename, rm } from "node:fs/promises";
import { createHash, createPublicKey, randomBytes } from "node:crypto";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { validateSessionRecord, type SessionRecord } from "./native-protocol.js";

export const APPLICATION_SUPPORT_NAME = "Agent Tab Bridge";
export const STATE_VERSION = 1 as const;
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
export interface PinnedExtensionIdentity { extensionId: string; publicKeySpki: string; fingerprint: string; pinnedAt: number; }
export interface CompanionState { version: typeof STATE_VERSION; companionPrincipalId: string; pinnedExtensions: PinnedExtensionIdentity[]; sessions: SessionRecord[]; brokerSecret: string; }
export interface CompanionStateStatus { version: typeof STATE_VERSION; companionPrincipalId: string; pinnedExtensions: Array<Omit<PinnedExtensionIdentity, "publicKeySpki"> & { publicKeySpkiFingerprint: string }>; sessions: SessionRecord[]; hasBrokerSecret: boolean; }
function extensionFingerprint(publicKeySpki: string): string | undefined { try { const key = createPublicKey({ key: Buffer.from(publicKeySpki, "base64url"), format: "der", type: "spki" }); const der = key.export({ type: "spki", format: "der" }); return `sha256/${createHash("sha256").update(der).digest("base64")}`; } catch { return undefined; } }

function emptyState(): CompanionState { return { version: STATE_VERSION, companionPrincipalId: "", pinnedExtensions: [], sessions: [], brokerSecret: "" }; }
function validState(value: unknown): value is CompanionState {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false; const state = value as Record<string, unknown>;
  return state.version === STATE_VERSION && typeof state.companionPrincipalId === "string" && state.companionPrincipalId.length <= 256 && Array.isArray(state.pinnedExtensions) && state.pinnedExtensions.every((item) => { if (!item || typeof item !== "object" || Array.isArray(item)) return false; const identity = item as Record<string, unknown>; const fingerprint = typeof identity.publicKeySpki === "string" ? extensionFingerprint(identity.publicKeySpki) : undefined; return typeof identity.extensionId === "string" && identity.extensionId.length <= 256 && typeof identity.publicKeySpki === "string" && identity.publicKeySpki.length > 0 && fingerprint !== undefined && identity.fingerprint === fingerprint && Number.isInteger(identity.pinnedAt); }) && Array.isArray(state.sessions) && state.sessions.every(validateSessionRecord) && typeof state.brokerSecret === "string" && state.brokerSecret.length <= 256;
}
export class CompanionStateStore {
  readonly filePath: string; private state: CompanionState | undefined;
  constructor(options: ApplicationSupportOptions & { fileName?: string } = {}) { this.filePath = applicationSupportPath(options.fileName ?? "state.json", options); }
  async load(): Promise<CompanionState> { if (this.state) return structuredClone(this.state); const value = await readPrivateJson<unknown>(this.filePath); if (value === undefined) this.state = emptyState(); else if (!validState(value)) throw new Error("invalid companion state"); else this.state = structuredClone(value); return structuredClone(this.state); }
  async save(state: CompanionState): Promise<void> { if (!validState(state)) throw new TypeError("invalid companion state"); await atomicWritePrivateJson(this.filePath, state); this.state = structuredClone(state); }
  async update(mutator: (state: CompanionState) => CompanionState | Promise<CompanionState>): Promise<CompanionState> { const next = await mutator(await this.load()); await this.save(next); return structuredClone(next); }
  async pinExtension(identity: PinnedExtensionIdentity): Promise<PinnedExtensionIdentity> { const fingerprint = extensionFingerprint(identity.publicKeySpki); if (!fingerprint || fingerprint !== identity.fingerprint) throw new TypeError("invalid pinned extension identity"); const current = await this.load(); const existing = current.pinnedExtensions.find((item) => item.extensionId === identity.extensionId && item.fingerprint === fingerprint); if (!existing) current.pinnedExtensions.push(structuredClone({ ...identity, fingerprint })); await this.save(current); return structuredClone(existing ?? identity); }
  async unpinExtension(extensionId: string, fingerprint?: string): Promise<boolean> { const current = await this.load(); const before = current.pinnedExtensions.length; current.pinnedExtensions = current.pinnedExtensions.filter((item) => item.extensionId !== extensionId || (fingerprint !== undefined && item.fingerprint !== fingerprint)); if (current.pinnedExtensions.length === before) return false; await this.save(current); return true; }
  async status(): Promise<CompanionStateStatus> { const state = await this.load(); return { version: STATE_VERSION, companionPrincipalId: state.companionPrincipalId, pinnedExtensions: state.pinnedExtensions.map(({ publicKeySpki, ...identity }) => ({ ...identity, publicKeySpkiFingerprint: extensionFingerprint(publicKeySpki)! })), sessions: structuredClone(state.sessions), hasBrokerSecret: state.brokerSecret.length > 0 }; }
}

import { readdir } from "node:fs/promises";
import { join } from "node:path";
import { createHandshakeNonce, fingerprintSpki, generateIdentity, signTranscript, verifyTranscript } from "./identity.js";
import { applicationSupportDirectory, atomicWritePrivateJson, readPrivateJson, type ApplicationSupportOptions } from "./state.js";

const PROFILE_RECORD_VERSION = 1 as const;

/**
 * A named controller keypair stored as a plain file in the state directory.
 * Profiles give each agent harness its own broker principal so approvals and
 * standing policy can bind to a key the user saw and named, instead of one
 * shared same-user secret. Files are user-only (0600); this is deliberately
 * portable storage - no macOS Keychain - and is not yet a boundary against
 * other processes running as the same user.
 */
export interface ControllerProfile {
  version: typeof PROFILE_RECORD_VERSION;
  name: string;
  principalId: string;
  publicKeySpki: string;
  privateKeyPkcs8: string;
  createdAt: number;
}

export const PROFILE_NAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

export function assertProfileName(name: string): string {
  if (!PROFILE_NAME_PATTERN.test(name)) throw new Error("profile name must be 1-64 characters of letters, digits, dot, underscore, or hyphen, starting with a letter or digit");
  return name;
}

export function profilesDirectory(options: ApplicationSupportOptions = {}): string {
  return join(applicationSupportDirectory(options), "profiles");
}

function profilePath(name: string, options: ApplicationSupportOptions = {}): string {
  return join(profilesDirectory(options), `${assertProfileName(name)}.json`);
}

function keyPairUsable(record: ControllerProfile): boolean {
  try {
    const probe = Buffer.from(`atb-profile-probe\u0000${record.name}`, "utf8");
    return verifyTranscript(record.publicKeySpki, probe, signTranscript(record.privateKeyPkcs8, probe));
  } catch {
    return false;
  }
}

function validProfile(value: unknown, name: string): value is ControllerProfile {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  return record.version === PROFILE_RECORD_VERSION
    && record.name === name
    && typeof record.principalId === "string"
    && typeof record.publicKeySpki === "string"
    && typeof record.privateKeyPkcs8 === "string"
    && typeof record.createdAt === "number";
}

export async function createProfile(name: string, options: ApplicationSupportOptions = {}): Promise<ControllerProfile> {
  const filePath = profilePath(name, options);
  if (await readPrivateJson<unknown>(filePath) !== undefined) throw new Error(`profile already exists: ${name}`);
  const generated = generateIdentity("controller");
  const record: ControllerProfile = {
    version: PROFILE_RECORD_VERSION,
    name,
    principalId: generated.principalId,
    publicKeySpki: generated.publicKeySpki,
    privateKeyPkcs8: generated.privateKeyPkcs8,
    createdAt: Date.now(),
  };
  await atomicWritePrivateJson(filePath, record);
  return record;
}

export async function loadProfile(name: string, options: ApplicationSupportOptions = {}): Promise<ControllerProfile> {
  const value = await readPrivateJson<unknown>(profilePath(name, options));
  if (value === undefined) throw new Error(`profile not found: ${name} (run: atb profile create ${name})`);
  if (!validProfile(value, name) || fingerprintSpki(value.publicKeySpki) !== value.principalId || !keyPairUsable(value)) throw new Error(`invalid profile record: ${name}`);
  return value;
}

export async function listProfiles(options: ApplicationSupportOptions = {}): Promise<Array<Pick<ControllerProfile, "name" | "principalId" | "createdAt">>> {
  let entries: string[];
  try {
    entries = await readdir(profilesDirectory(options));
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
    throw error;
  }
  const profiles: Array<Pick<ControllerProfile, "name" | "principalId" | "createdAt">> = [];
  for (const entry of entries.sort()) {
    if (!entry.endsWith(".json")) continue;
    const name = entry.slice(0, -".json".length);
    if (!PROFILE_NAME_PATTERN.test(name)) continue;
    try {
      const { principalId, createdAt } = await loadProfile(name, options);
      profiles.push({ name, principalId, createdAt });
    } catch {
      // Skip unreadable or invalid records; `loadProfile` reports them when addressed directly.
    }
  }
  return profiles;
}

/** Canonical bytes signed by a profile to answer a broker auth challenge. */
export function profileAuthTranscript(nonce: string, profileName: string): Uint8Array {
  return Buffer.from(`atb-broker-profile-auth\u0000${nonce}\u0000${profileName}`, "utf8");
}

export function createProfileAuthNonce(): string {
  return createHandshakeNonce();
}

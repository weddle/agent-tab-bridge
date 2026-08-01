import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { generateIdentity, signTranscript, verifyTranscript } from "./identity.js";
import { canonicalAuthV2Transcript } from "./auth-v2.js";
import { createProfile, listProfiles, loadProfile } from "./profiles.js";

const directories: string[] = [];
afterEach(async () => { await Promise.all(directories.splice(0).map(async (directory) => await rm(directory, { recursive: true, force: true }))); });

describe("controller profiles", () => {
  it("creates, lists, and reloads named keypairs and rejects duplicates and bad names", async () => {
    const directory = await mkdtemp(join(tmpdir(), "atb-profiles-")); directories.push(directory);
    const created = await createProfile("hermes-research", { directory });
    expect(created.principalId).toMatch(/^sha256\//);
    await expect(createProfile("hermes-research", { directory })).rejects.toThrow(/already exists/);
    await expect(createProfile("bad/name", { directory })).rejects.toThrow(/profile name/);
    const loaded = await loadProfile("hermes-research", { directory });
    expect(loaded).toEqual(created);
    await expect(loadProfile("missing", { directory })).rejects.toThrow(/profile not found/);
    const listed = await listProfiles({ directory });
    expect(listed).toEqual([{ name: "hermes-research", principalId: created.principalId, createdAt: created.createdAt }]);
    expect(await listProfiles({ directory: join(directory, "nowhere") })).toEqual([]);
  });

  it("signs v2 auth transcripts with a profile static key", async () => {
    const directory = await mkdtemp(join(tmpdir(), "atb-profiles-")); directories.push(directory);
    const profile = await createProfile("omp", { directory });
    const edge = generateIdentity("companion");
    const transcript = { protocolVersion: 2, cipherSuite: "P-256/SHA-256", controller: { principalId: profile.principalId, publicKeySpki: profile.publicKeySpki, role: "controller" as const }, edge: { machineId: edge.principalId, principalId: edge.principalId, publicKeySpki: edge.publicKeySpki, role: "edge" as const }, endpointId: edge.principalId, controllerEphemeralPublicKey: generateIdentity("controller").publicKeySpki, edgeEphemeralPublicKey: generateIdentity("controller").publicKeySpki, controllerNonce: Buffer.alloc(32, 1).toString("base64url"), edgeNonce: Buffer.alloc(32, 2).toString("base64url"), authority: { scope: null, ttlMs: null, stableSessionKey: null }, expiresAt: Date.now() + 60_000, hubId: null, routeId: null, streamId: null } as const;
    const signature = signTranscript(profile.privateKeyPkcs8, canonicalAuthV2Transcript(transcript));
    expect(verifyTranscript(profile.publicKeySpki, canonicalAuthV2Transcript(transcript), signature)).toBe(true);
    expect(verifyTranscript(profile.publicKeySpki, canonicalAuthV2Transcript({ ...transcript, endpointId: profile.principalId }), signature)).toBe(false);
  });
});

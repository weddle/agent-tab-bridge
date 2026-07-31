import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { signTranscript, verifyTranscript } from "./identity.js";
import { createProfile, listProfiles, loadProfile, profileAuthTranscript } from "./profiles.js";

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

  it("binds auth transcripts to the nonce and profile name", async () => {
    const directory = await mkdtemp(join(tmpdir(), "atb-profiles-")); directories.push(directory);
    const profile = await createProfile("omp", { directory });
    const signature = signTranscript(profile.privateKeyPkcs8, profileAuthTranscript("nonce-1", "omp"));
    expect(verifyTranscript(profile.publicKeySpki, profileAuthTranscript("nonce-1", "omp"), signature)).toBe(true);
    expect(verifyTranscript(profile.publicKeySpki, profileAuthTranscript("nonce-2", "omp"), signature)).toBe(false);
    expect(verifyTranscript(profile.publicKeySpki, profileAuthTranscript("nonce-1", "other"), signature)).toBe(false);
  });
});

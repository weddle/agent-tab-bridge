import { mkdtemp, readFile, stat, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { describe, expect, it } from "vitest";
import { CompanionStateStore, applicationSupportPath, ensureApplicationSupportDirectory } from "./state.js";
import { createBrokerSecret, deriveControllerPrincipalId, fingerprintSpki, generateIdentity, HostIdentityHandshake, IdentityStore, signHandshakeTranscript, verifyHandshakeTranscript } from "./identity.js";
import { NATIVE_PROTOCOL_VERSION } from "./native-protocol.js";

describe("companion identities and private state", () => {
  it("creates P-256 identities and rejects transcript/key substitution", () => {
    const extension = generateIdentity("controller");
    const companion = generateIdentity("companion");
    const fields = { extensionId: "extension", extensionPublicKey: extension.publicKeySpki, extensionNonce: Buffer.alloc(32, 1).toString("base64url"), companionId: companion.principalId, companionPublicKey: companion.publicKeySpki, companionNonce: Buffer.alloc(32, 2).toString("base64url") };
    const signature = signHandshakeTranscript(extension.privateKeyPkcs8, fields);
    expect(verifyHandshakeTranscript(extension.publicKeySpki, fields, signature)).toBe(true);
    expect(verifyHandshakeTranscript(companion.publicKeySpki, fields, signature)).toBe(false);
    expect(verifyHandshakeTranscript(extension.publicKeySpki, { ...fields, companionNonce: Buffer.alloc(32, 3).toString("base64url") }, signature)).toBe(false);
    expect(fingerprintSpki(extension.publicKeySpki)).toBe(extension.fingerprint);
    expect(() => createBrokerSecret(16)).toThrow();
  });

  it("persists restrictive modes and pins profile fingerprints", async () => {
    const root = await mkdtemp(join(tmpdir(), "atb-identity-"));
    try {
      const directory = await ensureApplicationSupportDirectory({ directory: root });
      expect((await stat(directory)).mode & 0o777).toBe(0o700);
      const identities = new IdentityStore("companion", { directory: root });
      const first = await identities.loadOrCreate();
      expect(await identities.load()).toEqual(first);
      expect((await stat(identities.filePath)).mode & 0o777).toBe(0o600);
      const state = new CompanionStateStore({ directory: root });
      await state.initializeMachine(first.principalId, createBrokerSecret());
      const extension = generateIdentity("controller");
      await state.pinExtension({ extensionId: "extension", publicKeySpki: extension.publicKeySpki, fingerprint: extension.fingerprint, pinnedAt: Date.now(), label: "Brave" });
      const secondExtension = generateIdentity("controller");
      await state.pinExtension({ extensionId: "extension", publicKeySpki: secondExtension.publicKeySpki, fingerprint: secondExtension.fingerprint, pinnedAt: Date.now(), label: "Chrome" });
      const status = await state.status();
      expect(status.machineId).toBe(first.principalId);
      expect(status.endpoints).toHaveLength(2);
      expect(status.endpoints.map((endpoint) => endpoint.label)).toEqual(["Brave", "Chrome"]);
      expect(status.hasBrokerSecret).toBe(true);
      expect(JSON.stringify(status)).not.toContain("privateKeyPkcs8");
      expect((await stat(state.filePath)).mode & 0o777).toBe(0o600);
      expect(() => applicationSupportPath("../escape.json", { directory: root })).toThrow();
    } finally { await rm(root, { recursive: true, force: true }); }
  });
  it("migrates legacy machine records into one endpoint-scoped state exactly once", async () => {
    const root = await mkdtemp(join(tmpdir(), "atb-state-migration-"));
    try {
      const machine = generateIdentity("companion");
      const extension = generateIdentity("controller");
      const legacy = { version: 1, companionPrincipalId: machine.principalId, pinnedExtensions: [{ extensionId: "extension", publicKeySpki: extension.publicKeySpki, fingerprint: extension.fingerprint, pinnedAt: 1 }], sessions: [{ id: "session-1", controllerPrincipalId: "sha256/controller", displayControllerName: "Research", taskLabel: "Task", requestedCapabilities: ["cdp"], access: { level: "selectedTabs", tabIds: [], domains: [] }, createdAt: 1, expiresAt: null, state: "pending" }], brokerSecret: createBrokerSecret(), enrolledProfiles: [] };
      const store = new CompanionStateStore({ directory: root });
      await writeFile(store.filePath, JSON.stringify(legacy));
      const migrated = await store.load();
      expect(migrated.machine.identity.machineId).toBe(machine.principalId);
      expect(migrated.endpoints).toHaveLength(1);
      expect(migrated.endpoints[0]?.sessions[0]?.route).toMatchObject({ endpointId: extension.fingerprint, controllerPrincipalId: "sha256/controller", routePolicy: "localOnly", hubId: null, routeId: null, streamId: null });
      expect(JSON.parse(await readFile(store.filePath, "utf8"))).toMatchObject({ version: 2, machine: { identity: { machineId: machine.principalId } } });
      expect(await new CompanionStateStore({ directory: root }).load()).toEqual(migrated);
    } finally { await rm(root, { recursive: true, force: true }); }
  });
  it("fails closed for corrupted key pairs and derives controller identity from broker secret", async () => {
    const root = await mkdtemp(join(tmpdir(), "atb-corrupt-"));
    try {
      const store = new IdentityStore("companion", { directory: root });
      const identity = await store.loadOrCreate();
      await writeFile(store.filePath, JSON.stringify({ ...identity, privateKeyPkcs8: generateIdentity("controller").privateKeyPkcs8 }));
      await expect(new IdentityStore("companion", { directory: root }).load()).rejects.toThrow(/invalid identity/);
      const secret = createBrokerSecret();
      expect(deriveControllerPrincipalId(secret)).toBe(deriveControllerPrincipalId(secret));
      expect(deriveControllerPrincipalId(secret)).not.toBe(deriveControllerPrincipalId(createBrokerSecret()));
    } finally { await rm(root, { recursive: true, force: true }); }
  });
  it("signs the companion challenge before accepting extension proof", async () => {
    const root = await mkdtemp(join(tmpdir(), "atb-handshake-"));
    try {
      const companionStore = new IdentityStore("companion", { directory: root });
      const extension = generateIdentity("controller");
      const handshake = new HostIdentityHandshake(companionStore);
      const hello = { version: NATIVE_PROTOCOL_VERSION, type: "hello" as const, role: "extension" as const, extensionId: "extension", extensionPublicKey: extension.publicKeySpki, extensionNonce: Buffer.alloc(32, 4).toString("base64url") };
      const challenge = await handshake.createChallenge(hello);
      const transcript = { extensionId: hello.extensionId, extensionPublicKey: hello.extensionPublicKey, extensionNonce: hello.extensionNonce, companionId: challenge.companionId, companionPublicKey: challenge.companionPublicKey, companionNonce: challenge.companionNonce };
      expect(verifyHandshakeTranscript(challenge.companionPublicKey, transcript, challenge.signature)).toBe(true);
      const proof = { version: NATIVE_PROTOCOL_VERSION, type: "helloProof" as const, role: "extension" as const, ...transcript, signature: signHandshakeTranscript(extension.privateKeyPkcs8, transcript) };
      await expect(handshake.verifyProof(proof)).resolves.toMatchObject({ extensionId: "extension" });
    } finally { await rm(root, { recursive: true, force: true }); }
  });
});

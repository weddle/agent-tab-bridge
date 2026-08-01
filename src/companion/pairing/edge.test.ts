import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { describe, expect, it } from "vitest";
import { CompanionStateStore } from "../state.js";
import { IdentityStore, generateIdentity, type StoredIdentity } from "../identity.js";
import { HubService } from "../../hub/service.js";
import { EdgeHubPairingClient } from "./edge.js";

function storedIdentity(): StoredIdentity {
  const generated = generateIdentity();
  return { version: 1, kind: "companion", principalId: generated.principalId, publicKeySpki: generated.publicKeySpki, privateKeyPkcs8: generated.privateKeyPkcs8, createdAt: Date.now() };
}

describe("edge hub pairing integration", () => {
  it("pairs over loopback TLS, pushes presence, and unpairs without reconnect", async () => {
    const hubDirectory = await mkdtemp(`${tmpdir()}/atb-edge-hub-`);
    const edgeDirectory = await mkdtemp(`${tmpdir()}/atb-edge-`);
    const hub = new HubService({ identity: storedIdentity(), directory: hubDirectory, port: 0 });
    await hub.start();
    const ceremony = await hub.startPairing();
    const machineIdentity = storedIdentity();
    hub.confirmPairingMachineFingerprint(machineIdentity.principalId);
    const stateStore = new CompanionStateStore({ directory: edgeDirectory });
    await stateStore.initializeMachine(machineIdentity.principalId, "test-broker-secret");
    const edge = new EdgeHubPairingClient({ directory: edgeDirectory, identityStore: { loadOrCreate: async () => machineIdentity } as IdentityStore, stateStore });
    const result = await edge.pair(`127.0.0.1:${hub.address!.port}`, ceremony.code, hub.identity.principalId);
    const endpointKey = storedIdentity();
    await stateStore.pinExtension({ extensionId: "test-extension", publicKeySpki: endpointKey.publicKeySpki, fingerprint: endpointKey.principalId, pinnedAt: Date.now() });
    await edge.store.setEndpointEnabled(endpointKey.principalId, true);
    const port = hub.address!.port;
    const hubIdentity = hub.identity;
    await hub.stop();
    const restarted = new HubService({ identity: hubIdentity, directory: hubDirectory, port });
    await restarted.start();
    const socket = await edge.connectPresence();
    expect(socket).toBeDefined();
    expect((await restarted.status()).machines[0]?.presence).toBe("online");
    expect((await restarted.directory()).map((endpoint) => endpoint.endpointId)).toEqual([endpointKey.principalId]);
    await edge.store.setEndpointEnabled(endpointKey.principalId, false);
    await edge.pushPresence(socket!);
    expect(await restarted.directory()).toEqual([]);
    await restarted.forgetMachine(machineIdentity.principalId);
    expect((await restarted.status()).machines).toEqual([]);
    await edge.unpair();
    expect(await edge.store.load()).toBeUndefined();
    await restarted.stop();
  });
});

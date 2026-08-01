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
    await hub.start(); await hub.startPairing();
    const machineIdentity = storedIdentity();
    const stateStore = new CompanionStateStore({ directory: edgeDirectory });
    await stateStore.initializeMachine(machineIdentity.principalId, "test-broker-secret");
    const edge = new EdgeHubPairingClient({ directory: edgeDirectory, identityStore: { loadOrCreate: async () => machineIdentity } as IdentityStore, stateStore });
    const result = await edge.pair(`127.0.0.1:${hub.address!.port}`);
    const endpointKey = storedIdentity();
    await stateStore.pinExtension({ extensionId: "test-extension", publicKeySpki: endpointKey.publicKeySpki, fingerprint: endpointKey.principalId, pinnedAt: Date.now() });
    await edge.store.setEndpointEnabled(endpointKey.principalId, true);
    expect(result.pairing.pinnedPeerKey.fingerprint).toBe(hub.identity.principalId);
    const socket = await edge.connectPresence();
    expect(socket).toBeDefined();
    expect((await hub.status()).machines[0]?.presence).toBe("online");
    expect((await hub.directory()).map((endpoint) => endpoint.endpointId)).toEqual([endpointKey.principalId]);
    await edge.store.setEndpointEnabled(endpointKey.principalId, false);
    await edge.pushPresence(socket!);
    expect(await hub.directory()).toEqual([]);
    await edge.unpair();
    expect(await edge.store.load()).toBeUndefined();
    await hub.stop();
  });
});

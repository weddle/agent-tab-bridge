import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { describe, expect, it } from "vitest";
import { generateIdentity, type StoredIdentity } from "../companion/identity.js";
import { MachinePairingCeremony } from "../companion/pairing/index.js";
import { HubService } from "./service.js";

function identity(): StoredIdentity {
  const key = generateIdentity();
  return { version: 1, kind: "companion", principalId: key.principalId, publicKeySpki: key.publicKeySpki, privateKeyPkcs8: key.privateKeyPkcs8, createdAt: Date.now() };
}
async function pairedHub(directory: string) {
  const hubIdentity = identity();
  const machineIdentity = identity();
  const hub = new HubService({ identity: hubIdentity, directory, port: 0 });
  const ceremony = await hub.startPairing();
  hub.confirmPairingMachineFingerprint(machineIdentity.principalId);
  const machine = new MachinePairingCeremony({ identity: machineIdentity, invitation: ceremony.invitation, code: ceremony.code, confirmedHubFingerprint: ceremony.invitation.hub.fingerprint });
  const hello = machine.createHello();
  const response = await hub.respondPairing(hello, machineIdentity.principalId);
  const machineResult = machine.complete(response);
  await hub.completePairing(response, machineResult.confirmation, "desk");
  return { hub, machineIdentity, machineResult };
}

describe("hub service core", () => {
  it("is inert without an explicitly configured port", async () => {
    const directory = await mkdtemp(`${tmpdir()}/atb-hub-`);
    const hub = new HubService({ identity: identity(), directory });
    expect(await hub.start()).toBeUndefined();
    expect(hub.listening).toBe(false);
    expect(hub.address).toBeUndefined();
    await hub.stop();
  });

  it("hosts pairing and persists a pinned machine keyset", async () => {
    const directory = await mkdtemp(`${tmpdir()}/atb-hub-`);
    const { hub, machineIdentity, machineResult } = await pairedHub(directory);
    const status = await hub.status();
    expect(status.machines).toHaveLength(1);
    expect(status.machines[0].alias).toBe("desk");
    expect(status.machines[0].pairing.pinnedPeerKey.fingerprint).toBe(machineIdentity.principalId);
    expect(machineResult.pairing.pinnedPeerKey.fingerprint).not.toBe(machineIdentity.principalId);
    await hub.stop();
  });

  it("serves only enabled opaque endpoint records and forgets machine pins", async () => {
    const directory = await mkdtemp(`${tmpdir()}/atb-hub-`);
    const { hub, machineIdentity } = await pairedHub(directory);
    await hub.putEndpoint({ machineId: machineIdentity.principalId, endpointId: "disabled", enabled: false, record: { secret: "opaque" } });
    await hub.putEndpoint({ machineId: machineIdentity.principalId, endpointId: "enabled", enabled: true, record: { secret: "opaque" } });
    expect((await hub.directory()).map((item) => item.endpointId)).toEqual(["enabled"]);
    await hub.forgetMachine(machineIdentity.principalId);
    expect((await hub.status()).machines).toHaveLength(0);
    expect(await hub.directory()).toEqual([]);
    await hub.stop();
  });
});

import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { createConnection } from "node:net";
import { connect, type TLSSocket } from "node:tls";
import { describe, expect, it } from "vitest";
import { createEnrollmentStatement } from "../companion/enrollment-statement.js";
import { createBrokerClient } from "../companion/broker-client.js";
import { startBrokerServer } from "../companion/broker.js";
import { createProfile } from "../companion/profiles.js";
import { HubRouteConnection } from "../companion/pairing/routes.js";
import { TaskSessionManager } from "../companion/task-sessions.js";
import { generateIdentity, type StoredIdentity } from "../companion/identity.js";
import { MachinePairingCeremony, type PinnedPeerKeyset } from "../companion/pairing/index.js";
import { clientTlsOptions, HubService } from "./service.js";
import { HubFrameDecoder, encodeHubFrame } from "./framing.js";
import { decodeOpaqueRoutePayload, encodeHubOpaqueRoute, parseHubOpaqueRoute, type RoutedBrokerAddress } from "./routing.js";

function identity(): StoredIdentity { const key = generateIdentity(); return { version: 1, kind: "companion", principalId: key.principalId, publicKeySpki: key.publicKeySpki, privateKeyPkcs8: key.privateKeyPkcs8, createdAt: Date.now() }; }
async function pair(hub: HubService, machine: StoredIdentity): Promise<PinnedPeerKeyset> {
  const ceremony = await hub.startPairing();
  const peer = new MachinePairingCeremony({ identity: machine, invitation: ceremony.invitation, code: ceremony.code, confirmedHubFingerprint: ceremony.invitation.hub.fingerprint });
  const hello = peer.createHello(); const response = await hub.respondPairing(hello, hello.machine.fingerprint); const result = peer.complete(response);
  await hub.completePairing(response, result.confirmation, machine.principalId); return result.pairing;
}
async function pairedSocket(hub: HubService, pairing: PinnedPeerKeyset, machine: StoredIdentity): Promise<TLSSocket> {
  const address = hub.address!; const tls = clientTlsOptions(pairing, machine, hub.serverCertificatePem);
  return await new Promise<TLSSocket>((resolve, reject) => { const socket = connect({ ...tls, host: "127.0.0.1", port: address.port }); socket.once("secureConnect", () => resolve(socket)); socket.once("error", reject); });
}
async function nextFrame(socket: TLSSocket): Promise<Buffer> {
  return await new Promise<Buffer>((resolve, reject) => {
    const decoder = new HubFrameDecoder();
    const onData = (chunk: Buffer) => { try { const frames = decoder.feed(chunk); if (!frames.length) return; socket.off("data", onData); resolve(frames[0]!); } catch (error) { reject(error); } };
    socket.on("data", onData); socket.once("error", reject);
  });
}

describe("hub opaque route control plane", () => {
  it("routes only addressed opaque bytes between paired live machines", async () => {
    const directory = await mkdtemp(`${tmpdir()}/atb-route-`); const hub = new HubService({ identity: identity(), directory, port: 0 });
    const sourceIdentity = identity(), targetIdentity = identity();
    const sourcePairing = await pair(hub, sourceIdentity), targetPairing = await pair(hub, targetIdentity);
    await hub.start();
    const endpointId = identity().principalId;
    await hub.putEndpoint({ machineId: targetIdentity.principalId, endpointId, enabled: true, record: { opaque: true } });
    const source = await pairedSocket(hub, sourcePairing, sourceIdentity), target = await pairedSocket(hub, targetPairing, targetIdentity);
    try {
      const address: RoutedBrokerAddress = { machineId: targetIdentity.principalId, endpointId, principalId: identity().principalId, stableSessionKey: "research" };
      const request = encodeHubOpaqueRoute({ type: "opaqueRoute", direction: "request", routeId: "route-1", streamId: "stream-1", address, payload: Buffer.from("private broker bytes").toString("base64url") });
      const delivered = nextFrame(target); source.write(encodeHubFrame(request));
      const targetEnvelope = parseHubOpaqueRoute(await delivered)!;
      expect(decodeOpaqueRoutePayload(targetEnvelope).toString()).toBe("private broker bytes");
      const response = encodeHubOpaqueRoute({ ...targetEnvelope, direction: "response", payload: Buffer.from("private response bytes").toString("base64url") });
      const returned = nextFrame(source); target.write(encodeHubFrame(response));

      expect(decodeOpaqueRoutePayload(parseHubOpaqueRoute(await returned)!).toString()).toBe("private response bytes");
    } finally { source.destroy(); target.destroy(); await hub.stop(); }
  });

  it("terminates a remote profile authentication at the addressed edge and leaves it pending", async () => {
    const directory = await mkdtemp(`${tmpdir()}/atb-route-`); const hub = new HubService({ identity: identity(), directory, port: 0 });
    const sourceIdentity = identity(), targetIdentity = identity(), endpoint = identity();
    const sourcePairing = await pair(hub, sourceIdentity), targetPairing = await pair(hub, targetIdentity);
    const profile = await createProfile("remote", { directory });
    const sessions = new TaskSessionManager({ startRelay: async () => ({ pairingUrl: "ws://127.0.0.1/extension#token", cdpUrl: "ws://127.0.0.1/cdp?token=token", close: async () => undefined }) });
    const broker = await startBrokerServer({
      socketPath: `${directory}/target-broker.sock`, token: "a".repeat(32), sessions, isTrusted: () => true, controller: () => null,
      profile: (name) => name === profile.name ? { principalId: profile.principalId, displayName: profile.name, publicKeySpki: profile.publicKeySpki } : null,
      authContext: () => ({ machineId: targetIdentity.principalId, machinePublicKeySpki: targetIdentity.publicKeySpki, machinePrivateKeyPkcs8: targetIdentity.privateKeyPkcs8, endpointId: endpoint.principalId }),
      routeFor: (route, principalId, authority) => ({ kind: "routed", endpointId: route.address.endpointId, controllerPrincipalId: principalId, routePolicy: "routed", accessCeiling: authority.scope!, hubId: route.hubId, routeId: route.routeId, streamId: route.streamId }),
    });
    await hub.start();
    await hub.putEndpoint({ machineId: targetIdentity.principalId, endpointId: endpoint.principalId, enabled: true, record: {} });
    const sourceSocket = await pairedSocket(hub, sourcePairing, sourceIdentity), targetSocket = await pairedSocket(hub, targetPairing, targetIdentity);
    const address: RoutedBrokerAddress = { machineId: targetIdentity.principalId, endpointId: endpoint.principalId, principalId: profile.principalId, stableSessionKey: "remote-key" };
    const sourceRoutes = new HubRouteConnection(sourceSocket, () => {});
    const targetRoutes = new HubRouteConnection(targetSocket, (stream, routedAddress) => {
      const upstream = createConnection(broker.socketPath);
      const close = () => { stream.close(); upstream.destroy(); };
      upstream.once("error", close); upstream.once("close", () => stream.close());
      upstream.on("data", (chunk: Buffer) => { try { stream.send(chunk); } catch { close(); } });
      stream.onClose(close);
      upstream.write(`${JSON.stringify(broker.authorizeRoutedContext({ hubId: hub.identity.principalId, routeId: stream.routeId, streamId: stream.streamId, address: routedAddress }))}\n`);
      stream.onPayload((payload) => upstream.write(payload, (error) => { if (error) close(); }));
    });
    try {
      const stream = sourceRoutes.open(address);
      const client = createBrokerClient({ socketPath: "routed", socketFactory: () => stream.transport, profile: { name: profile.name, principalId: profile.principalId, publicKeySpki: profile.publicKeySpki, privateKeyPkcs8: profile.privateKeyPkcs8 }, route: { hubId: hub.identity.principalId, routeId: stream.routeId, streamId: stream.streamId, address } });
      const opened = await client.request("openSession", { taskLabel: "remote test", requestedCapabilities: ["cdp"], stableSessionKey: "remote-key" }) as { session: { route: { kind: string; hubId: string | null; routeId: string | null } } };
      expect(opened.session.route).toMatchObject({ kind: "routed", hubId: hub.identity.principalId, routeId: stream.routeId });
      expect(sessions.snapshot()[0]!.state).toBe("pending");
      await client.close();
      await new Promise((resolve) => setTimeout(resolve, 20));
      expect(broker.connectionCount).toBe(0);
    } finally { sourceRoutes.close(); targetRoutes.close(); sourceSocket.destroy(); targetSocket.destroy(); await broker.close(); await hub.stop(); }
  });
  it("stores only enrollment statements signed by the paired edge machine", async () => {
    const directory = await mkdtemp(`${tmpdir()}/atb-route-`); const hub = new HubService({ identity: identity(), directory });
    const machine = identity(); const pairing = await pair(hub, machine); const profile = identity(); const endpoint = identity();
    const statement = createEnrollmentStatement(machine, { endpointId: endpoint.principalId, profileName: "remote", principalId: profile.principalId, publicKeySpki: profile.publicKeySpki, enrolledAt: Date.now() });
    await hub.putEnrollment(statement);
    await expect(hub.putEnrollment({ ...statement, profileName: "forged" })).rejects.toThrow(/invalid signed enrollment statement/);
    expect((await hub.enrollments()).map((item) => item.principalId)).toEqual([profile.principalId]);
    expect(pairing.pinnedPeerKey.principalId).toBe(hub.identity.principalId);
    await hub.stop();
  });
});

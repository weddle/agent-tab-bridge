import { createPublicKey } from "node:crypto";
import { describe, expect, it } from "vitest";
import { generateIdentity, fingerprintSpki, type StoredIdentity } from "../identity.js";
import { MachinePairingCeremony, PairingFailure, PairingState, PAIRING_MAX_ATTEMPTS, startHubPairing, type PairingRoles } from "./index.js";
import { pinnedTlsOptions } from "./tls.js";
import { selfSignedCertificate } from "../../hub/certificate.js";
import { p256 } from "./vendor/pake-js-0.1.1.js";

const hex = (value: string): Uint8Array => Buffer.from(value.replace(/\s/g, ""), "hex");
const roles: PairingRoles = { machine: ["edge"], hub: ["presence"] };
function identity(): StoredIdentity {
  const generated = generateIdentity();
  return { version: 1, kind: "companion", principalId: generated.principalId, publicKeySpki: generated.publicKeySpki, privateKeyPkcs8: generated.privateKeyPkcs8, createdAt: 0 };
}
function ceremony() {
  const hub = identity();
  const machine = identity();
  const started = startHubPairing({ identity: hub, roles, random: (length) => Buffer.alloc(length, 1) });
  const client = new MachinePairingCeremony({ identity: machine, invitation: started.invitation, code: started.code, confirmedHubFingerprint: fingerprintSpki(hub.publicKeySpki) });
  const hello = client.createHello();
  const response = started.ceremony.respond(hello, fingerprintSpki(machine.publicKeySpki));
  return { hub, machine, started, client, hello, response };
}

describe("SPAKE2+ P-256 vendor conformance", () => {
  // RFC 9383 Appendix C, first vector (P-256/SHA-256). The Context is exactly 56
  // bytes -- the authoritative TT hex begins 0x38 -- despite the RFC's 72-column
  // text wrapping "[Context=b'...Test Vectors" / "']" across lines, which reads
  // as if a trailing character belonged to the string. It does not.
  const context = Buffer.from("SPAKE2+-P256-SHA256-HKDF-SHA256-HMAC-SHA256 Test Vectors");
  const ids = { idProver: Buffer.from("client"), idVerifier: Buffer.from("server") };
  const w0 = hex("bb8e1bbcf3c48f62c08db243652ae55d3e5586053fca77102994f23ad95491b3");
  const w1 = hex("7e945f34d78785b8a3ef44d0df5a1a97d6b3b460409a345ca7830387a74b1dba");
  const x = BigInt("0xd1232c8e8693d02368976c174e2088851b8365d0d79a9eee709c6a05a2fad539");
  const y = BigInt("0x717a72348a182085109c8d3917d6c43d59b224dc6a7fc4f0483232fa6516d8b3");
  const hexOf = (value: Uint8Array): string => Buffer.from(value).toString("hex");

  it("matches RFC 9383 Appendix C's first P-256/SHA-256 vector", () => {
    const prover = p256.__clientStartWithScalar(w0, x);
    const verifier = p256.__serverRespondWithScalar({ w0, L: p256.registerVerifier(w1), shareP: prover.shareP }, y);
    const client = p256.clientFinish({ w0, w1, x: prover.x, shareV: verifier.shareV });
    const keys = p256.deriveKeys({ context, ...ids, w0, shareP: prover.shareP, shareV: verifier.shareV, Z: client.Z, V: client.V });
    expect(hexOf(prover.shareP)).toBe("04ef3bd051bf78a2234ec0df197f7828060fe9856503579bb1733009042c15c0c1de127727f418b5966afadfdd95a6e4591d171056b333dab97a79c7193e341727");
    expect(hexOf(verifier.shareV)).toBe("04c0f65da0d11927bdf5d560c69e1d7d939a05b0e88291887d679fcadea75810fb5cc1ca7494db39e82ff2f50665255d76173e09986ab46742c798a9a68437b048");
    expect(hexOf(client.Z)).toBe("04bbfce7dd7f277819c8da21544afb7964705569bdf12fb92aa388059408d50091a0c5f1d3127f56813b5337f9e4e67e2ca633117a4fbd559946ab474356c41839");
    expect(hexOf(client.V)).toBe("0458bf27c6bca011c9ce1930e8984a797a3419797b936629a5a937cf2f11c8b9514b82b993da8a46e664f23db7c01edc87faa530db01c2ee405230b18997f16b68");
    expect(hexOf(keys.K_main)).toBe("4c59e1ccf2cfb961aa31bd9434478a1089b56cd11542f53d3576fb6c2a438a29");
    expect(hexOf(keys.K_shared)).toBe("0c5f8ccd1413423a54f6c1fb26ff01534a87f893779c6e68666d772bfd91f3e7");
    expect(hexOf(keys.confirmP)).toBe("926cc713504b9b4d76c9162ded04b5493e89109f6d89462cd33adc46fda27527");
    expect(hexOf(keys.confirmV)).toBe("9747bcc4f8fe9f63defee53ac9b07876d907d55047e6ff2def2e7529089d3e68");
  });

  it("derives different keys under a perturbed w0 and rejects the mismatched confirmation", () => {
    const badW0 = Uint8Array.from(w0);
    badW0[31] ^= 0x01; // prover registered under a different code
    const prover = p256.__clientStartWithScalar(badW0, x);
    const verifier = p256.__serverRespondWithScalar({ w0, L: p256.registerVerifier(w1), shareP: prover.shareP }, y);
    const client = p256.clientFinish({ w0: badW0, w1, x: prover.x, shareV: verifier.shareV });
    const proverKeys = p256.deriveKeys({ context, ...ids, w0: badW0, shareP: prover.shareP, shareV: verifier.shareV, Z: client.Z, V: client.V });
    const verifierKeys = p256.deriveKeys({ context, ...ids, w0, shareP: prover.shareP, shareV: verifier.shareV, Z: verifier.Z, V: verifier.V });
    expect(hexOf(proverKeys.K_shared)).not.toBe(hexOf(verifierKeys.K_shared));
    expect(p256.verifyConfirmation(verifierKeys.confirmV, proverKeys.confirmV)).toBe(false);
    expect(p256.verifyConfirmation(verifierKeys.confirmV, verifierKeys.confirmV)).toBe(true);
  });
});

describe("machine-to-hub pairing", () => {
  it("pins reciprocal peer keysets after bidirectional confirmation", () => {
    const { hub, machine, started, client, response } = ceremony();
    const machineResult = client.complete(response);
    const hubResult = started.ceremony.complete(response, machineResult.confirmation);
    expect(machineResult.pairing.pinnedPeerKey.fingerprint).toBe(fingerprintSpki(hub.publicKeySpki));
    expect(hubResult.pairing.pinnedPeerKey.fingerprint).toBe(fingerprintSpki(machine.publicKeySpki));
    expect(machineResult.pairing.roles).toEqual(hubResult.pairing.roles);
  });

  it("rejects a tampered response, wrong code, replay, downgrade, and duplicate identity with typed failures", () => {
    const first = ceremony();
    // Replace the final base64url character with one guaranteed to differ; a fixed
    // replacement collides with the original share 1 in 16 runs.
    const tampered = `${first.response.verifierShare.slice(0, -1)}${first.response.verifierShare.endsWith("A") ? "E" : "A"}`;
    expect(() => first.client.complete({ ...first.response, verifierShare: tampered })).toThrowError(PairingFailure);
    expect(() => first.client.complete({ ...first.response, verifierShare: tampered })).toThrow(expect.objectContaining({ code: "key-mismatch" }));

    // The wrong-code scenario needs a hub ceremony whose single respond() is unused;
    // ceremony() has already consumed its hub's respond.
    const wrongHub = startHubPairing({ identity: identity(), roles, random: (length) => Buffer.alloc(length, 1) });
    const wrongMachine = identity();
    const wrongClient = new MachinePairingCeremony({ identity: wrongMachine, invitation: wrongHub.invitation, code: "999999", confirmedHubFingerprint: wrongHub.invitation.hub.fingerprint });
    const wrongHello = wrongClient.createHello();
    const wrongResponse = wrongHub.ceremony.respond(wrongHello, fingerprintSpki(wrongMachine.publicKeySpki));
    expect(() => wrongClient.complete(wrongResponse)).toThrow(expect.objectContaining({ code: "wrong-code" }));

    const replay = ceremony();
    const result = replay.client.complete(replay.response);
    replay.started.ceremony.complete(replay.response, result.confirmation);
    expect(() => replay.started.ceremony.complete(replay.response, result.confirmation)).toThrow(expect.objectContaining({ code: "replayed-confirmation" }));

    const downgrade = ceremony();
    const badInvitation = { ...downgrade.started.invitation, protocolVersion: "atb-pairing-v0" } as never;
    expect(() => new MachinePairingCeremony({ identity: downgrade.machine, invitation: badInvitation, code: downgrade.started.code, confirmedHubFingerprint: downgrade.started.invitation.hub.fingerprint }).createHello()).toThrow(expect.objectContaining({ code: "protocol-downgrade" }));

    const duplicateHub = startHubPairing({ identity: identity(), roles, random: (length) => Buffer.alloc(length, 1), isDuplicateIdentity: () => true });
    const duplicateMachine = identity();
    const duplicateClient = new MachinePairingCeremony({ identity: duplicateMachine, invitation: duplicateHub.invitation, code: duplicateHub.code, confirmedHubFingerprint: duplicateHub.invitation.hub.fingerprint });
    expect(() => duplicateHub.ceremony.respond(duplicateClient.createHello(), fingerprintSpki(duplicateMachine.publicKeySpki))).toThrow(expect.objectContaining({ code: "duplicate-identity" }));
  }, 10_000);

  it("expires dead codes and exhausts bounded wrong-code attempts", () => {
    let now = Date.now();
    const hub = identity();
    const machine = identity();
    const expired = startHubPairing({ identity: hub, roles, now: () => now, random: (length) => Buffer.alloc(length, 1) });
    const expiredClient = new MachinePairingCeremony({ identity: machine, invitation: expired.invitation, code: expired.code, confirmedHubFingerprint: expired.invitation.hub.fingerprint });
    const expiredHello = expiredClient.createHello();
    now = expired.invitation.expiresAt;
    expect(() => expired.ceremony.respond(expiredHello, fingerprintSpki(machine.publicKeySpki))).toThrow(expect.objectContaining({ code: "expired-code" }));

    const bounded = startHubPairing({ identity: hub, roles, random: (length) => Buffer.alloc(length, 1) });
    for (let attempt = 0; attempt < PAIRING_MAX_ATTEMPTS; attempt += 1) {
      const client = new MachinePairingCeremony({ identity: machine, invitation: bounded.invitation, code: "999999", confirmedHubFingerprint: bounded.invitation.hub.fingerprint });
      const response = bounded.ceremony.respond(client.createHello(), fingerprintSpki(machine.publicKeySpki));
      expect(() => client.complete(response)).toThrow(expect.objectContaining({ code: "wrong-code" }));
    }
    const finalClient = new MachinePairingCeremony({ identity: machine, invitation: bounded.invitation, code: "999999", confirmedHubFingerprint: bounded.invitation.hub.fingerprint });
    expect(() => bounded.ceremony.respond(finalClient.createHello(), fingerprintSpki(machine.publicKeySpki))).toThrow(expect.objectContaining({ code: "attempts-exhausted" }));
  });

  it("pins only the paired TLS 1.3 peer key", () => {
    const { hub, client, response } = ceremony();
    const options = pinnedTlsOptions(client.complete(response).pairing);
    const certificate = { pubkey: Buffer.from(hub.publicKeySpki, "base64url") } as never;
    expect(options.minVersion).toBe("TLSv1.3");
    expect(options.maxVersion).toBe("TLSv1.3");
    expect(options.rejectUnauthorized).toBe(true);
    expect(options.checkServerIdentity("hub", certificate)).toBeUndefined();
    expect(options.checkServerIdentity("hub", { ...certificate, pubkey: Buffer.from(identity().publicKeySpki, "base64url") })).toBeInstanceOf(Error);
  });

  it("pins the SPKI from a real generated certificate and rejects a wrong certificate", () => {
    const { hub, client, response } = ceremony();
    const pairing = client.complete(response).pairing;
    const good = selfSignedCertificate(hub);
    const wrong = selfSignedCertificate(identity());
    const options = pinnedTlsOptions(pairing);
    expect(options.checkServerIdentity("hub", { raw: good.certDer, pubkey: good.certDer } as never)).toBeUndefined();
    const spki = createPublicKey({ key: Buffer.from(hub.publicKeySpki, "base64url"), type: "spki", format: "der" }).export({ type: "spki", format: "der" });
    expect(options.checkServerIdentity("hub", { pubkey: spki.subarray(-65) } as never)).toBeUndefined();
    expect(options.checkServerIdentity("hub", { raw: wrong.certDer, pubkey: wrong.certDer } as never)).toBeInstanceOf(Error);
  });

  it("forgets all machine-wide pinned state", () => {
    const { client, response } = ceremony();
    const state = new PairingState();
    state.save(client.complete(response).pairing);
    expect(state.get()).toBeDefined();
    state.forget();
    expect(state.get()).toBeUndefined();
  });
});

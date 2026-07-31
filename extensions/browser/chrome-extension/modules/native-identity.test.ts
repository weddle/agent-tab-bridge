import { describe, expect, it } from "vitest";
import {
  fingerprintSpki,
  nativeProofTranscript,
  toBase64Url,
  verifyExtensionIdentity,
  verifyNativeChallenge,
} from "./native-identity.js";

describe("Native Messaging identity transcript", () => {
  it("binds both public keys, both nonces, identities, roles, and protocol v2 in canonical order", () => {
    const transcript = new TextDecoder().decode(
      nativeProofTranscript({
        companionId: "companion-principal",
        companionNonce: "companion-nonce",
        companionPublicKey: "companion-spki",
        extensionId: "extension-id",
        extensionNonce: "extension-nonce",
        extensionPublicKey: "extension-spki",
      }),
    );
    expect(transcript).toBe(
      '{"companionId":"companion-principal","companionNonce":"companion-nonce","companionPublicKey":"companion-spki","extensionId":"extension-id","extensionNonce":"extension-nonce","extensionPublicKey":"extension-spki","protocolVersion":2,"roles":["extension","companion"]}',
    );
  });

  it("rejects a companion challenge unless its pinned SPKI verifies the transcript", async () => {
    const pair = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"],
    );
    const fields = {
      companionId: "companion-principal",
      companionNonce: "companion-nonce",
      companionPublicKey: toBase64Url(await crypto.subtle.exportKey("spki", pair.publicKey)),
      extensionId: "extension-id",
      extensionNonce: "extension-nonce",
      extensionPublicKey: "extension-spki",
    };
    const signature = new Uint8Array(
      await crypto.subtle.sign(
        { name: "ECDSA", hash: "SHA-256" },
        pair.privateKey,
        nativeProofTranscript(fields),
      ),
    );
    expect(await verifyNativeChallenge(fields.companionPublicKey, toBase64Url(signature), fields)).toBe(true);
    signature[0] ^= 0x01;
    expect(await verifyNativeChallenge(fields.companionPublicKey, toBase64Url(signature), fields)).toBe(false);
  });

  it("recomputes SPKI fingerprints and rejects a stored public/private key substitution", async () => {
    const createIdentity = async () => {
      const pair = await crypto.subtle.generateKey(
        { name: "ECDSA", namedCurve: "P-256" },
        true,
        ["sign", "verify"],
      );
      const [publicKeySpki, privateKeyPkcs8] = await Promise.all([
        crypto.subtle.exportKey("spki", pair.publicKey),
        crypto.subtle.exportKey("pkcs8", pair.privateKey),
      ]);
      const [publicKey, privateKey] = await Promise.all([
        crypto.subtle.importKey(
          "spki",
          publicKeySpki,
          { name: "ECDSA", namedCurve: "P-256" },
          true,
          ["verify"],
        ),
        crypto.subtle.importKey(
          "pkcs8",
          privateKeyPkcs8,
          { name: "ECDSA", namedCurve: "P-256" },
          false,
          ["sign"],
        ),
      ]);
      return {
        key: "extension",
        version: 1,
        createdAt: 1,
        publicKey,
        privateKey,
        publicKeySpki: toBase64Url(publicKeySpki),
      };
    };

    const [first, second] = await Promise.all([createIdentity(), createIdentity()]);
    expect(await verifyExtensionIdentity(first)).toBe(true);
    expect(await verifyExtensionIdentity({ ...first, privateKey: second.privateKey })).toBe(false);
    expect(await fingerprintSpki(first.publicKeySpki)).toMatch(/^sha256\/[A-Za-z0-9+/]+={0,2}$/u);
    expect(await fingerprintSpki(first.publicKeySpki)).not.toBe(await fingerprintSpki(second.publicKeySpki));
  });
});

import { createHash, scryptSync } from "node:crypto";
import { p256 } from "./vendor/pake-js-0.1.1.js";

export const PAKE_CIPHER_SUITE = "SPAKE2PLUS-P256-SHA256-HKDF-SHA256-HMAC-SHA256" as const;
const encoder = new TextEncoder();

export interface PakeRegistration { readonly w0: Uint8Array; readonly w1: Uint8Array; readonly verifier: Uint8Array; }
export interface PakeProverStart { readonly secret: Uint8Array; readonly share: Uint8Array; }
export interface PakeVerifierResponse { readonly share: Uint8Array; readonly secrets: PakeSecrets; }
export interface PakeSecrets { readonly sharedKey: Uint8Array; readonly proverConfirmation: Uint8Array; readonly verifierConfirmation: Uint8Array; }

/** A replaceable adapter; no vendor-specific types cross this boundary. */
export interface PakeEngine {
  register(code: string, proverId: string, verifierId: string, context: Uint8Array): PakeRegistration;
  startProver(registration: PakeRegistration): PakeProverStart;
  respond(registration: PakeRegistration, proverShare: Uint8Array, proverId: string, verifierId: string, context: Uint8Array): PakeVerifierResponse;
  finishProver(registration: PakeRegistration, start: PakeProverStart, verifierShare: Uint8Array, proverId: string, verifierId: string, context: Uint8Array): PakeSecrets;
  verify(expected: Uint8Array, received: Uint8Array): boolean;
}

function lengthPrefixed(value: Uint8Array): Buffer {
  const length = Buffer.alloc(8);
  length.writeBigUInt64LE(BigInt(value.length));
  return Buffer.concat([length, value]);
}

function passwordInput(code: string, proverId: string, verifierId: string): Buffer {
  return Buffer.concat([lengthPrefixed(encoder.encode(code)), lengthPrefixed(encoder.encode(proverId)), lengthPrefixed(encoder.encode(verifierId))]);
}

function keys(registration: PakeRegistration, proverShare: Uint8Array, verifierShare: Uint8Array, shared: { Z: Uint8Array; V: Uint8Array }, proverId: string, verifierId: string, context: Uint8Array): PakeSecrets {
  const output = p256.deriveKeys({ context, idProver: encoder.encode(proverId), idVerifier: encoder.encode(verifierId), w0: registration.w0, shareP: proverShare, shareV: verifierShare, Z: shared.Z, V: shared.V });
  return { sharedKey: output.K_shared, proverConfirmation: output.confirmP, verifierConfirmation: output.confirmV };
}

/** RFC 9383 §3.2's recommended scrypt parameters and 80-byte output. */
export const defaultPakeEngine: PakeEngine = {
  register(code, proverId, verifierId, context) {
    if (!/^\d{6}$/.test(code)) throw new TypeError("pairing code must be exactly six digits");
    const salt = createHash("sha256").update("atb-spake2plus-p256-v1\0").update(context).digest();
    const material = scryptSync(passwordInput(code, proverId, verifierId), salt, 80, { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
    const { w0, w1 } = p256.deriveScalars(material);
    return { w0, w1, verifier: p256.registerVerifier(w1) };
  },
  startProver(registration) {
    const started = p256.clientStart(registration.w0);
    return { secret: started.x, share: started.shareP };
  },
  respond(registration, proverShare, proverId, verifierId, context) {
    const response = p256.serverRespond({ w0: registration.w0, L: registration.verifier, shareP: proverShare });
    return { share: response.shareV, secrets: keys(registration, proverShare, response.shareV, response, proverId, verifierId, context) };
  },
  finishProver(registration, start, verifierShare, proverId, verifierId, context) {
    const shared = p256.clientFinish({ w0: registration.w0, w1: registration.w1, x: start.secret, shareV: verifierShare });
    return keys(registration, start.share, verifierShare, shared, proverId, verifierId, context);
  },
  verify: p256.verifyConfirmation,
};

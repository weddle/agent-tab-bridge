import { X509Certificate, createPublicKey, timingSafeEqual } from "node:crypto";
import type { PeerCertificate } from "node:tls";
import { fingerprintSpki } from "../identity.js";
import type { PinnedPeerKeyset } from "./index.js";

export interface TlsPinningOptions {
  readonly minVersion: "TLSv1.3";
  readonly maxVersion: "TLSv1.3";
  readonly rejectUnauthorized: true;
  checkServerIdentity(hostname: string, certificate: PeerCertificate): Error | undefined;
}
function peerSpki(certificate: PeerCertificate): Uint8Array | undefined {
  if (certificate.raw) {
    try { return new X509Certificate(certificate.raw).publicKey.export({ type: "spki", format: "der" }); } catch { /* use runtime key below */ }
  }
  if (!certificate.pubkey) return undefined;
  try { return createPublicKey({ key: certificate.pubkey, type: "spki", format: "der" }).export({ type: "spki", format: "der" }); } catch { /* Node exposes an uncompressed P-256 point when raw is unavailable. */ }
  if (certificate.pubkey.length !== 65 || certificate.pubkey[0] !== 4) return undefined;
  return Buffer.concat([Buffer.from("3059301306072a8648ce3d020106082a8648ce3d030107034200", "hex"), Buffer.from(certificate.pubkey)]);
}
/** TLS 1.3-only certificate key pinning for the outbound edge→hub connection. */
export function pinnedTlsOptions(pairing: PinnedPeerKeyset): TlsPinningOptions {
  return {
    minVersion: "TLSv1.3",
    maxVersion: "TLSv1.3",
    rejectUnauthorized: true,
    checkServerIdentity(_hostname, certificate) {
      try {
        const spki = peerSpki(certificate);
        if (!spki) return new Error("TLS peer key does not match the pinned pairing key");
        const actual = Buffer.from(fingerprintSpki(spki));
        const expected = Buffer.from(pairing.pinnedPeerKey.fingerprint);
        if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) return new Error("TLS peer key does not match the pinned pairing key");
        return undefined;
      } catch { return new Error("TLS peer key does not match the pinned pairing key"); }
    },
  };
}

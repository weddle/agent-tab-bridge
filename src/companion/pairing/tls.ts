import type { PeerCertificate } from "node:tls";
import { fingerprintSpki } from "../identity.js";
import type { PinnedPeerKeyset } from "./index.js";

export interface TlsPinningOptions {
  readonly minVersion: "TLSv1.3";
  readonly maxVersion: "TLSv1.3";
  readonly rejectUnauthorized: true;
  checkServerIdentity(hostname: string, certificate: PeerCertificate): Error | undefined;
}

/** TLS 1.3-only certificate key pinning for the outbound edge→hub connection. */
export function pinnedTlsOptions(pairing: PinnedPeerKeyset): TlsPinningOptions {
  return {
    minVersion: "TLSv1.3",
    maxVersion: "TLSv1.3",
    rejectUnauthorized: true,
    checkServerIdentity(_hostname, certificate) {
      if (!certificate.pubkey || fingerprintSpki(certificate.pubkey) !== pairing.pinnedPeerKey.fingerprint) return new Error("TLS peer key does not match the pinned pairing key");
      return undefined;
    },
  };
}

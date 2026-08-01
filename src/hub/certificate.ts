import { createPrivateKey, sign, type KeyObject } from "node:crypto";
import type { StoredIdentity } from "../companion/identity.js";

const b64pem = (value: Uint8Array, label: string): string => {
  const encoded = Buffer.from(value).toString("base64").match(/.{1,64}/g)?.join("\n") ?? "";
  return `-----BEGIN ${label}-----\n${encoded}\n-----END ${label}-----\n`;
};
function derLength(length: number): Buffer {
  if (length < 0x80) return Buffer.from([length]);
  const bytes: number[] = []; let value = length;
  while (value > 0) { bytes.unshift(value & 0xff); value >>>= 8; }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}
function der(tag: number, value: Uint8Array): Buffer { return Buffer.concat([Buffer.from([tag]), derLength(value.byteLength), Buffer.from(value)]); }
function sequence(...values: Uint8Array[]): Buffer { return der(0x30, Buffer.concat(values.map((value) => Buffer.from(value)))); }
function set(...values: Uint8Array[]): Buffer { return der(0x31, Buffer.concat(values.map((value) => Buffer.from(value)))); }
function integer(value: number): Buffer {
  const bytes: number[] = []; let current = value;
  do { bytes.unshift(current & 0xff); current = Math.floor(current / 256); } while (current > 0);
  if (bytes[0] & 0x80) bytes.unshift(0);
  return der(0x02, Buffer.from(bytes));
}
function oid(value: number[]): Buffer {
  const encodeComponent = (component: number): number[] => {
    const parts = [component & 0x7f]; let current = component >>> 7;
    while (current > 0) { parts.unshift((current & 0x7f) | 0x80); current >>>= 7; }
    return parts;
  };
  const output = [...encodeComponent(value[0] * 40 + value[1])];
  for (const item of value.slice(2)) output.push(...encodeComponent(item));
  return der(0x06, Buffer.from(output));
}
function name(commonName: string): Buffer {
  const attribute = sequence(oid([2, 5, 4, 3]), der(0x0c, Buffer.from(commonName, "utf8")));
  return sequence(set(attribute));
}
function generalizedTime(date: Date): Buffer { return der(0x18, Buffer.from(date.toISOString().replace(/[-:T]/g, "").replace(/\.\d{3}/, ""))); }
/** Generate a short-lived self-signed certificate whose key is the identity SPKI. */
export function selfSignedCertificate(identity: StoredIdentity, commonName = "atb hub"): { keyPem: string; certPem: string; certDer: Buffer } {
  const privateKey: KeyObject = createPrivateKey({ key: Buffer.from(identity.privateKeyPkcs8, "base64url"), format: "der", type: "pkcs8" });
  const publicKey = Buffer.from(identity.publicKeySpki, "base64url");
  const algorithm = sequence(oid([1, 2, 840, 10045, 4, 3, 2]), der(0x05, Buffer.alloc(0)));
  const now = new Date(); const expires = new Date(now.getTime() + 365 * 24 * 60 * 60 * 1000);
  const validity = sequence(generalizedTime(now), generalizedTime(expires));
  const tbs = sequence(der(0xa0, integer(2)), integer(1), algorithm, name(commonName), validity, name(commonName), publicKey);
  const signature = sign("sha256", tbs, { key: privateKey, dsaEncoding: "der" });
  const certDer = sequence(tbs, algorithm, der(0x03, Buffer.concat([Buffer.from([0]), signature])));
  return { keyPem: b64pem(Buffer.from(identity.privateKeyPkcs8, "base64url"), "PRIVATE KEY"), certPem: b64pem(certDer, "CERTIFICATE"), certDer };
}

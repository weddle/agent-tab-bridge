import { fingerprintSpki, signTranscript, verifyTranscript, type StoredIdentity } from "./identity.js";

export interface EnrollmentStatement {
  readonly machineId: string;
  readonly endpointId: string;
  readonly profileName: string;
  readonly principalId: string;
  readonly publicKeySpki: string;
  readonly enrolledAt: number;
  readonly signature: string;
}

const fingerprint = (value: unknown): value is string => typeof value === "string" && /^sha256\/[A-Za-z0-9+/=_-]{1,249}$/.test(value);
const name = (value: unknown): value is string => typeof value === "string" && /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(value);

export function isEnrollmentStatement(value: unknown): value is EnrollmentStatement {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const statement = value as Record<string, unknown>;
  return Object.keys(statement).length === 7 && fingerprint(statement.machineId) && fingerprint(statement.endpointId) && name(statement.profileName) && fingerprint(statement.principalId) && typeof statement.publicKeySpki === "string" && statement.publicKeySpki.length > 0 && statement.publicKeySpki.length <= 8192 && typeof statement.enrolledAt === "number" && Number.isSafeInteger(statement.enrolledAt) && statement.enrolledAt > 0 && typeof statement.signature === "string" && statement.signature.length > 0;
}

export function canonicalEnrollmentStatement(statement: Omit<EnrollmentStatement, "signature">): Uint8Array {
  if (!isEnrollmentStatement({ ...statement, signature: "x" })) throw new TypeError("invalid enrollment statement");
  if (fingerprintSpki(statement.publicKeySpki) !== statement.principalId) throw new TypeError("enrollment statement profile key mismatch");
  return new TextEncoder().encode(JSON.stringify({ endpointId: statement.endpointId, enrolledAt: statement.enrolledAt, machineId: statement.machineId, principalId: statement.principalId, profileName: statement.profileName, publicKeySpki: statement.publicKeySpki }));
}

export function createEnrollmentStatement(identity: StoredIdentity, statement: Omit<EnrollmentStatement, "signature" | "machineId">): EnrollmentStatement {
  if (identity.principalId !== fingerprintSpki(identity.publicKeySpki)) throw new TypeError("invalid edge identity");
  const unsigned = { ...statement, machineId: identity.principalId };
  return { ...unsigned, signature: signTranscript(identity.privateKeyPkcs8, canonicalEnrollmentStatement(unsigned)) };
}

export function verifyEnrollmentStatement(statement: EnrollmentStatement, machinePublicKeySpki: string): boolean {
  try { return fingerprintSpki(machinePublicKeySpki) === statement.machineId && verifyTranscript(machinePublicKeySpki, canonicalEnrollmentStatement(statement), statement.signature); } catch { return false; }
}

import { describe, expect, it } from "vitest";
import { createEnrollmentStatement, verifyEnrollmentStatement } from "./enrollment-statement.js";
import { generateIdentity, type StoredIdentity } from "./identity.js";

function identity(): StoredIdentity { const key = generateIdentity(); return { version: 1, kind: "companion", principalId: key.principalId, publicKeySpki: key.publicKeySpki, privateKeyPkcs8: key.privateKeyPkcs8, createdAt: Date.now() }; }

describe("signed enrollment statements", () => {
  it("binds an enrolled profile and endpoint to the edge machine key", () => {
    const machine = identity(), endpoint = identity(), profile = identity();
    const statement = createEnrollmentStatement(machine, { endpointId: endpoint.principalId, profileName: "remote", principalId: profile.principalId, publicKeySpki: profile.publicKeySpki, enrolledAt: Date.now() });
    expect(verifyEnrollmentStatement(statement, machine.publicKeySpki)).toBe(true);
    expect(verifyEnrollmentStatement({ ...statement, endpointId: identity().principalId }, machine.publicKeySpki)).toBe(false);
    expect(verifyEnrollmentStatement(statement, identity().publicKeySpki)).toBe(false);
  });
});

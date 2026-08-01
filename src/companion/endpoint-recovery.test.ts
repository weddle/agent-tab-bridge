import { describe, expect, it } from "vitest";
import { ENDPOINT_RECOVERY_GRACE_MS } from "./endpoint-contracts.js";
import { nativeEndpointStopDisposition } from "./endpoint-recovery.js";

describe("Native endpoint shutdown recovery", () => {
  it("uses the approved two-minute recovery grace", () => {
    expect(ENDPOINT_RECOVERY_GRACE_MS).toBe(2 * 60_000);
  });
  it("treats Native Messaging output failure as recoverable endpoint loss", () => {
    expect(nativeEndpointStopDisposition({ hasRecovery: true, outputFailed: true, permanentClose: false })).toBe("suspend");
    expect(nativeEndpointStopDisposition({ hasRecovery: true, outputFailed: false, permanentClose: false })).toBe("suspend");
    expect(nativeEndpointStopDisposition({ hasRecovery: false, outputFailed: true, permanentClose: false })).toBe("revoke");
    expect(nativeEndpointStopDisposition({ hasRecovery: true, outputFailed: true, permanentClose: true })).toBe("revoke");
  });
});

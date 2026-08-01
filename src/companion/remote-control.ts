import { fingerprintSpki } from "./identity.js";
import type { HubRouteConnection } from "./pairing/routes.js";
import type { RoutedBrokerAddress } from "../hub/routing.js";

export interface RemoteEnrollmentResult { readonly enrollmentId: string; readonly code: string; readonly expiresAt: number; }

/** Starts the existing fingerprint-and-code enrollment ceremony at a selected remote edge. */
export async function enrollRoutedProfile(routes: HubRouteConnection, address: RoutedBrokerAddress, profileName: string, publicKeySpki: string): Promise<RemoteEnrollmentResult> {
  if (address.principalId !== fingerprintSpki(publicKeySpki)) throw new TypeError("routed enrollment principal does not match its public key");
  const stream = routes.open(address);
  return await new Promise<RemoteEnrollmentResult>((resolve, reject) => {
    const timer = setTimeout(() => { stream.close(); reject(new Error("remote enrollment timed out")); }, 15_000);
    timer.unref?.();
    const off = stream.onPayload((payload) => {
      try {
        const response = JSON.parse(payload.toString("utf8")) as Record<string, unknown>;
        if (response.type !== "remoteEnrollResult") return;
        clearTimeout(timer); off(); stream.close();
        if (response.ok !== true || !response.enrollment || typeof response.enrollment !== "object") throw new Error(typeof response.error === "string" ? response.error : "remote enrollment failed");
        const enrollment = response.enrollment as Record<string, unknown>;
        if (typeof enrollment.enrollmentId !== "string" || typeof enrollment.code !== "string" || typeof enrollment.expiresAt !== "number" || !Number.isSafeInteger(enrollment.expiresAt)) throw new Error("remote edge returned an invalid enrollment result");
        resolve({ enrollmentId: enrollment.enrollmentId, code: enrollment.code, expiresAt: enrollment.expiresAt });
      } catch (error) { clearTimeout(timer); off(); stream.close(); reject(error instanceof Error ? error : new Error(String(error))); }
    });
    stream.send(Buffer.from(JSON.stringify({ type: "remoteEnroll", profileName, publicKeySpki }), "utf8"));
  });
}

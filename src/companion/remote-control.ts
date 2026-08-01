import { fingerprintSpki } from "./identity.js";
import type { HubRouteConnection } from "./pairing/routes.js";
import type { RoutedBrokerAddress } from "../hub/routing.js";
import { createSecureRoutedTransport } from "./broker-client.js";

export interface RemoteEnrollmentResult { readonly enrollmentId: string; readonly code: string; readonly expiresAt: number; }
export interface RemoteEnrollmentProfile { readonly name: string; readonly principalId: string; readonly publicKeySpki: string; readonly privateKeyPkcs8: string; }

/** Starts the existing fingerprint-and-code enrollment ceremony over the authenticated E2E route. */
export async function enrollRoutedProfile(routes: HubRouteConnection, address: RoutedBrokerAddress, profile: RemoteEnrollmentProfile, targetPublicKeySpki: string, hubId: string): Promise<RemoteEnrollmentResult> {
  if (address.principalId !== fingerprintSpki(profile.publicKeySpki)) throw new TypeError("routed enrollment principal does not match its public key");
  const stream = routes.open(address);
  const route = { hubId, routeId: stream.routeId, streamId: stream.streamId, address };
  const secure = await createSecureRoutedTransport({ stream, profile, route, targetPublicKeySpki });
  const { promise, resolve, reject } = Promise.withResolvers<RemoteEnrollmentResult>();
  const timer = setTimeout(() => { secure.destroy(); reject(new Error("remote enrollment timed out")); }, 15_000);
  timer.unref?.();
  secure.on("data", (payload: Buffer) => {
    try {
      const response = JSON.parse(payload.toString("utf8")) as Record<string, unknown>;
      if (response.type !== "remoteEnrollResult") return;
      clearTimeout(timer);
      if (response.ok !== true || !response.enrollment || typeof response.enrollment !== "object") throw new Error(typeof response.error === "string" ? response.error : "remote enrollment failed");
      const enrollment = response.enrollment as Record<string, unknown>;
      if (typeof enrollment.enrollmentId !== "string" || typeof enrollment.code !== "string" || typeof enrollment.expiresAt !== "number" || !Number.isSafeInteger(enrollment.expiresAt)) throw new Error("remote edge returned an invalid enrollment result");
      resolve({ enrollmentId: enrollment.enrollmentId, code: enrollment.code, expiresAt: enrollment.expiresAt });
      secure.destroy();
    } catch (error) { clearTimeout(timer); secure.destroy(); reject(error instanceof Error ? error : new Error(String(error))); }
  });
  secure.once("error", (error) => { clearTimeout(timer); reject(error); });
  secure.write(JSON.stringify({ type: "remoteEnroll", profileName: profile.name, publicKeySpki: profile.publicKeySpki }));
  return await promise;
}

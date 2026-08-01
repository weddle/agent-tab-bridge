import type { BrokerServer } from "./broker.js";
import type { AccessUpgradeRecord, HostToExtensionMessage } from "./native-protocol.js";
import type { PinnedExtensionIdentity } from "./state.js";
import type { SessionAccessDelta } from "./session-access.js";
import type { TaskSessionManager } from "./task-sessions.js";

export type NativeEndpointBinding = {
  trusted: boolean;
  send: ((message: HostToExtensionMessage) => Promise<void>) | undefined;
  listTabs: ((sessionId: string | undefined, scope: "all" | "session") => Promise<unknown>) | undefined;
  claimTab: ((sessionId: string, tabId: number) => Promise<unknown>) | undefined;
  requestAccess: ((controllerPrincipalId: string, stableSessionKey: string, delta: SessionAccessDelta) => Promise<AccessUpgradeRecord>) | undefined;
  enrollProfile: ((profileName: string, publicKeySpki: string) => Promise<Readonly<{ enrollmentId: string; code: string; expiresAt: number }>>) | undefined;
};

/** In-memory endpoint authority retained only during the bounded recovery grace. */
export type NativeEndpointRecovery = {
  identity: PinnedExtensionIdentity;
  sessions: TaskSessionManager;
  broker: BrokerServer;
  binding: NativeEndpointBinding;
};

export type NativeEndpointStopDisposition = "suspend" | "revoke";

/**
 * A broken Native Messaging output is endpoint loss, not authority loss.
 * Only missing recovery state or an explicit permanent close bypasses grace.
 */
export function nativeEndpointStopDisposition(state: Readonly<{
  hasRecovery: boolean;
  outputFailed: boolean;
  permanentClose: boolean;
}>): NativeEndpointStopDisposition {
  return state.hasRecovery && !state.permanentClose ? "suspend" : "revoke";
}

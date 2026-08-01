import type { RoutedBrokerAddress } from "../../hub/routing.js";

export function routedChannelContext(address: RoutedBrokerAddress, routeId: string, streamId: string): Uint8Array {
  return new TextEncoder().encode(JSON.stringify({ type: "atb-routed-channel-v1", address, routeId, streamId }));
}

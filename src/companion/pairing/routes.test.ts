import { describe, expect, it } from "vitest";
import { HubRouteStream, type HubRouteConnection } from "./routes.js";

const address = { machineId: "sha256/machine", endpointId: "sha256/endpoint", principalId: "sha256/controller", stableSessionKey: "session" };

describe("HubRouteStream", () => {
  it("snapshots payload listeners so newly-added listeners await the next frame", () => {
    const stream = new HubRouteStream({} as HubRouteConnection, address, "route", "stream", "response");
    const received: string[] = [];
    let remove: (() => void) | undefined;
    remove = stream.onPayload((payload) => {
      received.push(`first:${payload.toString()}`);
      remove?.();
      stream.onPayload((next) => received.push(`second:${next.toString()}`));
    });
    stream.receive(Buffer.from("one"));
    expect(received).toEqual(["first:one"]);
    stream.receive(Buffer.from("two"));
    expect(received).toEqual(["first:one", "second:two"]);
  });
});

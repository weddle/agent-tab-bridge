import { describe, expect, it } from "vitest";
import {
  buildRelayWsProtocols,
  nearestGroupColor,
  parsePairingString,
  reconnectDelayMs,
  toRelayTabInfo,
} from "./relay-core.js";

describe("Agent Tab Bridge pairing", () => {
  it("parses the loopback extension pairing format", () => {
    expect(parsePairingString("ws://127.0.0.1:18797/extension#bridge-secret")).toEqual({
      relayUrl: "ws://127.0.0.1:18797/extension",
      token: "bridge-secret",
    });
  });

  it("rejects non-loopback, non-WebSocket, wrong-path, credentialed, query-bearing, and empty pairings", () => {
    const invalid = [
      "",
      "http://127.0.0.1:18797/extension#token",
      "wss://127.0.0.1:18797/extension#token",
      "ws://localhost:18797/extension#token",
      "ws://192.0.2.1:18797/extension#token",
      "ws://user:pass@127.0.0.1:18797/extension#token",
      "ws://127.0.0.1:0/extension#token",
      "ws://127.0.0.1:65536/extension#token",
      "ws://127.0.0.1:18797/other#token",
      "ws://127.0.0.1:18797/extension?debug=true#token",
      "ws://127.0.0.1:18797/extension#token%20",
      "ws://127.0.0.1/extension#token",
      "ws://127.0.0.1:18797/extension",
    ];
    for (const pairing of invalid) {
      expect(parsePairingString(pairing), pairing).toBeNull();
    }
  });

  it("uses the generic bridge WebSocket protocol and token prefix", () => {
    expect(buildRelayWsProtocols("bridge-secret")).toEqual([
      "agent-tab-bridge-relay",
      "agent-tab-bridge-token.bridge-secret",
    ]);
  });
});

describe("extension relay helpers", () => {
  it("normalizes shared tab snapshots without inventing consent", () => {
    expect(
      toRelayTabInfo({
        id: 17,
        url: undefined,
        title: undefined,
        active: undefined,
      }),
    ).toEqual({
      tabId: 17,
      url: "",
      title: "",
      active: false,
    });
  });

  it("backs off reconnects exponentially and caps at thirty seconds", () => {
    expect(reconnectDelayMs(0)).toBe(1_000);
    expect(reconnectDelayMs(1)).toBe(2_000);
    expect(reconnectDelayMs(4)).toBe(16_000);
    expect(reconnectDelayMs(5)).toBe(30_000);
    expect(reconnectDelayMs(100)).toBe(30_000);
  });

  it("maps group accents and safely falls back for invalid colors", () => {
    expect(nearestGroupColor("#4285F4")).toBe("blue");
    expect(nearestGroupColor("#00AA00")).toBe("green");
    expect(nearestGroupColor("not-a-color")).toBe("blue");
  });
});

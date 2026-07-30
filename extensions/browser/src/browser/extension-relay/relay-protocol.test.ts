import { describe, expect, it } from "vitest";
import { parseExtensionMessage } from "./relay-protocol.js";

describe("generic extension relay frames", () => {
  it("accepts the frames needed to establish and maintain a shared-tab session", () => {
    expect(
      parseExtensionMessage(
        JSON.stringify({
          type: "hello",
          userAgent: "Brave/1.80.0",
          browserVersion: "Brave/1.80.0",
          extensionVersion: "1.0.0",
          tabs: [],
        }),
      ),
    ).toMatchObject({ type: "hello", tabs: [] });
    expect(
      parseExtensionMessage(JSON.stringify({ type: "tabs", tabs: [{ tabId: 4 }] })),
    ).toMatchObject({ type: "tabs", tabs: [{ tabId: 4 }] });
    expect(
      parseExtensionMessage(JSON.stringify({ type: "result", seq: 3, result: { ok: true } })),
    ).toMatchObject({ type: "result", seq: 3 });
    expect(parseExtensionMessage(JSON.stringify({ type: "pong" }))).toEqual({ type: "pong" });
    expect(
      parseExtensionMessage(
        JSON.stringify({ type: "detached", tabId: 4, reason: "consent revoked" }),
      ),
    ).toMatchObject({ type: "detached", tabId: 4 });
  });

  it("rejects malformed and unknown frames", () => {
    expect(parseExtensionMessage("not json")).toBeNull();
    expect(parseExtensionMessage(JSON.stringify({ type: "unknown" }))).toBeNull();
    expect(parseExtensionMessage(JSON.stringify({ noType: true }))).toBeNull();
    expect(parseExtensionMessage(JSON.stringify(42))).toBeNull();
  });
});

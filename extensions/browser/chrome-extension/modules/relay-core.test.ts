import { describe, expect, it } from "vitest";
import {
  reconnectDelayMs,
  toRelayTabInfo,
} from "./relay-core.js";
import { isPermittedPageCdpMethod } from "./cdp-policy.js";



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

});

describe("shared-page CDP policy", () => {
  it("allows only the explicit page-domain surface", () => {
    for (const method of ["Page.navigate", "DOM.getDocument", "Runtime.evaluate", "Accessibility.getFullAXTree"]) {
      expect(isPermittedPageCdpMethod(method)).toBe(true);
    }
  });

  it("default-denies sensitive, browser-scope, and future CDP domains", () => {
    for (const method of [
      "DOM.getFileInfo",
      "Page.setDownloadBehavior",
      "Network.getCookies",
      "Browser.close",
      "Target.createTarget",
      "Tethering.bind",
      "Autofill.enable",
      "FedCm.enable",
      "WebAuthn.enable",
      "FutureCdpDomain.doThing",
    ]) {
      expect(isPermittedPageCdpMethod(method)).toBe(false);
    }
  });
});

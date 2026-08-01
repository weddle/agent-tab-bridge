import { describe, expect, it } from "vitest";
import {
  isCurrentRelaySocketFailure,
  relaySocketCloseDisposition,
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

  it("ignores delayed errors from removed or replaced relay sockets", () => {
    const stale = {};
    const current = {};
    expect(isCurrentRelaySocketFailure(stale, stale)).toBe(true);
    expect(isCurrentRelaySocketFailure(undefined, stale)).toBe(false);
    expect(isCurrentRelaySocketFailure(current, stale)).toBe(false);
    expect(isCurrentRelaySocketFailure(undefined, null)).toBe(true);
    expect(isCurrentRelaySocketFailure(current, current, true)).toBe(false);
  });

  it("classifies a current close before relay ownership is removed", () => {
    const stale = {};
    const current = {};
    expect(relaySocketCloseDisposition(current, stale, false)).toBe("ignore");
    expect(relaySocketCloseDisposition(current, current, false)).toBe("startupFailure");
    expect(relaySocketCloseDisposition(current, current, true)).toBe("disconnect");
    expect(relaySocketCloseDisposition(current, current, true, true)).toBe("ignore");
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

// Extension relay bridge: CDP target synthesis and extension command routing.
import { describe, expect, it, vi } from "vitest";
import {
  CDP_METHOD_POLICY_ERROR,
  CDP_METHOD_POLICY_ERROR_CODE,
  CdpMethodPolicy,
  classifyCdpMethod,
  ExtensionRelayBridge,
} from "./relay-bridge.js";
import type { ExtensionToRelayMessage, RelayToExtensionMessage } from "./relay-protocol.js";

/** In-memory socket capturing every frame the bridge sends. */
class FakeSocket {
  readonly sent: unknown[] = [];
  closed = false;
  closeCode?: number;
  send(data: string): void {
    this.sent.push(JSON.parse(data));
  }
  close(code?: number): void {
    this.closed = true;
    this.closeCode = code;
  }
  /** Frames of a given method (client CDP responses/events). */
  frames(): Array<Record<string, unknown>> {
    return this.sent as Array<Record<string, unknown>>;
  }
}

/**
 * Scripted extension: auto-answers relay commands so the bridge can complete
 * attach/CDP round-trips.
 */
function wireExtension(bridge: ExtensionRelayBridge) {
  const socket = new FakeSocket();
  const handlers = bridge.attachExtensionSocket(socket);
  // Auto-reply to commands the bridge issues to the extension.
  const originalSend = socket.send.bind(socket);
  socket.send = (data: string) => {
    originalSend(data);
    const msg = JSON.parse(data) as RelayToExtensionMessage;
    if (msg.type === "ping") {
      return;
    }
    queueMicrotask(() => {
      const reply = replyFor(msg);
      if (reply) {
        handlers.onMessage(JSON.stringify(reply));
      }
      if (msg.type === "createTab") {
        handlers.onMessage(
          JSON.stringify({
            type: "tabs",
            tabs: [
              ...defaultTabs(),
              {
                tabId: 999,
                url: msg.url,
                title: "New tab",
                active: msg.focus === true,
              },
            ],
          }),
        );
      }
    });
  };
  return { socket, handlers };
}

function replyFor(msg: RelayToExtensionMessage): ExtensionToRelayMessage | null {
  switch (msg.type) {
    case "attach":
      return { type: "result", seq: msg.seq, result: { targetId: `target-${msg.tabId}` } };
    case "detach":
    case "activateTab":
    case "closeTab":
      return { type: "result", seq: msg.seq, result: {} };
    case "createTab":
      return { type: "result", seq: msg.seq, result: { tabId: 999 } };
    case "cdp":
      return { type: "result", seq: msg.seq, result: { ok: true, echoed: msg.method } };
    default:
      return null;
  }
}

function sendHello(handlers: { onMessage: (raw: string) => void }, tabs = defaultTabs()) {
  handlers.onMessage(
    JSON.stringify({
      type: "hello",
      userAgent: "Mozilla/5.0 Brave/1.80.0",
      browserVersion: "Brave/1.80.0",
      extensionVersion: "2.0.0",
      tabs,
    }),
  );
}

function defaultTabs() {
  return [{ tabId: 1, url: "https://example.com", title: "Example", active: true }];
}

const flush = async () => {
  await new Promise<void>((resolve) => {
    setImmediate(resolve);
  });
};

async function attachSharedPageSession() {
  const bridge = new ExtensionRelayBridge();
  const { socket: extensionSocket, handlers } = wireExtension(bridge);
  sendHello(handlers);
  const client = new FakeSocket();
  const cdp = bridge.attachCdpClientSocket(client);
  cdp.onMessage(
    JSON.stringify({ id: 1, method: "Target.setAutoAttach", params: { autoAttach: true } }),
  );
  await flush();
  const attached = client.frames().find((frame) => frame.method === "Target.attachedToTarget");
  const sessionId = (attached?.params as { sessionId?: unknown } | undefined)?.sessionId;
  if (typeof sessionId !== "string") {
    throw new Error("expected a shared tab session");
  }
  return { client, cdp, extensionSocket, handlers, sessionId };
}

describe("ExtensionRelayBridge", () => {
  it("reports the paired browser identity through Browser.getVersion", async () => {
    const bridge = new ExtensionRelayBridge();
    const { handlers } = wireExtension(bridge);
    sendHello(handlers);
    expect(bridge.extensionConnected).toBe(true);

    const client = new FakeSocket();
    const cdp = bridge.attachCdpClientSocket(client);
    cdp.onMessage(JSON.stringify({ id: 1, method: "Browser.getVersion" }));
    await flush();

    const response = client.frames().find((frame) => frame.id === 1);
    expect(response?.result).toMatchObject({
      protocolVersion: "1.3",
      product: "Brave/1.80.0",
    });
  });

  it("attaches shared tabs and announces targets on Target.setAutoAttach", async () => {
    const bridge = new ExtensionRelayBridge();
    const { handlers } = wireExtension(bridge);
    sendHello(handlers);

    const client = new FakeSocket();
    const cdp = bridge.attachCdpClientSocket(client);
    cdp.onMessage(
      JSON.stringify({ id: 1, method: "Target.setAutoAttach", params: { autoAttach: true } }),
    );
    await flush();

    const attached = client.frames().find((frame) => frame.method === "Target.attachedToTarget");
    expect(attached).toBeTruthy();
    const params = attached?.params as {
      targetInfo?: { targetId?: string; browserContextId?: string };
      sessionId?: string;
    };
    expect(params.targetInfo?.targetId).toBe("agent-tab-bridge-target-1");
    expect(typeof params.sessionId).toBe("string");
  });

  it("discovers an unattached shared tab and attaches it only on demand", async () => {
    const bridge = new ExtensionRelayBridge();
    const { socket, handlers } = wireExtension(bridge);
    sendHello(handlers);

    const client = new FakeSocket();
    const cdp = bridge.attachCdpClientSocket(client);
    cdp.onMessage(JSON.stringify({ id: 1, method: "Target.getTargets" }));
    await flush();

    const targetId = "agent-tab-bridge-target-1";
    expect(client.frames().find((frame) => frame.id === 1)?.result).toEqual({
      targetInfos: [
        expect.objectContaining({ targetId, attached: false }),
      ],
    });
    expect(socket.frames().some((frame) => frame.type === "attach")).toBe(false);

    cdp.onMessage(
      JSON.stringify({ id: 2, method: "Target.getTargetInfo", params: { targetId } }),
    );
    await flush();
    expect(client.frames().find((frame) => frame.id === 2)?.result).toEqual({
      targetInfo: expect.objectContaining({ targetId, attached: false }),
    });

    cdp.onMessage(
      JSON.stringify({ id: 3, method: "Target.attachToTarget", params: { targetId, flatten: true } }),
    );
    await flush();
    expect(socket.frames().find((frame) => frame.type === "attach")).toMatchObject({ tabId: 1 });
    expect(client.frames().find((frame) => frame.id === 3)?.result).toEqual({
      sessionId: expect.any(String),
    });
    expect(client.frames().find((frame) => frame.id === 1)?.result).toEqual({
      targetInfos: [
        expect.objectContaining({ targetId, attached: false }),
      ],
    });
  });

  it("routes session-scoped CDP commands to the owning tab", async () => {
    const bridge = new ExtensionRelayBridge();
    const { socket: extSocket, handlers } = wireExtension(bridge);
    sendHello(handlers);

    const client = new FakeSocket();
    const cdp = bridge.attachCdpClientSocket(client);
    cdp.onMessage(
      JSON.stringify({ id: 1, method: "Target.setAutoAttach", params: { autoAttach: true } }),
    );
    await flush();
    const attached = client.frames().find((frame) => frame.method === "Target.attachedToTarget");
    expect(attached).toBeTruthy();
    const sessionId = (attached?.params as { sessionId: string })?.sessionId;

    cdp.onMessage(
      JSON.stringify({
        id: 2,
        sessionId,
        method: "Page.navigate",
        params: { url: "https://x.test" },
      }),
    );
    await flush();

    // The extension received a session-forwarded cdp command for tab 1.
    const forwarded = extSocket
      .frames()
      .find((frame) => frame.type === "cdp" && frame.method === "Page.navigate");
    expect(forwarded).toMatchObject({ tabId: 1, method: "Page.navigate" });
    const response = client.frames().find((frame) => frame.id === 2);
    expect(response?.result).toMatchObject({ ok: true });
  });

  it("multiplexes Playwright page CDP sessions over the shared tab attachment", async () => {
    const bridge = new ExtensionRelayBridge();
    const { socket: extSocket, handlers } = wireExtension(bridge);
    sendHello(handlers);

    const client = new FakeSocket();
    const cdp = bridge.attachCdpClientSocket(client);
    cdp.onMessage(
      JSON.stringify({ id: 1, method: "Target.setAutoAttach", params: { autoAttach: true } }),
    );
    await flush();
    cdp.onMessage(JSON.stringify({ id: 2, method: "Target.attachToBrowserTarget" }));
    await flush();
    const browserSessionId = (
      client.frames().find((frame) => frame.id === 2)?.result as { sessionId?: string }
    )?.sessionId;
    expect(browserSessionId).toBeTruthy();

    cdp.onMessage(
      JSON.stringify({
        id: 3,
        sessionId: browserSessionId,
        method: "Target.attachToTarget",
        params: { targetId: "agent-tab-bridge-target-1", flatten: true },
      }),
    );
    await flush();
    const pageSessionId = (
      client.frames().find((frame) => frame.id === 3)?.result as { sessionId?: string }
    )?.sessionId;
    expect(pageSessionId).toBeTruthy();
    expect(pageSessionId).not.toBe(browserSessionId);

    cdp.onMessage(
      JSON.stringify({ id: 4, sessionId: pageSessionId, method: "Runtime.evaluate", params: {} }),
    );
    await flush();
    expect(
      extSocket
        .frames()
        .find((frame) => frame.type === "cdp" && frame.method === "Runtime.evaluate"),
    ).toMatchObject({ tabId: 1, method: "Runtime.evaluate" });
    expect(client.frames().find((frame) => frame.id === 4)?.result).toMatchObject({ ok: true });

    handlers.onMessage(
      JSON.stringify({
        type: "cdpEvent",
        tabId: 1,
        method: "Runtime.consoleAPICalled",
        params: { type: "log" },
      }),
    );
    await flush();
    expect(
      client
        .frames()
        .find(
          (frame) =>
            frame.sessionId === pageSessionId && frame.method === "Runtime.consoleAPICalled",
        ),
    ).toMatchObject({ params: { type: "log" } });

    const otherClient = new FakeSocket();
    const otherCdp = bridge.attachCdpClientSocket(otherClient);
    otherCdp.onMessage(
      JSON.stringify({
        id: 1,
        method: "Target.detachFromTarget",
        params: { sessionId: pageSessionId },
      }),
    );
    await flush();
    expect(otherClient.frames().find((frame) => frame.id === 1)?.error).toMatchObject({
      code: -32001,
    });

    cdp.onMessage(
      JSON.stringify({
        id: 5,
        sessionId: browserSessionId,
        method: "Target.detachFromTarget",
        params: { sessionId: pageSessionId },
      }),
    );
    await flush();
    expect(client.frames().find((frame) => frame.id === 5)?.result).toEqual({});
  });

  it("creates a tab inside the group and returns its synthetic target", async () => {
    const bridge = new ExtensionRelayBridge();
    const { socket, handlers } = wireExtension(bridge);
    sendHello(handlers);

    const client = new FakeSocket();
    const cdp = bridge.attachCdpClientSocket(client);
    cdp.onMessage(
      JSON.stringify({ id: 1, method: "Target.setAutoAttach", params: { autoAttach: true } }),
    );
    await flush();
    cdp.onMessage(
      JSON.stringify({ id: 2, method: "Target.createTarget", params: { url: "https://new.test" } }),
    );
    await flush();

    const response = client.frames().find((frame) => frame.id === 2);
    expect(response?.result).toMatchObject({ targetId: "agent-tab-bridge-target-999" });
    expect(socket.frames().find((frame) => frame.type === "createTab")).toMatchObject({
      url: "https://new.test",
      background: true,
      focus: false,
    });
  });

  it("preserves an explicit foreground Target.createTarget request", async () => {
    const bridge = new ExtensionRelayBridge();
    const { socket, handlers } = wireExtension(bridge);
    sendHello(handlers);

    const client = new FakeSocket();
    const cdp = bridge.attachCdpClientSocket(client);
    cdp.onMessage(
      JSON.stringify({
        id: 1,
        method: "Target.createTarget",
        params: { url: "https://foreground.test", background: false },
      }),
    );
    await flush();

    expect(client.frames().find((frame) => frame.id === 1)?.result).toMatchObject({
      targetId: "agent-tab-bridge-target-999",
    });
    expect(socket.frames().find((frame) => frame.type === "createTab")).toMatchObject({
      url: "https://foreground.test",
      background: false,
      focus: true,
    });
  });

  it.each([true, false])(
    "honors an explicit Target.createTarget focus=%s request",
    async (focus) => {
      const bridge = new ExtensionRelayBridge();
      const { socket, handlers } = wireExtension(bridge);
      sendHello(handlers);

      const client = new FakeSocket();
      const cdp = bridge.attachCdpClientSocket(client);
      cdp.onMessage(
        JSON.stringify({
          id: 1,
          method: "Target.createTarget",
          params: { url: "https://focused.test", focus },
        }),
      );
      await flush();

      expect(client.frames().find((frame) => frame.id === 1)?.result).toMatchObject({
        targetId: "agent-tab-bridge-target-999",
      });
      expect(socket.frames().find((frame) => frame.type === "createTab")).toMatchObject({
        url: "https://focused.test",
        background: false,
        focus,
      });
    },
  );

  it("emits Target.detachedFromTarget when a shared tab leaves the group", async () => {
    const bridge = new ExtensionRelayBridge();
    const { handlers } = wireExtension(bridge);
    sendHello(handlers);

    const client = new FakeSocket();
    const cdp = bridge.attachCdpClientSocket(client);
    cdp.onMessage(
      JSON.stringify({ id: 1, method: "Target.setAutoAttach", params: { autoAttach: true } }),
    );
    await flush();

    // Tab 1 removed from the shared set.
    handlers.onMessage(JSON.stringify({ type: "tabs", tabs: [] }));
    await flush();

    const detached = client.frames().find((frame) => frame.method === "Target.detachedFromTarget");
    expect(detached).toBeTruthy();
    expect(bridge.sharedTabs()).toHaveLength(0);
  });

  it("rejects isolated browser contexts (real profile only)", async () => {
    const bridge = new ExtensionRelayBridge();
    const { handlers } = wireExtension(bridge);
    sendHello(handlers);

    const client = new FakeSocket();
    const cdp = bridge.attachCdpClientSocket(client);
    cdp.onMessage(JSON.stringify({ id: 1, method: "Target.createBrowserContext" }));
    await flush();

    const response = client.frames().find((frame) => frame.id === 1);
    expect(response?.error).toBeTruthy();
  });

  it("fails pending commands when the extension disconnects", async () => {
    const bridge = new ExtensionRelayBridge();
    const { handlers } = wireExtension(bridge);
    sendHello(handlers);

    const client = new FakeSocket();
    const cdp = bridge.attachCdpClientSocket(client);
    cdp.onMessage(
      JSON.stringify({ id: 1, method: "Target.setAutoAttach", params: { autoAttach: true } }),
    );
    await flush();

    handlers.onClose();
    // A subsequent session command should surface a clean error, not hang.
    cdp.onMessage(JSON.stringify({ id: 2, sessionId: "session-no-longer-shared", method: "Page.reload" }));
    await flush();
    const response = client.frames().find((frame) => frame.id === 2);
    expect(response?.error).toBeTruthy();
    expect(bridge.extensionConnected).toBe(false);
  });

  it("treats a queued keepalive callback after disconnect as extension teardown", () => {
    const bridge = new ExtensionRelayBridge();
    const intervalSpy = vi.spyOn(globalThis, "setInterval");
    try {
      const { handlers } = wireExtension(bridge);
      sendHello(handlers);
      const callback = intervalSpy.mock.calls.at(-1)?.[0] as (() => void) | undefined;
      expect(callback).toBeTypeOf("function");

      handlers.onClose();
      expect(() => callback?.()).not.toThrow();
      expect(bridge.extensionConnected).toBe(false);
    } finally {
      intervalSpy.mockRestore();
    }
  });

  it("reports malformed CDP client JSON instead of leaving the client waiting", () => {
    const bridge = new ExtensionRelayBridge();
    const client = new FakeSocket();
    const cdp = bridge.attachCdpClientSocket(client);

    cdp.onMessage("{");

    expect(client.frames()).toEqual([
      { id: null, error: { code: -32700, message: "Parse error" } },
    ]);
  });

  it("reports invalid CDP client requests instead of leaving the client waiting", () => {
    const bridge = new ExtensionRelayBridge();
    const client = new FakeSocket();
    const cdp = bridge.attachCdpClientSocket(client);

    cdp.onMessage(JSON.stringify({ id: 7, sessionId: "session-1", params: {} }));

    expect(client.frames()).toEqual([
      {
        id: 7,
        sessionId: "session-1",
        error: { code: -32600, message: "Invalid request" },
      },
    ]);
  });

  it("reaps child sessions when a tab leaves the group (no stale routing)", async () => {
    const bridge = new ExtensionRelayBridge();
    const { handlers } = wireExtension(bridge);
    sendHello(handlers);

    const client = new FakeSocket();
    const cdp = bridge.attachCdpClientSocket(client);
    cdp.onMessage(
      JSON.stringify({ id: 1, method: "Target.setAutoAttach", params: { autoAttach: true } }),
    );
    await flush();

    // Extension reports a child (iframe) session for tab 1.
    handlers.onMessage(
      JSON.stringify({
        type: "cdpEvent",
        tabId: 1,
        sessionId: "child-abc",
        method: "Page.frameNavigated",
        params: {},
      }),
    );
    await flush();

    // Tab 1 loses the user's sharing consent.
    handlers.onMessage(JSON.stringify({ type: "tabs", tabs: [] }));
    await flush();

    // A command addressed to the now-stale child session must not route to a
    // reused tab; it should surface a clean "session not found" error.
    cdp.onMessage(JSON.stringify({ id: 2, sessionId: "child-abc", method: "Page.reload" }));
    await flush();
    const response = client.frames().find((frame) => frame.id === 2);
    expect(response?.error).toBeTruthy();
  });

  it.each([
    ["page navigation", "Page.navigate", { url: "https://next.example" }],
    ["script evaluation", "Runtime.evaluate", { expression: "document.title" }],
    ["DOM inspection", "DOM.getDocument", {}],
    ["input dispatch", "Input.dispatchKeyEvent", { type: "keyDown", key: "A" }],
    ["network observation", "Network.enable", {}],
    ["request interception", "Fetch.enable", {}],
    ["page emulation", "Emulation.setUserAgentOverride", { userAgent: "ATB test" }],
    ["page logging", "Log.enable", {}],
    ["page performance", "Performance.enable", {}],
    ["page debugging", "Debugger.enable", {}],
    ["CSS inspection", "CSS.enable", {}],
    ["accessibility inspection", "Accessibility.enable", {}],
  ])("forwards allowed %s commands only to the shared page", async (_label, method, params) => {
    expect(classifyCdpMethod(method, "page")).toBe(CdpMethodPolicy.Allow);
    const { client, cdp, extensionSocket, sessionId } = await attachSharedPageSession();

    cdp.onMessage(JSON.stringify({ id: 2, sessionId, method, params }));
    await flush();

    expect(
      extensionSocket
        .frames()
        .find((frame) => frame.type === "cdp" && frame.method === method),
    ).toMatchObject({ tabId: 1, method, params });
    expect(client.frames().find((frame) => frame.id === 2)).toMatchObject({
      sessionId,
      result: { ok: true, echoed: method },
    });
  });

  it("handles Browser.close locally without forwarding it to Chrome", async () => {
    expect(classifyCdpMethod("Browser.close", "browser")).toBe(CdpMethodPolicy.Allow);
    const bridge = new ExtensionRelayBridge();
    const { socket: extensionSocket, handlers } = wireExtension(bridge);
    sendHello(handlers);
    const client = new FakeSocket();
    const cdp = bridge.attachCdpClientSocket(client);

    cdp.onMessage(JSON.stringify({ id: 1, method: "Browser.close" }));
    await flush();

    expect(client.frames()).toEqual([{ id: 1, result: {} }]);
    expect(client.closed).toBe(true);
    expect(extensionSocket.frames().filter((frame) => frame.type === "cdp")).toHaveLength(0);
  });

  it.each([
    ["download behavior", "Browser.setDownloadBehavior"],
    ["permission grant", "Browser.grantPermissions"],
    ["permission reset", "Browser.resetPermissions"],
    ["unknown Browser method", "Browser.futureSensitiveCommand"],
    ["browser-context creation", "Target.createBrowserContext"],
    ["browser-context disposal", "Target.disposeBrowserContext"],
    ["target protocol exposure", "Target.exposeDevToolsProtocol"],
    ["unknown Target method", "Target.futureSensitiveCommand"],
    ["profile cookies", "Storage.getCookies"],
    ["profile cache", "CacheStorage.requestEntries"],
    ["service-worker registry", "ServiceWorker.enable"],
    ["unknown System method", "System.futureSensitiveCommand"],
    ["browser cookies through Network", "Network.getAllCookies"],
    ["browser cache through Network", "Network.clearBrowserCache"],
  ])("rejects %s with a stable policy error", async (_label, method) => {
    expect(classifyCdpMethod(method, "browser")).toBe(CdpMethodPolicy.Deny);
    const bridge = new ExtensionRelayBridge();
    const { socket: extensionSocket, handlers } = wireExtension(bridge);
    sendHello(handlers);
    const client = new FakeSocket();
    const cdp = bridge.attachCdpClientSocket(client);

    cdp.onMessage(JSON.stringify({ id: 1, method }));
    await flush();

    expect(client.frames()).toEqual([
      {
        id: 1,
        error: {
          code: CDP_METHOD_POLICY_ERROR_CODE,
          message: CDP_METHOD_POLICY_ERROR,
        },
      },
    ]);
    expect(client.closed).toBe(false);
    expect(extensionSocket.frames().filter((frame) => frame.type === "cdp")).toHaveLength(0);
  });

  it.each([
    ["page download behavior", "Page.setDownloadBehavior"],
    ["local file path inspection", "DOM.getFileInfo"],
    ["profile cookies through Network", "Network.getCookies"],
    ["profile cookies set through Network", "Network.setCookies"],
    ["global certificate override", "Security.setIgnoreCertificateErrors"],
    ["unreviewed Tethering domain", "Tethering.bind"],
    ["unreviewed Autofill domain", "Autofill.trigger"],
    ["unreviewed FedCm domain", "FedCm.enable"],
    ["unreviewed WebAuthn domain", "WebAuthn.enable"],
    ["unknown new domain", "FutureCdpDomain.doThing"],
  ])("denies %s from a shared page session before forwarding", async (_label, method) => {
    expect(classifyCdpMethod(method, "page")).toBe(CdpMethodPolicy.Deny);
    const { client, cdp, extensionSocket, sessionId } = await attachSharedPageSession();

    cdp.onMessage(JSON.stringify({ id: 2, sessionId, method }));
    await flush();

    expect(client.frames().find((frame) => frame.id === 2)).toEqual({
      id: 2,
      sessionId,
      error: {
        code: CDP_METHOD_POLICY_ERROR_CODE,
        message: CDP_METHOD_POLICY_ERROR,
      },
    });
    expect(extensionSocket.frames().filter((frame) => frame.type === "cdp")).toHaveLength(0);
  });

  it("applies the policy to a flattened child session before forwarding", async () => {
    const { client, cdp, extensionSocket, handlers } = await attachSharedPageSession();
    handlers.onMessage(
      JSON.stringify({
        type: "cdpEvent",
        tabId: 1,
        sessionId: "child-iframe",
        method: "Runtime.executionContextCreated",
        params: {},
      }),
    );
    await flush();

    cdp.onMessage(
      JSON.stringify({
        id: 2,
        sessionId: "child-iframe",
        method: "Browser.grantPermissions",
      }),
    );
    await flush();

    expect(client.frames().find((frame) => frame.id === 2)).toEqual({
      id: 2,
      sessionId: "child-iframe",
      error: {
        code: CDP_METHOD_POLICY_ERROR_CODE,
        message: CDP_METHOD_POLICY_ERROR,
      },
    });
    expect(extensionSocket.frames().filter((frame) => frame.type === "cdp")).toHaveLength(0);
  });


  it("requires a hello frame before other extension messages", () => {
    const bridge = new ExtensionRelayBridge();
    const socket = new FakeSocket();
    const handlers = bridge.attachExtensionSocket(socket);
    handlers.onMessage(JSON.stringify({ type: "tabs", tabs: [] }));
    expect(socket.closed).toBe(true);
    expect(bridge.extensionConnected).toBe(false);
  });
});

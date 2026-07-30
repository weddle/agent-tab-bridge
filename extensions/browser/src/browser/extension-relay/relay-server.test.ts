import http from "node:http";
import { afterEach, describe, expect, it } from "vitest";
import WebSocket, { type RawData } from "ws";
import { buildRelayWsProtocols } from "../../../chrome-extension/modules/relay-core.js";
import {
  EXTENSION_RELAY_EXTENSION_ORIGIN,
  startAgentTabRelay,
  type AgentTabRelayHandle,
} from "./relay-server.js";

type JsonFrame = Record<string, unknown>;
function isJsonFrame(value: unknown): value is JsonFrame {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}


const handles: AgentTabRelayHandle[] = [];

async function start(extensionToken = "test-extension-token"): Promise<AgentTabRelayHandle> {
  const handle = await startAgentTabRelay({ extensionToken });
  handles.push(handle);
  return handle;
}

function httpGet(
  port: number,
  path: string,
  headers: Record<string, string> = {},
): Promise<{ status: number; body: string }> {
  const { promise, resolve, reject } =
    Promise.withResolvers<{ status: number; body: string }>();
  const request = http.get(
    {
      hostname: "127.0.0.1",
      port,
      path,
      headers,
    },
    (response) => {
      const chunks: Buffer[] = [];
      response.on("data", (chunk: Buffer) => chunks.push(chunk));
      response.on("end", () =>
        resolve({ status: response.statusCode ?? 0, body: Buffer.concat(chunks).toString("utf8") }),
      );
    },
  );
  request.on("error", reject);
  return promise;
}

function upgradeStatus(
  port: number,
  path: string,
  headers: Record<string, string> = {},
): Promise<number> {
  const { promise, resolve, reject } = Promise.withResolvers<number>();
  const request = http.request({ hostname: "127.0.0.1", port, path, headers });
  request.once("upgrade", (response, socket) => {
    socket.destroy();
    resolve(response.statusCode ?? 0);
  });
  request.once("response", (response) => {
    response.resume();
    resolve(response.statusCode ?? 0);
  });
  request.once("error", reject);
  request.end();
  return promise;
}

function openSocket(
  url: string,
  protocols?: string[],
  headers: Record<string, string> = {},
): Promise<WebSocket> {
  const { promise, resolve, reject } = Promise.withResolvers<WebSocket>();
  const socket = new WebSocket(url, protocols, { headers });
  socket.once("open", () => resolve(socket));
  socket.once("error", reject);
  return promise;
}

function nextFrame(socket: WebSocket, predicate: (frame: JsonFrame) => boolean): Promise<JsonFrame> {
  const { promise, resolve } = Promise.withResolvers<JsonFrame>();
  const onMessage = (raw: RawData) => {
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw.toString());
    } catch {
      return;
    }
    if (!isJsonFrame(parsed)) {
      return;
    }
    const frame = parsed;
    if (predicate(frame)) {
      socket.off("message", onMessage);
      resolve(frame);
    }
  };
  socket.on("message", onMessage);
  return promise;
}

function hello(tabs: Array<Record<string, unknown>>) {
  return {
    type: "hello",
    userAgent: "Mozilla/5.0 Brave/1.80.0",
    browserVersion: "Brave/1.80.0",
    extensionVersion: "1.0.0",
    tabs,
  };
}

async function connectExtension(
  handle: AgentTabRelayHandle,
  tabs: Array<Record<string, unknown>>,
  respondToDetach = true,
): Promise<WebSocket> {
  const pairing = new URL(handle.pairingUrl);
  pairing.hash = "";
  const extension = await openSocket(pairing.toString(), buildRelayWsProtocols(handle.extensionToken), {
    Origin: EXTENSION_RELAY_EXTENSION_ORIGIN,
  });
  extension.on("message", (raw) => {
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw.toString());
    } catch {
      return;
    }
    if (!isJsonFrame(parsed) || typeof parsed.type !== "string" || typeof parsed.seq !== "number") {
      return;
    }
    if (parsed.type === "attach" && typeof parsed.tabId === "number") {
      extension.send(
        JSON.stringify({
          type: "result",
          seq: parsed.seq,
          result: { targetId: `target-${parsed.tabId}` },
        }),
      );
      return;
    }
    if (
      (parsed.type === "detach" && !respondToDetach) ||
      !["detach", "activateTab", "closeTab"].includes(parsed.type)
    ) {
      return;
    }
    if (parsed.type === "detach" || parsed.type === "activateTab" || parsed.type === "closeTab") {
      extension.send(JSON.stringify({ type: "result", seq: parsed.seq, result: {} }));
    }
  });
  extension.send(JSON.stringify(hello(tabs)));
  return extension;
}

afterEach(async () => {
  for (const handle of handles.splice(0)) {
    await handle.close();
  }
});

describe("standalone Agent Tab Bridge relay", () => {
  it("requires the token for HTTP and WebSocket upgrades", async () => {
    const handle = await start();

    await expect(httpGet(handle.port, "/json/version")).resolves.toMatchObject({ status: 401 });
    await expect(httpGet(handle.port, "/json/version?token=wrong")).resolves.toMatchObject({
      status: 401,
    });
    await expect(
      upgradeStatus(handle.port, "/cdp", { Host: "127.0.0.1" }),
    ).resolves.toBe(401);
    await expect(
      upgradeStatus(handle.port, "/cdp?token=wrong", { Host: "127.0.0.1" }),
    ).resolves.toBe(401);
  });

  it("rejects foreign Host headers and extension origins", async () => {
    const handle = await start();

    await expect(
      httpGet(handle.port, `/json/version?token=${handle.cdpToken}`, { Host: "attacker.example" }),
    ).resolves.toMatchObject({ status: 403 });
    await expect(
      upgradeStatus(handle.port, `/extension?token=${handle.extensionToken}`, {
        Host: "127.0.0.1",
        Origin: "https://attacker.example",
        "Sec-WebSocket-Protocol": buildRelayWsProtocols(handle.extensionToken).join(", "),
        Connection: "Upgrade",
        Upgrade: "websocket",
      }),
    ).resolves.toBe(403);
  });

  it("publishes token-bearing discovery and only exposes consented tabs", async () => {
    const handle = await start();
    const extension = await connectExtension(handle, [
      { tabId: 7, url: "https://shared.example", title: "Shared", active: true },
    ]);

    const versionResponse = await httpGet(handle.port, `/json/version?token=${handle.cdpToken}`);
    expect(versionResponse.status).toBe(200);
    expect(JSON.parse(versionResponse.body)).toMatchObject({
      webSocketDebuggerUrl: handle.cdpUrl,
    });

    const tabsResponse = await httpGet(handle.port, `/json?token=${handle.cdpToken}`);
    expect(JSON.parse(tabsResponse.body)).toEqual([
      { tabId: 7, url: "https://shared.example", title: "Shared", active: true },
    ]);
    expect(handle.extensionToken).not.toBe(handle.cdpToken);
    expect(handle.pairingUrl).toBe(
      `ws://127.0.0.1:${handle.port}/extension#${handle.extensionToken}`,
    );
    expect(handle.cdpUrl).toBe(`ws://127.0.0.1:${handle.port}/cdp?token=${handle.cdpToken}`);

    extension.close();
  });

  it("attaches only a shared tab, then detaches and removes it when consent is revoked", async () => {
    const handle = await start();
    const extension = await connectExtension(handle, [
      { tabId: 7, url: "https://shared.example", title: "Shared", active: true },
    ]);
    const cdp = await openSocket(handle.cdpUrl);

    const attachedPromise = nextFrame(cdp, (frame) => frame.method === "Target.attachedToTarget");
    cdp.send(JSON.stringify({ id: 1, method: "Target.setAutoAttach", params: { autoAttach: true } }));
    const attached = await attachedPromise;
    expect(attached).toMatchObject({
      params: { targetInfo: { targetId: "target-7" } },
    });

    const deniedPromise = nextFrame(cdp, (frame) => frame.id === 2);
    cdp.send(
      JSON.stringify({
        id: 2,
        method: "Target.attachToTarget",
        params: { targetId: "target-999", flatten: true },
      }),
    );
    expect(await deniedPromise).toMatchObject({ id: 2, error: expect.any(Object) });

    const detachedPromise = nextFrame(cdp, (frame) => frame.method === "Target.detachedFromTarget");
    extension.send(JSON.stringify({ type: "tabs", tabs: [] }));
    expect(await detachedPromise).toMatchObject({ method: "Target.detachedFromTarget" });
    await expect(httpGet(handle.port, `/json?token=${handle.cdpToken}`)).resolves.toMatchObject({
      status: 200,
      body: "[]",
    });

    cdp.close();
    extension.close();
  });

  it("cleans all relay resources when HTTP listen fails", async () => {
    const first = await start();
    await expect(
      startAgentTabRelay({ port: first.port, extensionToken: "collision-extension-token" }),
    ).rejects.toBeTruthy();

    await first.close();
    handles.splice(handles.indexOf(first), 1);
    const replacement = await start();
    await replacement.close();
    handles.splice(handles.indexOf(replacement), 1);
  });

  it("withdraws CDP clients before waiting for an unresponsive extension", async () => {
    const handle = await start();
    const extension = await connectExtension(
      handle,
      [{ tabId: 7, url: "https://shared.example", title: "Shared", active: true }],
      false,
    );
    const forwarded: JsonFrame[] = [];
    extension.on("message", (raw) => {
      try {
        const frame = JSON.parse(raw.toString()) as unknown;
        if (isJsonFrame(frame) && frame.type === "cdp") {
          forwarded.push(frame);
        }
      } catch {
        // Ignore non-JSON frames in this diagnostic listener.
      }
    });
    const cdp = await openSocket(handle.cdpUrl);
    const attached = nextFrame(cdp, (frame) => frame.method === "Target.attachedToTarget");
    cdp.send(JSON.stringify({ id: 1, method: "Target.setAutoAttach", params: { autoAttach: true } }));
    await attached;
    const detachCommand = nextFrame(extension, (frame) => frame.type === "detach");
    const closing = handle.close();
    await detachCommand;
    try {
      cdp.send(JSON.stringify({ id: 2, method: "Page.reload" }));
    } catch {
      // The bridge may have already closed the client socket synchronously.
    }
    await closing;
    expect(forwarded).toEqual([]);
    expect(cdp.readyState).toBe(WebSocket.CLOSED);
  });

  it("detaches shared tabs and closes sockets and listener", async () => {
    const handle = await start();
    const extension = await connectExtension(handle, [
      { tabId: 7, url: "https://shared.example", title: "Shared", active: true },
    ]);
    const cdp = await openSocket(handle.cdpUrl);
    const attached = nextFrame(cdp, (frame) => frame.method === "Target.attachedToTarget");
    cdp.send(
      JSON.stringify({ id: 1, method: "Target.setAutoAttach", params: { autoAttach: true } }),
    );
    await attached;

    const detachCommand = nextFrame(extension, (frame) => frame.type === "detach");
    const extensionClosedGate = Promise.withResolvers<void>();
    extension.once("close", extensionClosedGate.resolve);
    const cdpClosedGate = Promise.withResolvers<void>();
    cdp.once("close", cdpClosedGate.resolve);

    await Promise.all([handle.close(), handle.close()]);
    handles.splice(handles.indexOf(handle), 1);
    await expect(detachCommand).resolves.toMatchObject({ type: "detach", tabId: 7 });
    await Promise.all([extensionClosedGate.promise, cdpClosedGate.promise]);
    expect(handle.bridge.sharedTabs()).toEqual([]);
    await expect(httpGet(handle.port, `/json/version?token=${handle.cdpToken}`)).rejects.toBeTruthy();
  });
});

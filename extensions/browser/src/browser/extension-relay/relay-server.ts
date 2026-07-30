/**
 * Standalone loopback relay between the Agent Tab Bridge extension and CDP.
 *
 * The relay has no application-runtime dependencies. It binds only to
 * 127.0.0.1, creates an ephemeral capability by default, and authenticates
 * every HTTP request and WebSocket upgrade before exposing discovery or CDP.
 */
import crypto from "node:crypto";
import http, { type IncomingMessage, type Server } from "node:http";
import type { Duplex } from "node:stream";
import { WebSocketServer, type RawData, type WebSocket } from "ws";
import { ExtensionRelayBridge } from "./relay-bridge.js";

export const EXTENSION_RELAY_PROTOCOL = "agent-tab-bridge-relay";
export const EXTENSION_RELAY_TOKEN_PROTOCOL_PREFIX = "agent-tab-bridge-token.";

/** Maximum size accepted for a single extension or CDP WebSocket frame. */
export const EXTENSION_RELAY_MAX_PAYLOAD_BYTES = 64 * 1024 * 1024;

export type AgentTabRelayHandle = {
  port: number;
  token: string;
  pairingUrl: string;
  cdpUrl: string;
  bridge: ExtensionRelayBridge;
  close: () => Promise<void>;
};

function firstHeader(value: string | string[] | undefined): string {
  return Array.isArray(value) ? (value[0] ?? "") : (value ?? "");
}

/** Extract a relay token carried by the extension's WebSocket subprotocol list. */
export function requestExtensionProtocolToken(req: IncomingMessage): string {
  const protocols = firstHeader(req.headers["sec-websocket-protocol"])
    .split(",")
    .map((value) => value.trim());
  if (!protocols.includes(EXTENSION_RELAY_PROTOCOL)) {
    return "";
  }
  const tokenProtocol = protocols.find((value) =>
    value.startsWith(EXTENSION_RELAY_TOKEN_PROTOCOL_PREFIX),
  );
  return tokenProtocol?.slice(EXTENSION_RELAY_TOKEN_PROTOCOL_PREFIX.length) ?? "";
}

function requestToken(req: IncomingMessage): string {
  const auth = firstHeader(req.headers.authorization);
  if (auth.startsWith("Bearer ")) {
    return auth.slice("Bearer ".length).trim();
  }
  if (auth.startsWith("Basic ")) {
    const decoded = Buffer.from(auth.slice("Basic ".length), "base64").toString("utf8");
    const separator = decoded.indexOf(":");
    return separator >= 0 ? decoded.slice(separator + 1) : decoded;
  }
  const protocolToken = requestExtensionProtocolToken(req);
  if (protocolToken) {
    return protocolToken;
  }
  try {
    const url = new URL(req.url ?? "/", "http://127.0.0.1");
    return url.searchParams.get("token") ?? "";
  } catch {
    return "";
  }
}

/** Compare the fixed-length capability without an ordinary string equality. */
function hasValidToken(expected: string, candidate: string): boolean {
  const expectedBytes = Buffer.from(expected, "utf8");
  const candidateBytes = Buffer.from(candidate, "utf8");
  const padded = Buffer.alloc(expectedBytes.length);
  candidateBytes.copy(padded, 0, 0, Math.min(candidateBytes.length, padded.length));
  const equal = crypto.timingSafeEqual(expectedBytes, padded);
  return candidateBytes.length === expectedBytes.length && equal;
}

function isAuthorized(req: IncomingMessage, token: string): boolean {
  return hasValidToken(token, requestToken(req));
}

/** Require a real chrome-extension:// origin for the extension endpoint. */
export function isAllowedExtensionOrigin(req: IncomingMessage): boolean {
  const origin = firstHeader(req.headers.origin).trim();
  if (!origin) {
    return false;
  }
  try {
    const parsed = new URL(origin);
    return (
      parsed.protocol === "chrome-extension:" &&
      parsed.hostname.length > 0 &&
      parsed.username === "" &&
      parsed.password === "" &&
      parsed.port === "" &&
      (parsed.pathname === "" || parsed.pathname === "/") &&
      parsed.search === "" &&
      parsed.hash === ""
    );
  } catch {
    return false;
  }
}

/** The relay accepts only the exact IPv4 loopback Host spelling. */
function hasLoopbackHostHeader(req: IncomingMessage): boolean {
  const host = firstHeader(req.headers.host).trim();
  const match = /^127\.0\.0\.1(?::(\d{1,5}))?$/.exec(host);
  return match !== null && (match[1] === undefined || Number(match[1]) <= 65_535);
}

function destroySocket(socket: Duplex, response: string): void {
  try {
    socket.write(response);
  } finally {
    socket.destroy();
  }
}

function rawDataToString(data: RawData): string {
  if (typeof data === "string") {
    return data;
  }
  if (data instanceof ArrayBuffer) {
    return Buffer.from(data).toString("utf8");
  }
  if (Array.isArray(data)) {
    return Buffer.concat(data).toString("utf8");
  }
  return data.toString("utf8");
}

/** Wire an accepted extension WebSocket to a bridge. */
export function attachExtensionWebSocket(bridge: ExtensionRelayBridge, ws: WebSocket): void {
  bindSocket(ws, bridge.attachExtensionSocket(ws));
}

function bindSocket(
  ws: WebSocket,
  handlers: { onMessage: (raw: string) => void; onClose: () => void },
): void {
  ws.on("message", (data) => {
    const raw = rawDataToString(data);
    if (Buffer.byteLength(raw, "utf8") > EXTENSION_RELAY_MAX_PAYLOAD_BYTES) {
      ws.close(1009, "relay frame exceeds maximum size");
      return;
    }
    handlers.onMessage(raw);
  });
  ws.on("close", handlers.onClose);
  ws.on("error", () => {});
}

/** Start one ephemeral Agent Tab Bridge relay. */
export async function startAgentTabRelay(
  params: { port?: number; token?: string } = {},
): Promise<AgentTabRelayHandle> {
  const requestedPort = params.port ?? 0;
  if (!Number.isInteger(requestedPort) || requestedPort < 0 || requestedPort > 65_535) {
    throw new RangeError("relay port must be an integer between 0 and 65535");
  }
  const token = params.token ?? crypto.randomBytes(32).toString("hex");
  if (token.length === 0) {
    throw new Error("relay token must not be empty");
  }

  const bridge = new ExtensionRelayBridge();
  const wss = new WebSocketServer({
    noServer: true,
    maxPayload: EXTENSION_RELAY_MAX_PAYLOAD_BYTES,
  });

  let serverPort = requestedPort;
  let server: Server;
  const resolvedPort = () => {
    const address = server.address();
    return typeof address === "object" && address ? address.port : serverPort;
  };

  server = http.createServer((req, res) => {
    if (!hasLoopbackHostHeader(req)) {
      res.writeHead(403).end("Forbidden");
      return;
    }
    if (!isAuthorized(req, token)) {
      res.writeHead(401, { "WWW-Authenticate": 'Bearer realm="agent-tab-bridge-relay"' });
      res.end("Unauthorized");
      return;
    }

    const path = (req.url ?? "/").split("?", 1)[0];
    if (req.method === "GET" && (path === "/json/version" || path === "/json/version/")) {
      if (!bridge.extensionConnected) {
        res.writeHead(503, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Agent Tab Bridge extension is not connected" }));
        return;
      }
      const identity = bridge.identity;
      const cdpUrl = `ws://127.0.0.1:${resolvedPort()}/cdp?token=${encodeURIComponent(token)}`;
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          Browser: identity?.browserVersion ?? "Brave/unknown",
          "Protocol-Version": "1.3",
          "User-Agent": identity?.userAgent ?? "unknown",
          webSocketDebuggerUrl: cdpUrl,
        }),
      );
      return;
    }
    if (req.method === "GET" && (path === "/json" || path === "/json/list")) {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(bridge.sharedTabs()));
      return;
    }
    if (path === "/extension") {
      if (!isAllowedExtensionOrigin(req)) {
        res.writeHead(403).end("Forbidden");
        return;
      }
      res.writeHead(426, { Upgrade: "websocket" }).end("Upgrade Required");
      return;
    }
    if (path === "/cdp") {
      res.writeHead(426, { Upgrade: "websocket" }).end("Upgrade Required");
      return;
    }
    res.writeHead(404).end("Not found");
  });

  server.on("upgrade", (req, socket, head) => {
    const path = (req.url ?? "/").split("?", 1)[0];
    if (!hasLoopbackHostHeader(req)) {
      destroySocket(socket, "HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n");
      return;
    }
    if (!isAuthorized(req, token)) {
      destroySocket(socket, "HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n");
      return;
    }
    if (path === "/extension") {
      if (!isAllowedExtensionOrigin(req) || !requestExtensionProtocolToken(req)) {
        destroySocket(socket, "HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n");
        return;
      }
      wss.handleUpgrade(req, socket, head, (ws) => {
        attachExtensionWebSocket(bridge, ws);
      });
      return;
    }
    if (path === "/cdp") {
      wss.handleUpgrade(req, socket, head, (ws) => {
        bindSocket(ws, bridge.attachCdpClientSocket(ws));
      });
      return;
    }
    destroySocket(socket, "HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n");
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(requestedPort, "127.0.0.1", () => {
      serverPort = resolvedPort();
      resolve();
    });
  });

  const port = resolvedPort();
  const encodedToken = encodeURIComponent(token);
  let closePromise: Promise<void> | null = null;
  const close = async (): Promise<void> => {
    if (closePromise) {
      return closePromise;
    }
    closePromise = (async () => {
      await bridge.dispose();
      for (const client of wss.clients) {
        client.terminate();
      }
      await new Promise<void>((resolve) => {
        try {
          wss.close(() => resolve());
        } catch {
          resolve();
        }
      });
      await new Promise<void>((resolve) => {
        try {
          server.close(() => resolve());
        } catch {
          resolve();
        }
      });
    })();
    return closePromise;
  };

  return {
    port,
    token,
    pairingUrl: `ws://127.0.0.1:${port}/extension#${encodedToken}`,
    cdpUrl: `ws://127.0.0.1:${port}/cdp?token=${encodedToken}`,
    bridge,
    close,
  };
}

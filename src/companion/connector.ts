import { createServer, type Server, type Socket } from "node:net";
import type { HubRouteConnection, HubRouteStream } from "./pairing/routes.js";
import type { RoutedBrokerAddress } from "../hub/routing.js";
import { createRoutedBrokerClient } from "./broker-client.js";
import { initiateChannel } from "./channel/index.js";
import { routedChannelContext } from "./channel/context.js";
import { SecureChannelTransportAdapter, connectTransports } from "./transport-adapter.js";

export interface ConnectorProfile {
  name: string;
  principalId: string;
  publicKeySpki: string;
  privateKeyPkcs8: string;
}
export interface HarnessConnectorOptions {
  routes: HubRouteConnection;
  hubId: string;
  address: RoutedBrokerAddress;
  profile: ConnectorProfile;
  targetPublicKeySpki: string;
  host?: string;
  port?: number;
}
export interface HarnessConnectorHandle {
  readonly cdpUrl: string;
  readonly remoteCdpUrl: string;
  readonly port: number;
  close(): Promise<void>;
}

function loopbackCdpUrl(value: unknown): URL {
  if (typeof value !== "string") throw new Error("remote broker did not return a CDP URL");
  let parsed: URL;
  try { parsed = new URL(value); } catch { throw new Error("remote broker returned an invalid CDP URL"); }
  if (parsed.protocol !== "ws:" || (parsed.hostname !== "127.0.0.1" && parsed.hostname !== "localhost") || !parsed.port || parsed.username || parsed.password || parsed.hash) throw new Error("remote broker returned a non-loopback CDP URL");
  return parsed;
}

function channelMessage(type: string, value: unknown): Buffer { return Buffer.from(JSON.stringify({ type, value }), "utf8"); }

/** Connector for an approved routed session. Broker discovery and CDP bytes use separate opaque route streams. */
export class HarnessConnector {
  constructor(private readonly options: HarnessConnectorOptions) {}

  async start(): Promise<HarnessConnectorHandle> {
    const brokerStream = this.options.routes.open(this.options.address);
    const route = { hubId: this.options.hubId, routeId: brokerStream.routeId, streamId: brokerStream.streamId, address: this.options.address };
    const broker = await createRoutedBrokerClient({ stream: brokerStream, profile: this.options.profile, route, targetPublicKeySpki: this.options.targetPublicKeySpki });
    let remoteCdpUrl: string;
    let sessionId: string;
    try {
      const result = await broker.request("sessionUrl", { stableSessionKey: this.options.address.stableSessionKey });
      const record = result && typeof result === "object" ? result as Record<string, unknown> : {};
      const nested = record.session && typeof record.session === "object" ? record.session as Record<string, unknown> : record;
      if (typeof nested.id !== "string") throw new Error("remote broker did not return a session ID");
      sessionId = nested.id;
      remoteCdpUrl = loopbackCdpUrl(record.cdpUrl ?? nested.cdpUrl).toString();
    } finally { await broker.close?.(); }
    const remote = new URL(remoteCdpUrl);
    const sockets = new Set<Socket>();
    const server = createServer((socket) => {
      sockets.add(socket);
      socket.once("close", () => sockets.delete(socket));
      void this.attachSocket(socket, remote, sessionId, remoteCdpUrl).catch(() => socket.destroy());
    });
    const host = this.options.host ?? "127.0.0.1";
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(this.options.port ?? 0, host, () => { server.off("error", reject); resolve(); });
    });
    const address = server.address();
    const port = address && typeof address === "object" ? address.port : 0;
    if (!port) { await this.closeServer(server, sockets); throw new Error("connector failed to bind a loopback port"); }
    const local = new URL(remoteCdpUrl);
    local.hostname = "127.0.0.1";
    local.port = String(port);
    return { cdpUrl: local.toString(), remoteCdpUrl, port, close: async () => await this.closeServer(server, sockets) };

  }
  private async attachSocket(socket: Socket, remote: URL, sessionId: string, cdpUrl: string): Promise<void> {
    const route = this.options.routes.open(this.options.address);
    const identity = { version: 1 as const, kind: "controller" as const, principalId: this.options.profile.principalId, publicKeySpki: this.options.profile.publicKeySpki, privateKeyPkcs8: this.options.profile.privateKeyPkcs8, createdAt: Date.now() };
    const initiated = initiateChannel({ identity, peerPublicKeySpki: this.options.targetPublicKeySpki, sessionId: this.options.address.stableSessionKey, context: routedChannelContext(this.options.address, route.routeId, route.streamId) });
    let handshake = true;
    let removePayload: (() => void) | undefined;
    const close = () => { removePayload?.(); route.close(); socket.destroy(); };
    const finish = (payload: Buffer): void => {
      if (!handshake) return;
      let message: Record<string, unknown>;
      try { message = JSON.parse(payload.toString("utf8")) as Record<string, unknown>; } catch { close(); return; }
      if (message.type !== "channelAccept" || !message.value || typeof message.value !== "object") { close(); return; }
      try {
        const completed = initiated.complete(message.value as never);
        route.send(channelMessage("channelConfirm", completed.confirm));
        handshake = false;
        removePayload?.();
        const secure = new SecureChannelTransportAdapter(completed.channel, (frame) => { route.send(frame); });
        removePayload = route.onPayload((frame) => secure.receive(frame));
        connectTransports(socket, secure);
      } catch { close(); }
    };
    removePayload = route.onPayload(finish);
    route.send(Buffer.from(JSON.stringify({ type: "relayTransport", port: Number(remote.port), profileName: this.options.profile.name, sessionId, cdpUrl }), "utf8"));
    route.send(channelMessage("channelHello", initiated.hello));
  }

  private async closeServer(server: Server, sockets: Set<Socket>): Promise<void> {
    for (const socket of sockets) socket.destroy();
    if (!server.listening) return;
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}

export async function startHarnessConnector(options: HarnessConnectorOptions): Promise<HarnessConnectorHandle> { return await new HarnessConnector(options).start(); }

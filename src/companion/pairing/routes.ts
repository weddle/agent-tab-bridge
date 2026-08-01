import { randomUUID } from "node:crypto";
import { Duplex } from "node:stream";
import type { TLSSocket } from "node:tls";
import { encodeHubFrame, HubFrameDecoder } from "../../hub/framing.js";
import { decodeOpaqueRoutePayload, encodeHubOpaqueRoute, encodeOpaqueRoutePayload, parseHubOpaqueRoute, type RoutedBrokerAddress } from "../../hub/routing.js";

export type HubRouteHandler = (stream: HubRouteStream, address: RoutedBrokerAddress) => void | Promise<void>;

/** An endpoint-terminated opaque route. Payload bytes are never interpreted by the hub. */
export class HubRouteStream {
  private readonly listeners = new Set<(payload: Buffer) => void>();
  private readonly closeListeners = new Set<() => void>();
  private closed = false;
  constructor(private readonly connection: HubRouteConnection, readonly address: RoutedBrokerAddress, readonly routeId: string, readonly streamId: string, private readonly direction: "request" | "response") { }
  send(payload: Uint8Array): void {
    if (this.closed) throw new Error("routed stream is closed");
    this.connection.send(this.direction, this.routeId, this.streamId, this.address, payload);
  }
  onPayload(listener: (payload: Buffer) => void): () => void { this.listeners.add(listener); return () => this.listeners.delete(listener); }
  onClose(listener: () => void): () => void { this.closeListeners.add(listener); return () => this.closeListeners.delete(listener); }
  get transport(): Duplex { return new RoutedBrokerTransport(this); }
  close(): void { this.finish(true); }
  closeFromPeer(): void { this.finish(false); }
  private finish(sendClose: boolean): void {
    if (this.closed) return;
    this.closed = true;
    if (sendClose) this.connection.closeStream(this);
    else this.connection.forget(this.routeId);
    this.listeners.clear();
    for (const listener of this.closeListeners) listener();
    this.closeListeners.clear();
  }
  receive(payload: Buffer): void { if (!this.closed) for (const listener of this.listeners) listener(payload); }
}

export class HubRouteConnection {
  private readonly decoder: HubFrameDecoder;
  private readonly streams = new Map<string, HubRouteStream>();
  private closed = false;
  constructor(private readonly socket: TLSSocket, private readonly onRequest: HubRouteHandler, maxFrameBytes?: number) {
    this.decoder = new HubFrameDecoder(maxFrameBytes);
    socket.on("data", this.onData);
    socket.once("close", () => this.close());
    socket.once("error", () => this.close());
  }
  get connectionSocket(): TLSSocket { return this.socket; }
  open(address: RoutedBrokerAddress): HubRouteStream {
    if (this.closed) throw new Error("hub route connection is closed");
    const stream = new HubRouteStream(this, structuredClone(address), randomUUID(), randomUUID(), "request");
    this.streams.set(stream.routeId, stream); return stream;
  }
  send(direction: "request" | "response" | "close", routeId: string, streamId: string, address: RoutedBrokerAddress, payload: Uint8Array): void {
    if (this.closed) throw new Error("hub route connection is closed");
    const frame = encodeHubOpaqueRoute({ type: "opaqueRoute", direction, routeId, streamId, address, payload: encodeOpaqueRoutePayload(payload) });
    this.socket.write(encodeHubFrame(frame, this.decoder.maxFrameBytes));
  }
  closeStream(stream: HubRouteStream): void {
    if (!this.closed) this.send("close", stream.routeId, stream.streamId, stream.address, Buffer.from([0]));
    this.forget(stream.routeId);
  }
  forget(routeId: string): void { this.streams.delete(routeId); }
  close(): void { if (this.closed) return; this.closed = true; this.socket.off("data", this.onData); for (const stream of [...this.streams.values()]) stream.closeFromPeer(); this.streams.clear(); }
  private readonly onData = (chunk: Buffer): void => {
    try {
      for (const frame of this.decoder.feed(chunk)) {
        const envelope = parseHubOpaqueRoute(frame);
        if (!envelope) continue;
        const existing = this.streams.get(envelope.routeId);
        if (envelope.direction === "close") {
          if (existing && existing.streamId === envelope.streamId) existing.closeFromPeer();
          continue;
        }
        if (envelope.direction === "request") {
          let stream = existing;
          if (!stream) {
            stream = new HubRouteStream(this, envelope.address, envelope.routeId, envelope.streamId, "response");
            this.streams.set(envelope.routeId, stream);
            void Promise.resolve(this.onRequest(stream, envelope.address)).catch(() => stream?.close());
          }
          stream.receive(decodeOpaqueRoutePayload(envelope));
        } else if (existing && existing.streamId === envelope.streamId) {
          existing.receive(decodeOpaqueRoutePayload(envelope));
        }
      }
    } catch { this.close(); }
  };
}

/** Adapts a routed stream to the broker client's newline-delimited transport. */
class RoutedBrokerTransport extends Duplex {
  private readonly unsubscribe: () => void;
  private readonly unsubscribeClose: () => void;
  constructor(private readonly stream: HubRouteStream) {
    super();
    this.unsubscribe = stream.onPayload((payload) => this.push(payload));
    this.unsubscribeClose = stream.onClose(() => { this.unsubscribe(); this.push(null); });
    queueMicrotask(() => this.emit("connect"));
  }
  _read(): void { }
  _write(chunk: Buffer, _encoding: BufferEncoding, callback: (error?: Error | null) => void): void { try { this.stream.send(chunk); callback(); } catch (error) { callback(error instanceof Error ? error : new Error(String(error))); } }
  _final(callback: (error?: Error | null) => void): void { this.unsubscribe(); this.unsubscribeClose(); this.stream.close(); this.push(null); callback(); }
}

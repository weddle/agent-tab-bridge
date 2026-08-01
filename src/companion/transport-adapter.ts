import { Duplex } from "node:stream";
import type { HubRouteStream } from "./pairing/routes.js";
import type { SecureSessionChannel } from "./channel/index.js";

/** Byte transport over a hub route. The route carries opaque bytes and owns close propagation. */
export class RoutedTransportAdapter extends Duplex {
  private readonly removePayload: () => void;
  private readonly removeClose: () => void;
  private terminated = false;

  constructor(readonly route: HubRouteStream) {
    super();
    this.removePayload = route.onPayload((payload) => { if (!this.terminated) this.push(payload); });
    this.removeClose = route.onClose(() => { if (!this.terminated) { this.terminated = true; this.push(null); } });
  }

  _read(): void {}

  _write(chunk: Buffer, _encoding: BufferEncoding, callback: (error?: Error | null) => void): void {
    if (this.terminated) { callback(new Error("routed transport is closed")); return; }
    try {
      const writable = this.route.send(chunk);
      if (writable) callback();
      else this.route.connectionSocket.once("drain", callback);
    } catch (error) { callback(error instanceof Error ? error : new Error(String(error))); }
  }

  _final(callback: (error?: Error | null) => void): void {
    this.removePayload(); this.removeClose();
    try { this.route.close(); callback(); } catch (error) { callback(error instanceof Error ? error : new Error(String(error))); }
  }

  _destroy(error: Error | null, callback: (error?: Error | null) => void): void {
    this.terminated = true;
    this.removePayload(); this.removeClose();
    try { this.route.close(); } catch {}
    callback(error);
  }
}

/** Duplex adapter for WP10: every write becomes one or more authenticated frames. */
export class SecureChannelTransportAdapter extends Duplex {
  private terminated = false;
  constructor(readonly channel: SecureSessionChannel, private readonly sendFrame: (frame: Uint8Array) => void) { super(); }
  _read(): void {}
  _write(chunk: Buffer, _encoding: BufferEncoding, callback: (error?: Error | null) => void): void {
    if (this.terminated) { callback(new Error("secure channel is closed")); return; }
    try { for (const frame of this.channel.send(chunk)) this.sendFrame(frame); callback(); }
    catch (error) { this.terminated = true; this.channel.abort(); callback(error instanceof Error ? error : new Error(String(error))); }
  }
  receive(frame: Uint8Array): void {
    if (this.terminated) return;
    try {
      const receipt = this.channel.receive(frame);
      if (receipt.type === "data") this.push(Buffer.from(receipt.payload));
      else if (receipt.type === "closed") { this.terminated = true; this.push(null); }
    } catch (error) { this.destroy(error instanceof Error ? error : new Error(String(error))); }
  }
  _final(callback: (error?: Error | null) => void): void {
    if (this.terminated) { callback(); return; }
    try { for (const frame of this.channel.close()) this.sendFrame(frame); this.terminated = true; callback(); }
    catch (error) { this.terminated = true; this.channel.abort(); callback(error instanceof Error ? error : new Error(String(error))); }
  }
  _destroy(error: Error | null, callback: (error?: Error | null) => void): void { this.terminated = true; this.channel.abort(); callback(error); }
}

/** Connect two byte streams with cancellation and EOF/error propagation in both directions. */
export function connectTransports(left: Duplex, right: Duplex): () => void {
  let closed = false;
  const close = () => {
    if (closed) return;
    closed = true;
    left.destroy(); right.destroy();
  };
  left.on("data", (chunk: Buffer) => { if (!right.write(chunk)) left.pause(); });
  right.on("drain", () => left.resume());
  right.on("data", (chunk: Buffer) => { if (!left.write(chunk)) right.pause(); });
  left.on("drain", () => right.resume());
  left.once("end", close); right.once("end", close);
  left.once("close", close); right.once("close", close);
  left.once("error", close); right.once("error", close);
  return close;
}

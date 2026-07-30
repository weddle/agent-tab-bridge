import type { Writable } from "node:stream";
import { NATIVE_MAX_FRAME_BYTES, assertNativeMessage, type NativeMessage } from "./native-protocol.js";

export const NATIVE_FRAME_HEADER_BYTES = 4;
export class NativeFramingError extends Error {
  constructor(message: string) { super(message); this.name = "NativeFramingError"; }
}

/** Encode exactly one validated JSON message in Chrome's uint32 little-endian format. */
export function encodeNativeFrame(message: NativeMessage): Buffer {
  const validated = assertNativeMessage(message);
  const json = Buffer.from(JSON.stringify(validated), "utf8");
  if (json.length === 0 || json.length > NATIVE_MAX_FRAME_BYTES) throw new NativeFramingError("native message exceeds 1 MiB");
  const frame = Buffer.allocUnsafe(NATIVE_FRAME_HEADER_BYTES + json.length);
  frame.writeUInt32LE(json.length, 0);
  json.copy(frame, NATIVE_FRAME_HEADER_BYTES);
  return frame;
}

/** Incremental decoder supporting arbitrary fragmentation and coalesced frames. */
export class NativeMessageDecoder {
  private buffered = Buffer.alloc(0);
  private expectedLength: number | undefined;
  private failed = false;

  feed(chunk: Uint8Array): NativeMessage[] {
    if (this.failed) throw new NativeFramingError("decoder is closed after a framing error");
    if (chunk.byteLength === 0) return [];
    this.buffered = this.buffered.length === 0 ? Buffer.from(chunk) : Buffer.concat([this.buffered, Buffer.from(chunk)]);
    const messages: NativeMessage[] = [];
    try {
      while (true) {
        if (this.expectedLength === undefined) {
          if (this.buffered.length < NATIVE_FRAME_HEADER_BYTES) break;
          this.expectedLength = this.buffered.readUInt32LE(0);
          this.buffered = this.buffered.subarray(NATIVE_FRAME_HEADER_BYTES);
          if (this.expectedLength === 0 || this.expectedLength > NATIVE_MAX_FRAME_BYTES) throw new NativeFramingError("invalid native frame length");
        }
        if (this.buffered.length < this.expectedLength) break;
        const body = this.buffered.subarray(0, this.expectedLength);
        this.buffered = this.buffered.subarray(this.expectedLength);
        const message = assertNativeMessage(JSON.parse(body.toString("utf8")));
        messages.push(message);
        this.expectedLength = undefined;
      }
      return messages;
    } catch (error) {
      this.failed = true;
      if (error instanceof NativeFramingError) throw error;
      throw new NativeFramingError(`invalid native frame payload: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  /** Alias useful to stream adapters. */
  push(chunk: Uint8Array): NativeMessage[] { return this.feed(chunk); }
  /** Reject a stream ending in a partial header or body. */
  finish(): void {
    if (this.expectedLength !== undefined || this.buffered.length !== 0) throw new NativeFramingError("truncated native frame");
  }
  get pendingBytes(): number { return this.buffered.length + (this.expectedLength === undefined ? 0 : NATIVE_FRAME_HEADER_BYTES); }
}

/** Write one bounded frame and wait until the destination accepts it. */
export function writeNativeFrame(stream: Writable, message: NativeMessage): Promise<void> {
  const frame = encodeNativeFrame(message);
  const { promise, resolve, reject } = Promise.withResolvers<void>();
  let settled = false;
  const done = (error?: Error | null) => { if (settled) return; settled = true; error ? reject(error) : resolve(); };
  try {
    const accepted = stream.write(frame, (error?: Error | null) => done(error));
    if (!accepted) stream.once("drain", () => done());
  } catch (error) { done(error instanceof Error ? error : new Error(String(error))); }
  return promise;
}

import type { Writable } from "node:stream";

export const HUB_FRAME_HEADER_BYTES = 4;
export const HUB_MAX_FRAME_BYTES = 1024 * 1024;

export class HubFramingError extends Error {
  constructor(message: string) { super(message); this.name = "HubFramingError"; }
}

/** Length-prefix an opaque payload. The hub never interprets the payload bytes. */
export function encodeHubFrame(payload: Uint8Array, maxFrameBytes = HUB_MAX_FRAME_BYTES): Buffer {
  if (!(payload instanceof Uint8Array) || payload.byteLength === 0 || payload.byteLength > maxFrameBytes || payload.byteLength > 0xffffffff) throw new HubFramingError("hub frame exceeds configured limit");
  const frame = Buffer.allocUnsafe(HUB_FRAME_HEADER_BYTES + payload.byteLength);
  frame.writeUInt32BE(payload.byteLength, 0);
  Buffer.from(payload).copy(frame, HUB_FRAME_HEADER_BYTES);
  return frame;
}

/** Incremental decoder for bounded, length-prefixed opaque frames. */
export class HubFrameDecoder {
  private buffered = Buffer.alloc(0);
  private expectedLength: number | undefined;
  private failed = false;
  constructor(readonly maxFrameBytes = HUB_MAX_FRAME_BYTES) {
    if (!Number.isSafeInteger(maxFrameBytes) || maxFrameBytes < 1 || maxFrameBytes > 0xffffffff) throw new RangeError("invalid hub frame limit");
  }
  feed(chunk: Uint8Array): Buffer[] {
    if (this.failed) throw new HubFramingError("decoder is closed after a framing error");
    if (chunk.byteLength === 0) return [];
    this.buffered = this.buffered.length === 0 ? Buffer.from(chunk) : Buffer.concat([this.buffered, Buffer.from(chunk)]);
    const frames: Buffer[] = [];
    try {
      while (true) {
        if (this.expectedLength === undefined) {
          if (this.buffered.length < HUB_FRAME_HEADER_BYTES) break;
          this.expectedLength = this.buffered.readUInt32BE(0);
          this.buffered = this.buffered.subarray(HUB_FRAME_HEADER_BYTES);
          if (this.expectedLength === 0 || this.expectedLength > this.maxFrameBytes) throw new HubFramingError("invalid hub frame length");
        }
        if (this.buffered.length < this.expectedLength) break;
        frames.push(this.buffered.subarray(0, this.expectedLength));
        this.buffered = this.buffered.subarray(this.expectedLength);
        this.expectedLength = undefined;
      }
      return frames;
    } catch (error) {
      this.failed = true;
      if (error instanceof HubFramingError) throw error;
      throw new HubFramingError(`invalid hub frame: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  finish(): void {
    if (this.expectedLength !== undefined || this.buffered.length !== 0) throw new HubFramingError("truncated hub frame");
  }
  get pendingBytes(): number { return this.buffered.length + (this.expectedLength === undefined ? 0 : HUB_FRAME_HEADER_BYTES); }
}

export function writeHubFrame(stream: Writable, payload: Uint8Array, maxFrameBytes = HUB_MAX_FRAME_BYTES): void {
  stream.write(encodeHubFrame(payload, maxFrameBytes));
}

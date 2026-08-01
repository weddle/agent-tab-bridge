import { describe, expect, it } from "vitest";
import { acceptChannel, initiateChannel } from "./channel/index.js";
import { generateIdentity, type StoredIdentity } from "./identity.js";
import { SecureChannelTransportAdapter } from "./transport-adapter.js";

function identity(): StoredIdentity {
  const key = generateIdentity();
  return { version: 1, kind: "companion", principalId: key.principalId, publicKeySpki: key.publicKeySpki, privateKeyPkcs8: key.privateKeyPkcs8, createdAt: Date.now() };
}

describe("secure transport adapter", () => {
  it("encrypts bytes, delivers them, rejects replay, and aborts on transport teardown", async () => {
    const controller = identity();
    const edge = identity();
    const context = new TextEncoder().encode("routed-channel-test");
    const initiated = initiateChannel({ identity: controller, peerPublicKeySpki: edge.publicKeySpki, sessionId: "session-1", context });
    const accepted = acceptChannel({ identity: edge, peerPublicKeySpki: controller.publicKeySpki, sessionId: "session-1", context }, initiated.hello);
    const completed = initiated.complete(accepted.accept);
    const responder = accepted.complete(completed.confirm);
    const sent: Uint8Array[] = [];
    const left = new SecureChannelTransportAdapter(completed.channel, (frame) => sent.push(frame));
    const right = new SecureChannelTransportAdapter(responder, () => undefined);
    const received = new Promise<Buffer>((resolve) => right.once("data", (chunk: Buffer) => resolve(chunk)));
    await new Promise<void>((resolve, reject) => left.write(Buffer.from('{"method":"Page.navigate"}'), (error) => error ? reject(error) : resolve()));
    expect(sent).toHaveLength(1);
    expect(() => JSON.parse(Buffer.from(sent[0]!).toString("utf8"))).toThrow();
    right.receive(sent[0]!);
    await expect(received).resolves.toEqual(Buffer.from('{"method":"Page.navigate"}'));
    expect(() => responder.receive(sent[0]!)).toThrow(/replay/i);
    left.destroy();
    expect(completed.channel.state).toBe("failed");
    right.destroy();
  });
});

import { EventEmitter } from "node:events";
import type net from "node:net";
import { describe, expect, it } from "vitest";
import { createBrokerClient } from "./broker-client.js";

type FakeSocket = EventEmitter & {
  write(data: string, callback?: (error?: Error | null) => void): boolean;
  end(callback?: () => void): void;
};

function socketForToken(expectedToken: string) {
  const socket = new EventEmitter() as FakeSocket;
  const received: Array<Record<string, unknown>> = [];
  socket.write = (data, callback) => {
    const message = JSON.parse(data.trim()) as Record<string, unknown>;
    received.push(message);
    queueMicrotask(() => {
      if (message.type === "auth") {
        if (message.token === expectedToken) socket.emit("data", Buffer.from(JSON.stringify({ type: "authOk" }) + "\n"));
        else socket.emit("data", Buffer.from(JSON.stringify({ type: "error", error: { message: "unauthorized" } }) + "\n"));
      } else {
        socket.emit("data", Buffer.from(JSON.stringify({ id: message.id, ok: true, result: { accepted: true } }) + "\n"));
      }
    });
    callback?.();
    return true;
  };
  socket.end = (callback) => {
    callback?.();
    socket.emit("close");
  };
  queueMicrotask(() => socket.emit("connect"));
  return { socket, received };
}

describe("authenticated broker client boundary", () => {
  it("authenticates before the first command and parses NDJSON replies", async () => {
    const { socket, received } = socketForToken("secret-token");
    const client = createBrokerClient({ socketPath: "/tmp/atb.sock", token: "secret-token", socketFactory: () => socket as unknown as net.Socket });

    await expect(client.request("status")).resolves.toEqual({ accepted: true });
    expect(received).toEqual([
      { type: "auth", token: "secret-token" },
      { id: "1", command: "status" },
    ]);
    await client.close();
  });

  it("does not accept a command when broker authentication fails", async () => {
    const { socket, received } = socketForToken("secret-token");
    const client = createBrokerClient({ socketPath: "/tmp/atb.sock", token: "wrong-token", socketFactory: () => socket as unknown as net.Socket });

    await expect(client.request("openSession", { capabilities: ["cdp"] })).rejects.toThrow("unauthorized");
    expect(received).toEqual([{ type: "auth", token: "wrong-token" }]);
    await client.close();
  });
});

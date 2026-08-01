import { createServer, type Server } from "node:net";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { readLiveEndpoints, selectLiveEndpoint } from "./endpoint-registry.js";

const directories: string[] = [];
const endpointId = (char: string) => `sha256/${char.repeat(43)}`;
const servers: Server[] = [];
afterEach(async () => {
  await Promise.all(servers.splice(0).map(async (server) => await new Promise<void>((resolve) => server.close(() => resolve()))));
  await Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

async function listening(path: string) {
  const server = createServer((socket) => socket.destroy());
  await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(path, () => { server.off("error", reject); resolve(); }); });
  servers.push(server);
  return server;
}

async function registry(endpoints: unknown[]) {
  const directory = await mkdtemp(join(tmpdir(), "atb-registry-"));
  directories.push(directory);
  await writeFile(join(directory, "live-endpoints.json"), JSON.stringify({ version: 1, endpoints }));
  return directory;
}

describe("live endpoint registry", () => {
  it("filters dead sockets and selects by label or fingerprint", async () => {
    const directory = await mkdtemp(join(tmpdir(), "atb-registry-"));
    directories.push(directory);
    const livePath = join(directory, "live.sock");
    await listening(livePath);
    const live = { endpointId: endpointId("A"), label: "desk-brave", socketPath: livePath };
    const stale = { endpointId: endpointId("B"), label: "old-chrome", socketPath: join(directory, "gone.sock") };
    await writeFile(join(directory, "live-endpoints.json"), JSON.stringify({ version: 1, endpoints: [live, stale] }));
    await expect(readLiveEndpoints({ directory })).resolves.toEqual([live]);
    await expect(selectLiveEndpoint("desk-brave", { directory })).resolves.toEqual(live);
    await expect(selectLiveEndpoint(live.endpointId, { directory })).resolves.toEqual(live);
  });

  it("refuses to guess when two live endpoints exist and names the choices", async () => {
    const directory = await mkdtemp(join(tmpdir(), "atb-registry-"));
    directories.push(directory);
    const firstPath = join(directory, "first.sock");
    const secondPath = join(directory, "second.sock");
    await listening(firstPath);
    await listening(secondPath);
    await writeFile(join(directory, "live-endpoints.json"), JSON.stringify({ version: 1, endpoints: [
      { endpointId: endpointId("A"), label: "desk-brave", socketPath: firstPath },
      { endpointId: endpointId("B"), label: "desk-chrome", socketPath: secondPath },
    ] }));
    await expect(selectLiveEndpoint(undefined, { directory })).rejects.toThrow(/multiple browser endpoints.*desk-brave.*desk-chrome/);
  });

  it("treats a missing registry as no live endpoints", async () => {
    const directory = await registry([]);
    await rm(join(directory, "live-endpoints.json"));
    await expect(readLiveEndpoints({ directory })).resolves.toEqual([]);
  });
});

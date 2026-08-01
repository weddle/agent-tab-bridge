import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { createConnection, type Socket } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateIdentity, signHandshakeTranscript } from "./identity.js";
import { createBrokerClient } from "./broker-client.js";
import { writeNativeFrame, NativeMessageDecoder } from "./native-framing.js";
import { NATIVE_PROTOCOL_VERSION, type HostToExtensionMessage } from "./native-protocol.js";
import { CompanionStateStore } from "./state.js";
import { EdgeSupervisor, LIVE_ENDPOINT_REGISTRY_FILE, type SupervisorLifecycleEvent } from "./supervisor.js";

type LiveEndpoint = { endpointId: string; label: string; socketPath: string };

async function endpoints(directory: string): Promise<LiveEndpoint[]> {
  const registry = JSON.parse(await readFile(join(directory, LIVE_ENDPOINT_REGISTRY_FILE), "utf8")) as { version: number; endpoints?: LiveEndpoint[] };
  assert.equal(registry.version, 1);
  assert.ok(Array.isArray(registry.endpoints));
  return registry.endpoints;
}

function nativeEndpoint(socketPath: string, extensionId: string, extension = generateIdentity("controller")) {
  const socket = createConnection(socketPath);
  const messages: HostToExtensionMessage[] = [];
  const waiters: Array<() => void> = [];
  const decoder = new NativeMessageDecoder();
  socket.on("data", (chunk: Buffer) => {
    for (const message of decoder.feed(chunk) as HostToExtensionMessage[]) {
      messages.push(message);
      waiters.shift()?.();
    }
  });
  const connected = new Promise<void>((resolvePromise, reject) => { socket.once("connect", resolvePromise); socket.once("error", reject); });
  const next = async <T extends HostToExtensionMessage["type"]>(type: T): Promise<Extract<HostToExtensionMessage, { type: T }>> => {
    for (;;) {
      const index = messages.findIndex((message) => message.type === type);
      if (index >= 0) return messages.splice(index, 1)[0] as Extract<HostToExtensionMessage, { type: T }>;
      await new Promise<void>((resolvePromise) => waiters.push(resolvePromise));
    }
  };
  const authenticate = async (): Promise<void> => {
    await connected;
    const hello = { version: NATIVE_PROTOCOL_VERSION, type: "hello" as const, role: "extension" as const, extensionId, extensionPublicKey: extension.publicKeySpki, extensionNonce: Buffer.alloc(32, extensionId.length).toString("base64url") };
    await writeNativeFrame(socket, hello);
    const challenge = await next("helloChallenge");
    const transcript = { extensionId, extensionPublicKey: extension.publicKeySpki, extensionNonce: hello.extensionNonce, companionId: challenge.companionId, companionPublicKey: challenge.companionPublicKey, companionNonce: challenge.companionNonce };
    await writeNativeFrame(socket, { version: NATIVE_PROTOCOL_VERSION, type: "helloProof", role: "extension", ...transcript, signature: signHandshakeTranscript(extension.privateKeyPkcs8, transcript) });
    await next("trusted");
  };
  return { socket, authenticate, extension, next };
}
async function closeSocket(socket: Socket): Promise<void> {
  await new Promise<void>((resolvePromise) => { socket.once("close", resolvePromise); socket.end(); });
}

function relay() { return async () => ({ pairingUrl: "ws://127.0.0.1/extension#token", cdpUrl: "ws://127.0.0.1/cdp?token=token", close: async () => undefined }); }

async function approveSession(endpoint: ReturnType<typeof nativeEndpoint>) {
  const pending = await endpoint.next("sessionPending");
  const session = pending.session;
  await writeNativeFrame(endpoint.socket, { version: NATIVE_PROTOCOL_VERSION, type: "approveSession", sessionId: session.id, controllerPrincipalId: session.controllerPrincipalId, displayControllerName: session.displayControllerName, taskLabel: session.taskLabel, requestedCapabilities: [...session.requestedCapabilities], access: { ...session.access, tabIds: [...session.access.tabIds], domains: [...session.access.domains] }, expiresAt: session.expiresAt, route: session.route });
  await endpoint.next("sessionStarted");
  await writeNativeFrame(endpoint.socket, { version: NATIVE_PROTOCOL_VERSION, type: "relayReady", sessionId: session.id, relayUrl: "ws://127.0.0.1/extension#token" });
  return session;
}
function disconnections() {
  const seen = new Set<string>();
  const waiters = new Map<string, Array<() => void>>();
  return {
    observe: (event: SupervisorLifecycleEvent) => {
      if (event.type !== "endpointDisconnected") return;
      seen.add(event.endpointId);
      for (const resolvePromise of waiters.get(event.endpointId) ?? []) resolvePromise();
      waiters.delete(event.endpointId);
    },
    wait: async (endpointId: string): Promise<void> => {
      if (seen.has(endpointId)) return;
      await new Promise<void>((resolvePromise) => { const pending = waiters.get(endpointId) ?? []; pending.push(resolvePromise); waiters.set(endpointId, pending); });
    },
  };
}

async function multiplexAndTeardown(): Promise<void> {
  const directory = await mkdtemp(join(tmpdir(), "atb-supervisor-integration-"));
  const lifecycle = disconnections();
  let supervisor: EdgeSupervisor | undefined;
  try {
    supervisor = await new EdgeSupervisor({ directory, startRelay: relay(), onEvent: lifecycle.observe }).start();
    const first = nativeEndpoint(supervisor.sockets.controlSocketPath, "brave");
    await first.authenticate();
    const second = nativeEndpoint(supervisor.sockets.controlSocketPath, "chrome");
    await second.authenticate();
    const live = await endpoints(directory);
    assert.equal(live.length, 2);
    assert.equal((await stat(supervisor.sockets.controlSocketPath)).mode & 0o777, 0o600);
    await Promise.all(live.map(async ({ socketPath }) => assert.equal((await stat(socketPath)).mode & 0o777, 0o600)));
    const state = await new CompanionStateStore({ directory }).load();
    const sessions = await Promise.all(live.map(async (endpoint) => {
      const client = createBrokerClient({ socketPath: endpoint.socketPath, token: state.machine.brokerSecret });
      try {
        return await client.request("openSession", { taskLabel: endpoint.label, requestedCapabilities: ["cdp"], stableSessionKey: "same-key" }) as { session: { id: string } };
      } finally { await client.close(); }
    }));
    assert.notEqual(sessions[0]!.session.id, sessions[1]!.session.id);
    const firstDisconnected = lifecycle.wait(first.extension.principalId);
    await closeSocket(first.socket);
    await firstDisconnected;
    assert.equal((await endpoints(directory)).length, 1);
    const secondDisconnected = lifecycle.wait(second.extension.principalId);
    await closeSocket(second.socket);
    await secondDisconnected;
    await supervisor.closed;
    await assert.rejects(stat(supervisor.sockets.controlSocketPath));
    await assert.rejects(stat(supervisor.sockets.brokerSocketPath));
    await assert.rejects(stat(supervisor.sockets.registryPath));
  } finally {
    await supervisor?.close();
    await rm(directory, { recursive: true, force: true });
  }
}

async function survivesShimChurn(): Promise<void> {
  const directory = await mkdtemp(join(tmpdir(), "atb-supervisor-churn-"));
  const lifecycle = disconnections();
  let supervisor: EdgeSupervisor | undefined;
  try {
    supervisor = await new EdgeSupervisor({ directory, startRelay: relay(), onEvent: lifecycle.observe }).start();
    const healthy = nativeEndpoint(supervisor.sockets.controlSocketPath, "chrome");
    await healthy.authenticate();
    assert.equal((await endpoints(directory)).length, 1);
    const interrupted = nativeEndpoint(supervisor.sockets.controlSocketPath, "brave");
    await new Promise<void>((resolvePromise, reject) => { interrupted.socket.once("connect", resolvePromise); interrupted.socket.once("error", reject); });
    await writeNativeFrame(interrupted.socket, { version: NATIVE_PROTOCOL_VERSION, type: "hello", role: "extension", extensionId: "brave", extensionPublicKey: interrupted.extension.publicKeySpki, extensionNonce: Buffer.alloc(32, 1).toString("base64url") });
    await closeSocket(interrupted.socket);
    assert.equal((await endpoints(directory)).length, 1);
    const replacement = nativeEndpoint(supervisor.sockets.controlSocketPath, "brave");
    await replacement.authenticate();
    assert.equal((await endpoints(directory)).length, 2);
    const replacementDisconnected = lifecycle.wait(replacement.extension.principalId);
    await closeSocket(replacement.socket);
    await replacementDisconnected;
    const healthyDisconnected = lifecycle.wait(healthy.extension.principalId);
    await closeSocket(healthy.socket);
    await healthyDisconnected;
    await supervisor.closed;
  } finally {
    await supervisor?.close();
    await rm(directory, { recursive: true, force: true });
  }
}
async function resumesActiveSessionAfterSameEndpointReconnect(): Promise<void> {
  const directory = await mkdtemp(join(tmpdir(), "atb-supervisor-recovery-"));
  const lifecycle = disconnections();
  let supervisor: EdgeSupervisor | undefined;
  try {
    supervisor = await new EdgeSupervisor({ directory, startRelay: relay(), onEvent: lifecycle.observe }).start();
    const first = nativeEndpoint(supervisor.sockets.controlSocketPath, "chrome");
    await first.authenticate();
    const state = await new CompanionStateStore({ directory }).load();
    const client = createBrokerClient({ socketPath: (await endpoints(directory))[0]!.socketPath, token: state.machine.brokerSecret });
    let opened: { session: { id: string } };
    try {
      opened = await client.request("openSession", { taskLabel: "reconnect", requestedCapabilities: ["cdp"], stableSessionKey: "recovery-key" }) as { session: { id: string } };
    } finally {
      await client.close();
    }
    const active = await approveSession(first);
    assert.equal(active.id, opened.session.id);
    const disconnected = lifecycle.wait(first.extension.principalId);
    await closeSocket(first.socket);
    await disconnected;
    const restored = nativeEndpoint(supervisor.sockets.controlSocketPath, "chrome", first.extension);
    await restored.authenticate();
    const resuming = await restored.next("sessionResuming");
    assert.equal(resuming.session.id, active.id);
    assert.equal(resuming.session.state, "reconnecting");
    assert.equal(resuming.relayUrl, "ws://127.0.0.1/extension#token");
    await writeNativeFrame(restored.socket, { version: NATIVE_PROTOCOL_VERSION, type: "relayReady", sessionId: active.id, relayUrl: resuming.relayUrl });
    await writeNativeFrame(restored.socket, { version: NATIVE_PROTOCOL_VERSION, type: "revokeSession", sessionId: active.id, reason: "complete" });
    await restored.next("sessionStopped");
    const restoredDisconnected = lifecycle.wait(restored.extension.principalId);
    await closeSocket(restored.socket);
    await restoredDisconnected;
    await supervisor.closed;
  } finally {
    await supervisor?.close();
    await rm(directory, { recursive: true, force: true });
  }
}


export async function runSupervisorIntegration(): Promise<void> {
  await multiplexAndTeardown();
  await survivesShimChurn();
  await resumesActiveSessionAfterSameEndpointReconnect();
}

if (process.argv.includes("--atb-supervisor-integration")) {
  void runSupervisorIntegration().then(
    () => process.stdout.write("supervisor integration passed\n"),
    (error) => { process.stderr.write(`${error instanceof Error ? error.stack ?? error.message : String(error)}\n`); process.exitCode = 1; },
  );
}

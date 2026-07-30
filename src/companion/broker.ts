import { timingSafeEqual } from "node:crypto";
import { chmod, lstat, rm } from "node:fs/promises";
import { createConnection, createServer, type Server, type Socket } from "node:net";
import { join } from "node:path";
import { applicationSupportDirectory, type ApplicationSupportOptions } from "./state.js";
import { TaskSessionError, type TaskSession, type TaskSessionManager } from "./task-sessions.js";

export const BROKER_MAX_LINE_BYTES = 1024 * 1024;
export type BrokerCommand = "status" | "openSession" | "revokeSession";
export type BrokerAuthRequest = Readonly<{ type: "auth"; token: string }>;
export type BrokerCommandRequest = Readonly<{ id: string; command: BrokerCommand; taskLabel?: string; requestedCapabilities?: string[]; ttlMs?: number; sessionId?: string; reason?: string }>;
export type BrokerAuthOk = Readonly<{ type: "authOk" }>;
export type BrokerResponse = Readonly<{ id: string; ok: true; result: unknown }> | Readonly<{ id: string; ok: false; error: { code: string; message: string } }>;
export type BrokerEvent = Readonly<{ event: "pending" | "active" | "revoked" | "hostClosing"; sessionId?: string; session?: TaskSession; cdpUrl?: string; reason?: string }>;
export type BrokerServerOptions = Readonly<{ socketPath?: string; token: string; sessions: TaskSessionManager; isTrusted: () => boolean; controller: () => Readonly<{ principalId: string; displayName: string }> | null; status?: () => Record<string, unknown> }>;
export function defaultBrokerSocketPath(paths: ApplicationSupportOptions = {}): string { return join(applicationSupportDirectory(paths), "broker.sock"); }
const object = (value: unknown): value is Record<string, unknown> => !!value && typeof value === "object" && !Array.isArray(value);
const id = (value: unknown): value is string => typeof value === "string" && value.length > 0 && value.length <= 128 && /^[A-Za-z0-9._:-]+$/.test(value);
function matches(expected: string, actual: unknown): boolean { if (typeof actual !== "string") return false; const a = Buffer.from(expected), b = Buffer.from(actual), p = Buffer.alloc(a.length); b.copy(p, 0, 0, Math.min(a.length, b.length)); return a.length === b.length && timingSafeEqual(a, p); }
function code(error: unknown): string { return error instanceof TaskSessionError ? error.code : "invalidRequest"; }
function message(error: unknown): string { return error instanceof Error ? error.message : "invalid broker request"; }
async function prepareSocketPath(socketPath: string): Promise<void> {
  try {
    if (!(await lstat(socketPath)).isSocket()) throw new Error("broker socket path exists and is not a socket");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
    throw error;
  }
  const live = await new Promise<boolean>((resolve, reject) => {
    const probe = createConnection(socketPath);
    probe.once("connect", () => { probe.destroy(); resolve(true); });
    probe.once("error", (error) => {
      probe.destroy();
      if ((error as NodeJS.ErrnoException).code === "ECONNREFUSED" || (error as NodeJS.ErrnoException).code === "ENOENT") resolve(false);
      else reject(error);
    });
  });
  if (live) throw new Error("Agent Tab Bridge broker is already running");
  await rm(socketPath);
}

/** User-only NDJSON broker, retained only while the browser native host lives. */
export class BrokerServer {
  readonly socketPath: string;
  private readonly clients = new Set<Socket>();
  private readonly sessionOwners = new Map<string, Socket>();
  private readonly pendingEvents = new Map<string, BrokerEvent[]>();

  private readonly connections = new Set<Socket>();
  private closed = false;
  private constructor(private readonly server: Server, private readonly options: BrokerServerOptions, socketPath: string) { this.socketPath = socketPath; }
  static async start(options: BrokerServerOptions): Promise<BrokerServer> {
    if (options.token.length < 32) throw new Error("broker token is missing or too short");
    const socketPath = options.socketPath ?? defaultBrokerSocketPath();
    await prepareSocketPath(socketPath);
    let broker: BrokerServer;
    const server = createServer((socket) => broker.accept(socket));
    broker = new BrokerServer(server, options, socketPath);
    await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(socketPath, () => { server.off("error", reject); resolve(); }); });
    await chmod(socketPath, 0o600);
    return broker;
  }
  publish(event: BrokerEvent): void {
    if (this.closed) return;
    if (!event.sessionId) { const line = JSON.stringify(event) + "\n"; for (const socket of this.clients) if (!socket.destroyed) socket.write(line); return; }
    const owner = this.sessionOwners.get(event.sessionId);
    if (!owner) { if (event.event === "pending") { const pending = this.pendingEvents.get(event.sessionId) ?? []; pending.push(event); this.pendingEvents.set(event.sessionId, pending); } return; }
    if (!owner.destroyed && this.clients.has(owner)) owner.write(JSON.stringify(event) + "\n");
  }

  async close(): Promise<void> {
    if (this.closed) return; this.closed = true;
    for (const socket of this.connections) { socket.end('{"event":"hostClosing"}\n'); socket.destroy(); }
    this.clients.clear(); this.connections.clear(); this.sessionOwners.clear(); this.pendingEvents.clear(); await new Promise<void>((resolve) => this.server.close(() => resolve())); await rm(this.socketPath, { force: true });
  }
  private bindSessionOwner(sessionId: string, socket: Socket): void {
    this.sessionOwners.set(sessionId, socket);
    const pending = this.pendingEvents.get(sessionId);
    if (pending) { this.pendingEvents.delete(sessionId); for (const event of pending) if (!socket.destroyed) socket.write(JSON.stringify(event) + "\n"); }
  }

  private accept(socket: Socket): void {
    if (this.closed) { socket.destroy(); return; }
    this.connections.add(socket); let input = Buffer.alloc(0), authenticated = false; const requestIds = new Set<string>();
    socket.on("error", () => {}); socket.on("close", () => { this.clients.delete(socket); this.connections.delete(socket); const owned = [...this.sessionOwners.entries()].filter(([, owner]) => owner === socket).map(([sessionId]) => sessionId); for (const [sessionId] of owned) this.sessionOwners.delete(sessionId); void Promise.allSettled(owned.map(async (sessionId) => await this.options.sessions.revoke(sessionId, "controllerDisconnected"))); });
    socket.on("data", (chunk: Buffer) => {
      input = input.length ? Buffer.concat([input, chunk]) : Buffer.from(chunk);
      if (input.length > BROKER_MAX_LINE_BYTES) { socket.destroy(); return; }
      while (true) {
        const end = input.indexOf(0x0a); if (end < 0) return;
        const line = input.subarray(0, end); input = input.subarray(end + 1);
        if (!line.length || line.length > BROKER_MAX_LINE_BYTES) { socket.destroy(); return; }
        let value: unknown; try { value = JSON.parse(line.toString("utf8")); } catch { socket.destroy(); return; }
        if (!authenticated) {
          if (!object(value) || value.type !== "auth" || !matches(this.options.token, value.token)) { socket.end('{"type":"error","error":{"code":"unauthorized","message":"authentication failed"}}\n'); return; }
          authenticated = true; this.clients.add(socket); socket.write('{"type":"authOk"}\n'); continue;
        }
        void this.command(socket, value, requestIds);
      }
    });
  }
  private async command(socket: Socket, value: unknown, requestIds: Set<string>): Promise<void> {
    if (!object(value) || !id(value.id) || (value.command !== "status" && value.command !== "openSession" && value.command !== "revokeSession")) { socket.write('{"id":"","ok":false,"error":{"code":"invalidRequest","message":"invalid broker command"}}\n'); return; }
    const request = value as BrokerCommandRequest;
    if (requestIds.has(request.id)) { socket.write(JSON.stringify({ id: request.id, ok: false, error: { code: "replayedRequest", message: "request ID was already used" } } satisfies BrokerResponse) + "\n"); return; }
    requestIds.add(request.id);
    try {
      let result: unknown;
      if (request.command === "status") {
        result = { trusted: this.options.isTrusted(), sessions: this.options.sessions.snapshot(), ...(this.options.status?.() ?? {}) };
      } else if (request.command === "openSession") {
        if (!this.options.isTrusted()) throw new TaskSessionError("invalidSession", "browser extension is not trusted");
        const controller = this.options.controller(); if (!controller) throw new TaskSessionError("invalidSession", "browser identity is unavailable");
        if (typeof request.taskLabel !== "string" || !Array.isArray(request.requestedCapabilities)) throw new TaskSessionError("invalidSession", "taskLabel and requestedCapabilities are required");
        const session = this.options.sessions.open({ controllerPrincipalId: controller.principalId, controllerName: controller.displayName, taskLabel: request.taskLabel, capabilities: request.requestedCapabilities, ttlMs: request.ttlMs });
        this.bindSessionOwner(session.id, socket);
        result = { session };
      } else {
        if (typeof request.sessionId !== "string") throw new TaskSessionError("invalidSession", "sessionId is required");
        if (this.sessionOwners.get(request.sessionId) !== socket) throw new TaskSessionError("invalidSession", "session is owned by another controller");
        result = { session: await this.options.sessions.revoke(request.sessionId, request.reason ?? "cliRevoked") };
      }
      socket.write(JSON.stringify({ id: request.id, ok: true, result } satisfies BrokerResponse) + "\n");
    } catch (error) { socket.write(JSON.stringify({ id: request.id, ok: false, error: { code: code(error), message: message(error) } } satisfies BrokerResponse) + "\n"); }
  }
}
export async function startBrokerServer(options: BrokerServerOptions): Promise<BrokerServer> { return await BrokerServer.start(options); }

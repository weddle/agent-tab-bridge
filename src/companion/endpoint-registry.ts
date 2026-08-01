import { createConnection } from "node:net";
import { lstat, readFile } from "node:fs/promises";
import { supervisorSocketLayout, type LiveEndpointRecord } from "./supervisor.js";
import type { ApplicationSupportOptions } from "./state.js";

export type LiveEndpoint = LiveEndpointRecord;

type RegistryDocument = { version?: unknown; endpoints?: unknown };

function validRecord(value: unknown): value is LiveEndpointRecord {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  return typeof record.endpointId === "string"
    && /^sha256\/[A-Za-z0-9+/=_-]{1,249}$/.test(record.endpointId)
    && typeof record.label === "string"
    && record.label.length > 0
    && record.label.length <= 256
    && typeof record.socketPath === "string"
    && record.socketPath.startsWith("/")
    && !record.socketPath.split("/").includes("..");
}

async function acceptsConnections(socketPath: string): Promise<boolean> {
  return await new Promise<boolean>((resolve) => {
    const socket = createConnection(socketPath);
    let settled = false;
    const finish = (accepted: boolean) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(accepted);
    };
    socket.once("connect", () => finish(true));
    socket.once("error", () => finish(false));
    socket.setTimeout(250, () => finish(false));
  });
}

/** Read the supervisor's convenience registry and retain only currently reachable endpoint sockets. */
export async function readLiveEndpoints(options: ApplicationSupportOptions = {}): Promise<LiveEndpointRecord[]> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(await readFile(supervisorSocketLayout(options).registryPath, "utf8")) as unknown;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT" || error instanceof SyntaxError) return [];
    throw error;
  }
  const document = parsed as RegistryDocument;
  if (!document || document.version !== 1 || !Array.isArray(document.endpoints)) return [];
  const candidates = document.endpoints.filter(validRecord);
  const live: LiveEndpointRecord[] = [];
  for (const endpoint of candidates) {
    try {
      if (!(await lstat(endpoint.socketPath)).isSocket()) continue;
      if (await acceptsConnections(endpoint.socketPath)) live.push({ ...endpoint });
    } catch {
      // Registry records are advisory. A disconnect between lstat and probe is stale.
    }
  }
  return live;
}

export async function selectLiveEndpoint(selector: string | undefined, options: ApplicationSupportOptions = {}): Promise<LiveEndpointRecord> {
  const endpoints = await readLiveEndpoints(options);
  if (selector !== undefined) {
    const matches = endpoints.filter((endpoint) => endpoint.endpointId === selector || endpoint.label === selector);
    if (matches.length === 1) return matches[0]!;
    if (matches.length > 1) throw new Error(`refused: --browser ${selector} matches multiple live browser endpoints`);
    const available = endpoints.map((endpoint) => `${endpoint.label} (${endpoint.endpointId})`).join(", ") || "none";
    throw new Error(`refused: browser ${selector} is not live (available: ${available})`);
  }
  if (endpoints.length === 1) return endpoints[0]!;
  if (endpoints.length === 0) throw new Error("refused: no live browser endpoints");
  throw new Error(`refused: multiple browser endpoints are live; pass --browser <label|fingerprint> (available: ${endpoints.map((endpoint) => `${endpoint.label} (${endpoint.endpointId})`).join(", ")})`);
}

import crypto from "node:crypto";
import { existsSync } from "node:fs";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
export const DEFAULT_NATIVE_HOST_NAME = "com.agenttabbridge.companion";
export const DEFAULT_EXTENSION_MANIFEST = "extensions/browser/chrome-extension/manifest.json";

const moduleDirectory = path.dirname(fileURLToPath(import.meta.url));
const sourceExtensionManifest = path.resolve(moduleDirectory, "..", "..", DEFAULT_EXTENSION_MANIFEST);
const compiledExtensionManifest = path.resolve(moduleDirectory, "..", "..", "..", DEFAULT_EXTENSION_MANIFEST);
const packagedExtensionManifest = existsSync(compiledExtensionManifest)
  ? compiledExtensionManifest
  : sourceExtensionManifest;

export type Browser = "brave" | "chrome";
export type NativeHostManifest = {
  name: string;
  description: string;
  path: string;
  type: "stdio";
  allowed_origins: string[];
};

export type ManifestFs = Pick<typeof fs, "mkdir" | "readFile" | "rename" | "rm" | "writeFile"> & {
  chmod?: typeof fs.chmod;
};
export type ManifestPaths = Record<Browser, string>;

export function nativeMessagingDirectory(browser: Browser, home = os.homedir()): string {
  const root = browser === "brave"
    ? path.join(home, "Library", "Application Support", "BraveSoftware", "Brave-Browser")
    : path.join(home, "Library", "Application Support", "Google", "Chrome");
  return path.join(root, "NativeMessagingHosts");
}

export function nativeManifestPaths(hostName = DEFAULT_NATIVE_HOST_NAME, home = os.homedir()): ManifestPaths {
  return {
    brave: path.join(nativeMessagingDirectory("brave", home), `${hostName}.json`),
    chrome: path.join(nativeMessagingDirectory("chrome", home), `${hostName}.json`),
  };
}

function extensionIdFromKey(key: string): string {
  const normalized = key.includes("BEGIN PUBLIC KEY")
    ? key
    : `-----BEGIN PUBLIC KEY-----\n${key}\n-----END PUBLIC KEY-----`;
  const der = crypto.createPublicKey(normalized).export({ type: "spki", format: "der" });
  const digest = crypto.createHash("sha256").update(der).digest();
  return [...digest.subarray(0, 16)]
    .map((byte) => String.fromCharCode(97 + ((byte >> 4) & 0xf), 97 + (byte & 0xf)))
    .join("");
}

export async function extensionOriginFromManifest(
  manifestPath = packagedExtensionManifest,
  readFile: ManifestFs["readFile"] = fs.readFile,
): Promise<string> {
  const raw = await readFile(manifestPath, "utf8");
  const manifest = JSON.parse(raw) as { id?: unknown; key?: unknown; extension_id?: unknown };
  const explicit = [manifest.id, manifest.extension_id].find(
    (value): value is string => typeof value === "string" && /^[a-p]{32}$/.test(value),
  );
  const id = explicit ?? (typeof manifest.key === "string" ? extensionIdFromKey(manifest.key) : "");
  if (!id) throw new Error(`extension manifest has no stable identity: ${manifestPath}`);
  return `chrome-extension://${id}/`;
}

export function makeNativeHostManifest(params: {
  executablePath: string;
  extensionOrigin: string;
  hostName?: string;
  description?: string;
}): NativeHostManifest {
  const executablePath = path.resolve(params.executablePath);
  if (!path.isAbsolute(executablePath)) throw new Error("native host executable path must be absolute");
  if (!params.extensionOrigin.startsWith("chrome-extension://") || !params.extensionOrigin.endsWith("/")) {
    throw new Error("native host extension origin is invalid");
  }
  return {
    name: params.hostName ?? DEFAULT_NATIVE_HOST_NAME,
    description: params.description ?? "Agent Tab Bridge native companion",
    path: executablePath,
    type: "stdio",
    allowed_origins: [params.extensionOrigin],
  };
}

async function atomicWrite(filePath: string, body: string, io: ManifestFs): Promise<void> {
  await io.mkdir(path.dirname(filePath), { recursive: true, mode: 0o700 });
  const temporary = `${filePath}.${process.pid}.${crypto.randomBytes(8).toString("hex")}.tmp`;
  try {
    await io.writeFile(temporary, body, { encoding: "utf8", mode: 0o600, flag: "wx" });
    if (io.chmod) await io.chmod(temporary, 0o600);
    await io.rename(temporary, filePath);
  } catch (error) {
    await io.rm(temporary, { force: true }).catch(() => undefined);
    throw error;
  }
}

export async function installNativeManifests(params: {
  executablePath: string;
  extensionOrigin: string;
  hostName?: string;
  description?: string;
  home?: string;
  io?: ManifestFs;
}): Promise<ManifestPaths> {
  const io = params.io ?? fs;
  const manifest = makeNativeHostManifest(params);
  const paths = nativeManifestPaths(manifest.name, params.home);
  const body = `${JSON.stringify(manifest, null, 2)}\n`;
  await Promise.all(Object.values(paths).map((target) => atomicWrite(target, body, io)));
  return paths;
}

export async function uninstallNativeManifests(params: {
  executablePath: string;
  extensionOrigin: string;
  hostName?: string;
  description?: string;
  home?: string;
  io?: ManifestFs;
}): Promise<{ removed: string[]; skipped: string[] }> {
  const io = params.io ?? fs;
  const expected = makeNativeHostManifest(params);
  const paths = nativeManifestPaths(expected.name, params.home);
  const removed: string[] = [];
  const skipped: string[] = [];
  for (const target of Object.values(paths)) {
    let raw: string;
    try { raw = await io.readFile(target, "utf8"); } catch { skipped.push(target); continue; }
    let parsed: unknown;
    try { parsed = JSON.parse(raw); } catch { skipped.push(target); continue; }
    if (JSON.stringify(parsed) !== JSON.stringify(expected)) { skipped.push(target); continue; }
    await io.rm(target, { force: false });
    removed.push(target);
  }
  return { removed, skipped };
}

export async function nativeManifestStatus(params: {
  executablePath: string;
  extensionOrigin: string;
  hostName?: string;
  description?: string;
  home?: string;
  io?: ManifestFs;
}): Promise<Record<Browser, { path: string; installed: boolean; matches: boolean }>> {
  const io = params.io ?? fs;
  const expected = makeNativeHostManifest(params);
  const paths = nativeManifestPaths(expected.name, params.home);
  const result = {} as Record<Browser, { path: string; installed: boolean; matches: boolean }>;
  for (const browser of ["brave", "chrome"] as const) {
    try {
      const parsed = JSON.parse(await io.readFile(paths[browser], "utf8")) as unknown;
      result[browser] = { path: paths[browser], installed: true, matches: JSON.stringify(parsed) === JSON.stringify(expected) };
    } catch {
      result[browser] = { path: paths[browser], installed: false, matches: false };
    }
  }
  return result;
}

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
type NativeHostInstallation = {
  executablePath: string;
  extensionOrigin: string;
  hostName?: string;
  description?: string;
  home?: string;
  runtimePath?: string;
  io?: ManifestFs;
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

export function nativeHostLauncherPath(hostName = DEFAULT_NATIVE_HOST_NAME, home = os.homedir()): string {
  return path.join(home, "Library", "Application Support", "Agent Tab Bridge", hostName);
}

function shellQuote(value: string): string {
  return `'${value.replaceAll("'", "'\\''")}'`;
}

export function makeNativeHostLauncher(runtimePath: string, executablePath: string): string {
  return `#!/bin/sh\nexec ${shellQuote(path.resolve(runtimePath))} ${shellQuote(path.resolve(executablePath))} "$@"\n`;
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

function installedExecutablePath(params: NativeHostInstallation): string {
  return params.runtimePath
    ? nativeHostLauncherPath(params.hostName, params.home)
    : params.executablePath;
}

async function atomicWrite(filePath: string, body: string, io: ManifestFs, mode = 0o600): Promise<void> {
  await io.mkdir(path.dirname(filePath), { recursive: true, mode: 0o700 });
  const temporary = `${filePath}.${process.pid}.${crypto.randomBytes(8).toString("hex")}.tmp`;
  try {
    await io.writeFile(temporary, body, { encoding: "utf8", mode, flag: "wx" });
    if (io.chmod) await io.chmod(temporary, mode);
    await io.rename(temporary, filePath);
  } catch (error) {
    await io.rm(temporary, { force: true }).catch(() => undefined);
    throw error;
  }
}

export async function installNativeManifests(params: NativeHostInstallation): Promise<ManifestPaths> {
  const io = params.io ?? fs;
  const launcherPath = installedExecutablePath(params);
  if (params.runtimePath) {
    await atomicWrite(
      launcherPath,
      makeNativeHostLauncher(params.runtimePath, params.executablePath),
      io,
      0o700,
    );
  }
  const manifest = makeNativeHostManifest({ ...params, executablePath: launcherPath });
  const paths = nativeManifestPaths(manifest.name, params.home);
  const body = `${JSON.stringify(manifest, null, 2)}\n`;
  await Promise.all(Object.values(paths).map((target) => atomicWrite(target, body, io)));
  return paths;
}

export async function uninstallNativeManifests(params: NativeHostInstallation): Promise<{ removed: string[]; skipped: string[] }> {
  const io = params.io ?? fs;
  const launcherPath = installedExecutablePath(params);
  const expected = makeNativeHostManifest({ ...params, executablePath: launcherPath });
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
  if (params.runtimePath && removed.length > 0 && skipped.length === 0) {
    const expectedLauncher = makeNativeHostLauncher(params.runtimePath, params.executablePath);
    try {
      if (await io.readFile(launcherPath, "utf8") === expectedLauncher) {
        await io.rm(launcherPath, { force: false });
      }
    } catch {}
  }
  return { removed, skipped };
}

export async function nativeManifestStatus(params: NativeHostInstallation): Promise<Record<Browser, { path: string; installed: boolean; matches: boolean }>> {
  const io = params.io ?? fs;
  const launcherPath = installedExecutablePath(params);
  const expected = makeNativeHostManifest({ ...params, executablePath: launcherPath });
  const paths = nativeManifestPaths(expected.name, params.home);
  let launcherMatches = true;
  if (params.runtimePath) {
    try {
      launcherMatches = await io.readFile(launcherPath, "utf8") === makeNativeHostLauncher(params.runtimePath, params.executablePath);
    } catch {
      launcherMatches = false;
    }
  }
  const result = {} as Record<Browser, { path: string; installed: boolean; matches: boolean }>;
  for (const browser of ["brave", "chrome"] as const) {
    try {
      const parsed = JSON.parse(await io.readFile(paths[browser], "utf8")) as unknown;
      result[browser] = {
        path: paths[browser],
        installed: true,
        matches: launcherMatches && JSON.stringify(parsed) === JSON.stringify(expected),
      };
    } catch {
      result[browser] = { path: paths[browser], installed: false, matches: false };
    }
  }
  return result;
}

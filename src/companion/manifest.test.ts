import { mkdtemp, readFile, rm, stat } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  installNativeManifests,
  nativeHostLauncherPath,
} from "./manifest.js";

const roots: string[] = [];
afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

describe("native messaging host installation", () => {
  it("uses an executable launcher with an absolute runtime path", async () => {
    const home = await mkdtemp(path.join(os.tmpdir(), "agent-tab-bridge-manifest-"));
    roots.push(home);
    const executablePath = "/Applications/Agent Tab Bridge/atb.js";
    const runtimePath = "/opt/homebrew/bin/node";

    const manifests = await installNativeManifests({
      executablePath,
      runtimePath,
      extensionOrigin: "chrome-extension://abcdefghijklmnopabcdefghijklmnop/",
      home,
    });
    const launcherPath = nativeHostLauncherPath(undefined, home);

    await expect(readFile(launcherPath, "utf8")).resolves.toBe(
      `#!/bin/sh\nexec '${runtimePath}' '${executablePath}' "$@"\n`,
    );
    expect((await stat(launcherPath)).mode & 0o777).toBe(0o700);
    await expect(readFile(manifests.brave, "utf8")).resolves.toContain(
      `"path": "${launcherPath}"`,
    );
  });
});

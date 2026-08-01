import { existsSync } from "node:fs";
import { spawn } from "node:child_process";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const integration = resolve("dist/src/companion/supervisor-integration.js");
const run = existsSync(integration) ? it : it.skip;

describe("edge supervisor lifecycle", () => {
  run("multiplexes endpoints, cleans up when idle, and survives shim churn", async () => {
    const child = spawn(process.execPath, [integration, "--atb-supervisor-integration"], { stdio: ["ignore", "pipe", "pipe"] });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    child.stdout.on("data", (chunk: Buffer) => stdout.push(chunk));
    child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));
    const code = await new Promise<number | null>((resolvePromise, reject) => { child.once("exit", resolvePromise); child.once("error", reject); });
    expect(code, Buffer.concat(stderr).toString("utf8")).toBe(0);
    expect(Buffer.concat(stdout).toString("utf8")).toBe("supervisor integration passed\n");
  });
});

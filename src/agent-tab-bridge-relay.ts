#!/usr/bin/env node

import { startAgentTabRelay } from "../extensions/browser/src/browser/extension-relay/relay-server.js";

function waitForShutdownSignal(): { promise: Promise<void>; dispose: () => void } {
  const { promise, resolve } = Promise.withResolvers<void>();
  const onSignal = () => {
    resolve();
  };
  const dispose = () => {
    process.off("SIGINT", onSignal);
    process.off("SIGTERM", onSignal);
  };

  process.on("SIGINT", onSignal);
  process.on("SIGTERM", onSignal);
  return { promise, dispose };
}

async function main(): Promise<void> {
  const relay = await startAgentTabRelay();

  process.stdout.write(`${relay.pairingUrl}\n`);
  process.stdout.write(`BROWSER_CDP_URL=${relay.cdpUrl}\n`);

  const shutdown = waitForShutdownSignal();
  await shutdown.promise;
  try {
    await relay.close();
  } finally {
    shutdown.dispose();
  }
}

main().catch(() => {
  process.stderr.write("Agent Tab Bridge relay failed.\n");
  process.exitCode = 1;
});

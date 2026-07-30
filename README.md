# Agent Tab Bridge

A general-purpose Brave/Chrome extension and local relay that lets an agent co-browse only the tabs you explicitly share—without starting your everyday browser with a remote-debugging port and without leaving a persistent CDP service running.

The first target is **Brave**, because that is the browser used for development and MVP validation. Chrome compatibility is intended but will be claimed only after it is tested.

## Why

Launching a browser with `--remote-debugging-port` exposes a broad automation surface and usually means maintaining a separate automation profile or accepting that CDP is always available. Agent Tab Bridge instead uses Chrome's visible `chrome.debugger` consent surface:

- You explicitly share or unshare a tab from the extension.
- Shared tabs live in a visibly labelled tab group.
- Tabs outside that group are not reported to the relay or attachable by clients.
- Dragging a tab out of the group immediately revokes access.
- The browser's debugger banner remains visible; dismissing it revokes access.
- The relay exists only for the current task, binds to `127.0.0.1`, and requires an ephemeral token.

The immediate motivation was finding a narrow, user-consented way to expose an existing Brave session to [Hermes](https://github.com/NousResearch/hermes-agent) through its `BROWSER_CDP_URL` interface. The bridge itself is intentionally agent-agnostic: any compatible CDP client can use the authenticated loopback endpoint.

## Shape

- `extensions/browser/chrome-extension/`: MV3 extension and shared-tab consent UI.
- `extensions/browser/src/browser/extension-relay/`: loopback HTTP/WebSocket relay and CDP routing.
- A task launcher supplies an authenticated URL such as:

  ```text
  ws://127.0.0.1:<ephemeral-port>/cdp?token=<ephemeral-token>
  ```

The capability URL is short-lived. It must not be committed, stored in persistent agent configuration, logged, or sent in notifications.

## Status

Release 1's trusted-local workflow is implemented. The companion is installed once, the extension and companion authenticate and pin each other, each `atb run` request requires an explicit browser-local approval, and only tabs shared into that task's visible group appear over CDP. No user copies a token or port.

The focused contract suite and disposable Brave and Chrome-for-Testing profiles cover companion authentication, task approval, one explicitly shared page read through authenticated CDP, launcher-scoped revocation, browser disconnect, and one-click device trust removal.

See [`ROADMAP.md`](ROADMAP.md) for the later trusted-LAN, bookmarks/history, managed-action, and Guardian Auto releases.

## Build and install

Requires Node.js 22 or newer.

```bash
npm install
npm run build
npm test
node dist/src/atb.js install
node dist/src/atb.js status
```

Then load `extensions/browser/chrome-extension/` as an unpacked extension:

1. Open `brave://extensions` or `chrome://extensions`.
2. Enable **Developer mode** and choose **Load unpacked**.
3. Select `extensions/browser/chrome-extension/`.
4. Open the extension popup and confirm that the companion is connected and its abbreviated verified identity is visible.

The manifest's committed public key gives the unpacked extension a stable ID. The installer derives the allowed Native Messaging origin from that manifest rather than accepting an extension ID from the command line.

## Run a task

Launch the agent as a child of `atb run`:

```bash
node dist/src/atb.js run --label "Research task" -- hermes
```

The popup shows the authenticated controller principal, unverified display label, requested capability, and TTL. Approve the task, then share only the intended tabs with that session. `atb` injects the ephemeral `BROWSER_CDP_URL` only into the child process; it is never printed, persisted, or copied by the user. Child exit, browser loss, session revocation, tab-group removal, or debugger detachment removes the corresponding authority.

To remove the Native Messaging registration:

```bash
node dist/src/atb.js uninstall
```

The popup's **Forget companion & revoke all access** control separately removes device trust and stops every local task session.

## Upstream and attribution

This project is derived from the browser-extension and extension-relay work in [OpenClaw](https://github.com/openclaw/openclaw), used under the MIT License.

- Upstream source commit: [`b907309b35754e25aa15a309ce6cf63875267c71`](https://github.com/openclaw/openclaw/commit/b907309b35754e25aa15a309ce6cf63875267c71)
- Filtered mirror tag: `openclaw-b907309b35754e25aa15a309ce6cf63875267c71`
- Selected upstream paths: [`upstream/openclaw-paths.txt`](upstream/openclaw-paths.txt)
- Detailed provenance and update procedure: [`upstream/README.md`](upstream/README.md)
- Required notices: [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md)

The project is independently named and is not affiliated with or endorsed by the OpenClaw Foundation.

## License

Agent Tab Bridge is distributed under the MIT License. OpenClaw-derived portions retain the OpenClaw Foundation copyright and MIT notice in `THIRD_PARTY_NOTICES.md`. Additional incorporated notices are retained there as required.

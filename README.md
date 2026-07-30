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

Initial upstream import. OpenClaw-specific branding, copilot/sidebar features, gateway integration, and page-sharing features are being removed before the first usable build. Brave is the MVP validation target.

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

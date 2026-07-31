/**
 * Extension relay CDP bridge.
 *
 * Presents a CDP browser endpoint (compatible with Playwright connectOverCDP)
 * on one side and the browser extension's chrome.debugger transport on the
 * other. The bridge owns all Target.* synthesis so the extension stays a thin
 * forwarder.
 */
import { resolveCreateTargetParams } from "./create-target-params.js";
import {
  type ExtensionToRelayMessage,
  parseExtensionMessage,
  type RelayCommandBody,
  type RelayTabInfo,
  type RelayToExtensionMessage,
} from "./relay-protocol.js";

const EXTENSION_COMMAND_TIMEOUT_MS = 15_000;
const EXTENSION_PING_INTERVAL_MS = 20_000;
const EXTENSION_DISPOSE_TIMEOUT_MS = 2_000;

/** Synthetic targetId for the emulated browser target. */
const BROWSER_TARGET_ID = "agent-tab-bridge-browser";
/** Playwright requires every attached page target to identify its browser context. */
const BROWSER_CONTEXT_ID = "agent-tab-bridge-context";

/** Stable target identity for a tab in an approved extension session snapshot. */
function targetIdForTab(tabId: number): string {
  return `agent-tab-bridge-target-${tabId}`;
}

/**
 * CDP commands from a browser-scoped synthetic session and a debugger-attached
 * page session have different authorities. The bridge synthesizes the safe
 * browser/Target surface; only page automation commands may reach
 * chrome.debugger.
 */
export type CdpMethodScope = "browser" | "page";

export enum CdpMethodPolicy {
  Allow = "allow",
  Deny = "deny",
}

/** Stable error returned when a method could escape the shared-page boundary. */
export const CDP_METHOD_POLICY_ERROR = "CDP method is not permitted by Agent Tab Bridge";
export const CDP_METHOD_POLICY_ERROR_CODE = -32000;

const SYNTHETIC_BROWSER_METHODS: Record<string, true> = {
  "Browser.getVersion": true,
  // Close only this CDP client; never forward a browser-close command.
  "Browser.close": true,
};
const SYNTHETIC_TARGET_METHODS: Record<string, true> = {
  "Target.getTargetInfo": true,
  "Target.getTargets": true,
  "Target.attachToBrowserTarget": true,
  "Target.setAutoAttach": true,
  "Target.attachToTarget": true,
  "Target.detachFromTarget": true,
  "Target.createTarget": true,
  "Target.closeTarget": true,
  "Target.activateTarget": true,
  // This is a no-op: target enumeration remains bridge-synthesized.
  "Target.setDiscoverTargets": true,
};

/**
 * Domains whose commands are useful solely against the already attached page
 * target. New domains must be explicitly reviewed before joining this list.
 */
const PAGE_CDP_DOMAINS: Record<string, true> = {
  Accessibility: true,
  CSS: true,
  DOM: true,
  Debugger: true,
  Emulation: true,
  Fetch: true,
  Input: true,
  Log: true,
  Network: true,
  Page: true,
  Performance: true,
  Runtime: true,
};

/**
 * Commands from otherwise page-scoped domains that alter or expose profile
 * state, or disclose a local file path.
 */
const DENIED_PAGE_METHODS: Record<string, true> = {
  "DOM.getFileInfo": true,
  "Network.clearBrowserCache": true,
  "Network.clearBrowserCookies": true,
  "Network.deleteCookies": true,
  "Network.getAllCookies": true,
  "Network.getCookies": true,
  "Network.setCookie": true,
  "Network.setCookies": true,
  "Page.setDownloadBehavior": true,
};

/**
 * Deterministically classifies CDP methods before the bridge forwards them.
 *
 * Only reviewed page-control and inspection domains may be forwarded. Unknown
 * methods in those domains remain compatible, but new domains fail closed.
 */
export function classifyCdpMethod(
  method: string,
  scope: CdpMethodScope,
): CdpMethodPolicy {
  if (scope === "browser" && SYNTHETIC_BROWSER_METHODS[method]) {
    return CdpMethodPolicy.Allow;
  }
  if (scope === "browser" && SYNTHETIC_TARGET_METHODS[method]) {
    return CdpMethodPolicy.Allow;
  }
  if (scope !== "page" || DENIED_PAGE_METHODS[method]) {
    return CdpMethodPolicy.Deny;
  }
  const separator = method.indexOf(".");
  const domain = separator === -1 ? method : method.slice(0, separator);
  return PAGE_CDP_DOMAINS[domain] ? CdpMethodPolicy.Allow : CdpMethodPolicy.Deny;
}

/** Minimal socket seam so tests can drive the bridge without real WebSockets. */
type BridgeSocket = {
  send: (data: string) => void;
  close: (code?: number, reason?: string) => void;
};

type CdpRequest = {
  id: number;
  method: string;
  params?: Record<string, unknown>;
  sessionId?: string;
};

type PendingExtensionCommand = {
  resolve: (result: unknown) => void;
  reject: (err: Error) => void;
  timer: NodeJS.Timeout;
};

type TabState = {
  info: RelayTabInfo;
  /** Set after the extension claims the tab and chrome.debugger attaches. */
  attached?: { targetId: string; sessionId: string };
  attaching?: Promise<{ targetId: string; sessionId: string }>;
};

type CdpClientState = {
  socket: BridgeSocket;
  autoAttach: boolean;
  /** Session ids this client has been told about (root and child sessions). */
  announcedSessions: Set<string>;
};

type AuxiliaryTabSession = {
  tabId: number;
  parentSessionId: string;
  client: CdpClientState;
};
type TabWaiter = {
  resolve: (tab: TabState) => void;
  reject: (err: Error) => void;
  timer: NodeJS.Timeout;
};


/** Browser identity reported by the paired extension. */
type ExtensionIdentity = {
  userAgent: string;
  browserVersion: string;
  extensionVersion: string;
};


function toErrorPayload(
  id: number | null,
  sessionId: string | undefined,
  message: string,
  code = -32000,
): string {
  return JSON.stringify({ id, ...(sessionId ? { sessionId } : {}), error: { code, message } });
}
function isRelayTabInfo(value: unknown): value is RelayTabInfo {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const tab = value as Partial<RelayTabInfo>;
  return (
    Number.isSafeInteger(tab.tabId) &&
    (tab.tabId as number) >= 0 &&
    typeof tab.url === "string" &&
    typeof tab.title === "string" &&
    typeof tab.active === "boolean"
  );
}

/**
 * One relay bridge per extension-driver profile. Accepts at most one extension
 * connection (a newer one replaces the old — MV3 workers restart freely) and
 * any number of CDP clients (pw-session caches one per cdpUrl in practice).
 */
export class ExtensionRelayBridge {
  private extension: { socket: BridgeSocket; identity: ExtensionIdentity } | null = null;
  private readonly clients = new Set<CdpClientState>();
  private readonly tabs = new Map<number, TabState>();
  /** Browser-level sessions created by Playwright for page-scoped CDP access. */
  private readonly browserSessions = new Map<string, CdpClientState>();
  /** Extra root-page sessions multiplexed over one chrome.debugger attachment. */
  private readonly auxiliaryTabSessions = new Map<string, AuxiliaryTabSession>();
  /** Child debugger sessions (iframes/workers) mapped to their owning tab. */
  private readonly childSessions = new Map<string, number>();
  private readonly pendingExtension = new Map<number, PendingExtensionCommand>();
  private readonly tabWaiters = new Map<number, Set<TabWaiter>>();
  private nextSeq = 1;
  private nextSessionOrdinal = 1;
  private pingTimer: NodeJS.Timeout | null = null;
  private disposePromise: Promise<void> | null = null;
  private closing = false;
  private disposed = false;

  /** True once an extension socket completed its hello handshake. */
  get extensionConnected(): boolean {
    return this.extension !== null;
  }

  /** Identity of the paired browser, when connected. */
  get identity(): ExtensionIdentity | null {
    return this.extension?.identity ?? null;
  }

  /** Tabs in the latest snapshot from the approved extension session. */
  sharedTabs(): RelayTabInfo[] {
    return [...this.tabs.values()].map((tab) => tab.info);
  }

  /** Number of connected CDP clients (diagnostics). */
  get cdpClientCount(): number {
    return this.clients.size;
  }

  // ---------------------------------------------------------------------
  // Extension side
  // ---------------------------------------------------------------------

  /** Wire up a newly accepted extension WebSocket. */
  attachExtensionSocket(socket: BridgeSocket): {
    onMessage: (raw: string) => void;
    onClose: () => void;
  } {
    if (this.closing || this.disposed) {
      socket.close(1001, "relay stopped");
      return { onMessage: () => {}, onClose: () => {} };
    }
    if (this.extension) {
      // Replace the previous connection: MV3 service workers restart and the
      // stale socket may linger half-open. Newest connection wins.
      this.extension.socket.close(4000, "replaced by newer extension connection");
      this.handleExtensionGone();
    }
    let helloSeen = false;
    const onMessage = (raw: string) => {
      if (this.closing || this.disposed) {
        return;
      }
      const msg = parseExtensionMessage(raw);
      if (!msg) {
        return;
      }
      if (!helloSeen) {
        if (msg.type !== "hello") {
          socket.close(4001, "expected hello");
          return;
        }
        helloSeen = true;
        this.extension = {
          socket,
          identity: {
            userAgent: msg.userAgent,
            browserVersion: msg.browserVersion,
            extensionVersion: msg.extensionVersion,
          },
        };
        this.syncTabs(msg.tabs);
        this.startPing();
        return;
      }
      this.handleExtensionMessage(msg);
    };
    const onClose = () => {
      if (this.extension?.socket === socket) {
        this.handleExtensionGone();
      }
    };
    return { onMessage, onClose };
  }

  private handleExtensionMessage(msg: ExtensionToRelayMessage): void {
    switch (msg.type) {
      case "result": {
        const pending = this.pendingExtension.get(msg.seq);
        if (pending) {
          this.pendingExtension.delete(msg.seq);
          clearTimeout(pending.timer);
          pending.resolve(msg.result);
        }
        return;
      }
      case "error": {
        const pending = this.pendingExtension.get(msg.seq);
        if (pending) {
          this.pendingExtension.delete(msg.seq);
          clearTimeout(pending.timer);
          pending.reject(new Error(msg.message));
        }
        return;
      }
      case "cdpEvent": {
        this.forwardExtensionEvent(msg.tabId, msg.sessionId, msg.method, msg.params);
        return;
      }
      case "tabs": {
        this.syncTabs(msg.tabs);
        return;
      }
      case "detached": {
        const tab = this.tabs.get(msg.tabId);
        if (tab?.attached) {
          this.emitDetachedFromTarget(msg.tabId, tab.attached.sessionId, tab.attached.targetId);
          tab.attached = undefined;
        }
        break;
      }
      case "pong":
      case "hello":
        break;
    }
  }


  private handleExtensionGone(): void {
    this.extension = null;
    this.stopPing();
    for (const pending of this.pendingExtension.values()) {
      clearTimeout(pending.timer);
      pending.reject(new Error("extension disconnected"));
    }
    this.pendingExtension.clear();
    for (const [tabId, waiters] of this.tabWaiters) {
      for (const waiter of waiters) {
        clearTimeout(waiter.timer);
        waiter.reject(new Error(`tab ${tabId} is no longer available to this approved session`));
      }
    }
    this.tabWaiters.clear();
    for (const [tabId, tab] of this.tabs) {
      if (tab.attached) {
        this.emitDetachedFromTarget(tabId, tab.attached.sessionId, tab.attached.targetId);
        tab.attached = undefined;
      }
    }
    this.tabs.clear();
    this.childSessions.clear();
  }

  private startPing(): void {
    this.stopPing();
    this.pingTimer = setInterval(() => {
      if (!this.extension) {
        this.handleExtensionGone();
        return;
      }
      try {
        this.sendToExtension({ type: "ping" });
      } catch {
        // A queued interval callback can run after the extension's close
        // callback. Treat a failed keepalive exactly like that close.
        this.handleExtensionGone();
      }
    }, EXTENSION_PING_INTERVAL_MS);
    this.pingTimer.unref?.();
  }

  private stopPing(): void {
    if (this.pingTimer) {
      clearInterval(this.pingTimer);
      this.pingTimer = null;
    }
  }

  private sendToExtension(msg: RelayToExtensionMessage): void {
    if (!this.extension) {
      throw new Error("Agent Tab Bridge extension is not connected to the relay");
    }
    this.extension.socket.send(JSON.stringify(msg));
  }


  private callExtension(
    command: RelayCommandBody,
    timeoutMs = EXTENSION_COMMAND_TIMEOUT_MS,
  ): Promise<unknown> {
    const seq = this.nextSeq++;
    return new Promise<unknown>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pendingExtension.delete(seq);
        reject(new Error(`extension relay command timed out: ${command.type}`));
      }, timeoutMs);
      timer.unref?.();
      this.pendingExtension.set(seq, { resolve, reject, timer });
      try {
        this.sendToExtension({ ...command, seq });
      } catch (err) {
        this.pendingExtension.delete(seq);
        clearTimeout(timer);
        reject(err instanceof Error ? err : new Error(String(err)));
      }
    });
  }
  private syncTabs(tabs: unknown): void {
    const validTabs = (Array.isArray(tabs) ? tabs : []).filter(isRelayTabInfo);
    const nextIds = new Set(validTabs.map((tab) => tab.tabId));
    for (const [tabId, tab] of this.tabs) {
      if (!nextIds.has(tabId)) {
        if (tab.attached) {
          this.emitDetachedFromTarget(tabId, tab.attached.sessionId, tab.attached.targetId);
        }
        this.tabs.delete(tabId);
      }
    }
    for (const info of validTabs) {
      const existing = this.tabs.get(info.tabId);
      if (existing) {
        existing.info = info;
      } else {
        const tab = { info };
        this.tabs.set(info.tabId, tab);
        const waiters = this.tabWaiters.get(info.tabId);
        if (waiters) {
          for (const waiter of waiters) {
            clearTimeout(waiter.timer);
            waiter.resolve(tab);
          }
          this.tabWaiters.delete(info.tabId);
        }
        // An auto-attach client explicitly asked to attach new snapshot tabs.
        if ([...this.clients].some((client) => client.autoAttach)) {
          void this.claimAndAttachTab(info.tabId)
            .then(({ targetId, sessionId }) => {
              this.announceAttachedTab(info.tabId, targetId, sessionId, { onlyAutoAttach: true });

            })
            .catch(() => {});
        }
      }
    }
  }
  private waitForReportedTab(tabId: number): Promise<TabState> {
    const existing = this.tabs.get(tabId);
    if (existing) {
      return Promise.resolve(existing);
    }
    return new Promise<TabState>((resolve, reject) => {
      let waiter: TabWaiter;
      const timer = setTimeout(() => {
        const waiters = this.tabWaiters.get(tabId);
        waiters?.delete(waiter);
        if (waiters?.size === 0) {
          this.tabWaiters.delete(tabId);
        }
        reject(new Error(`extension did not report tab ${tabId} in the approved session snapshot`));
      }, EXTENSION_COMMAND_TIMEOUT_MS);
      timer.unref?.();
      waiter = { resolve, reject, timer };
      const waiters = this.tabWaiters.get(tabId) ?? new Set<TabWaiter>();
      waiters.add(waiter);
      this.tabWaiters.set(tabId, waiters);
    });
  }


  private async claimAndAttachTab(tabId: number): Promise<{ targetId: string; sessionId: string }> {
    const tab = this.tabs.get(tabId);
    if (!tab) {
      throw new Error(`tab ${tabId} is not available to this approved session`);
    }
    if (tab.attached) {
      return tab.attached;
    }
    if (tab.attaching) {
      return await tab.attaching;
    }
    const attaching = (async () => {
      // Target discovery is metadata-only. The extension claims this selected
      // snapshot tab into its session group before attaching chrome.debugger.
      await this.callExtension({ type: "attach", tabId });
      const targetId = targetIdForTab(tabId);
      const sessionId = `agent-tab-bridge-tab-${tabId}-${this.nextSessionOrdinal++}`;
      const attached = { targetId, sessionId };
      // Identity check, not just presence: the tab could have left the group and
      // rejoined under the same tabId while this attach was in flight, replacing
      // the TabState. Writing onto the new TabState would bind stale attach data.
      const current = this.tabs.get(tabId);
      if (current !== tab) {
        // Original tab vanished (or was recreated); best-effort detach the banner.
        void this.callExtension({ type: "detach", tabId }).catch(() => {});
        throw new Error(`tab ${tabId} closed during attach`);
      }
      current.attached = attached;
      return attached;
    })();
    tab.attaching = attaching;
    try {
      return await attaching;
    } finally {
      tab.attaching = undefined;
    }
  }

  private targetInfoForTab(tab: TabState, targetId: string): Record<string, unknown> {
    return {
      targetId,
      type: "page",
      title: tab.info.title,
      url: tab.info.url,
      // connectOverCDP owns this as a persistent default context, but still
      // asserts that attached page events carry a non-empty context id.
      browserContextId: BROWSER_CONTEXT_ID,
      attached: tab.attached !== undefined,
      canAccessOpener: false,
    };
  }

  private announceAttachedTab(
    tabId: number,
    targetId: string,
    sessionId: string,
    opts: { onlyAutoAttach: boolean; onlyClient?: CdpClientState },
  ): void {
    const tab = this.tabs.get(tabId);
    if (!tab) {
      return;
    }
    const event = {
      method: "Target.attachedToTarget",
      params: {
        sessionId,
        targetInfo: this.targetInfoForTab(tab, targetId),
        waitingForDebugger: false,
      },
    };
    const recipients = opts.onlyClient
      ? [opts.onlyClient]
      : [...this.clients].filter((client) => !opts.onlyAutoAttach || client.autoAttach);
    for (const client of recipients) {
      if (client.announcedSessions.has(sessionId)) {
        continue;
      }
      client.announcedSessions.add(sessionId);
      client.socket.send(JSON.stringify(event));
    }
  }

  private emitDetachedFromTarget(tabId: number, sessionId: string, targetId: string): void {
    const event = JSON.stringify({
      method: "Target.detachedFromTarget",
      params: { sessionId, targetId },
    });
    for (const client of this.clients) {
      if (client.announcedSessions.delete(sessionId)) {
        client.socket.send(event);
      }
    }
    // Playwright's page-scoped CDP sessions listen on their synthetic parent
    // browser session, so detach those aliases when the claimed tab goes.
    for (const [auxiliarySessionId, auxiliary] of this.auxiliaryTabSessions) {
      if (auxiliary.tabId !== tabId) {
        continue;
      }
      auxiliary.client.socket.send(
        JSON.stringify({
          sessionId: auxiliary.parentSessionId,
          method: "Target.detachedFromTarget",
          params: { sessionId: auxiliarySessionId, targetId },
        }),
      );
      this.auxiliaryTabSessions.delete(auxiliarySessionId);
    }
    // Reap this tab's child sessions (iframes/workers) by owner tabId. Callers
    // clear tab.attached before/around this, so matching on the root sessionId
    // would miss every child and leak the childSessions map. Deleting the
    // current key during Map iteration is safe.
    for (const [childSessionId, ownerTabId] of this.childSessions) {
      if (ownerTabId !== tabId) {
        continue;
      }
      this.childSessions.delete(childSessionId);
      for (const client of this.clients) {
        client.announcedSessions.delete(childSessionId);
      }
    }
  }

  private forwardExtensionEvent(
    tabId: number,
    childSessionId: string | undefined,
    method: string,
    params: unknown,
  ): void {
    const tab = this.tabs.get(tabId);
    const rootSessionId = tab?.attached?.sessionId;
    if (!rootSessionId) {
      return;
    }
    const sessionId = childSessionId ?? rootSessionId;
    if (childSessionId) {
      this.childSessions.set(childSessionId, tabId);
    }
    // Child sessions announced through a parent's Target.attachedToTarget event
    // must stay routable for clients that saw the parent announcement.
    if (method === "Target.attachedToTarget") {
      const announced = (params as { sessionId?: unknown } | null)?.sessionId;
      if (typeof announced === "string") {
        this.childSessions.set(announced, tabId);
        for (const client of this.clients) {
          if (client.announcedSessions.has(sessionId)) {
            client.announcedSessions.add(announced);
          }
        }
      }
    }
    const frame = JSON.stringify({ sessionId, method, params });
    for (const client of this.clients) {
      if (client.announcedSessions.has(sessionId)) {
        client.socket.send(frame);
      }
    }
    if (!childSessionId) {
      // Page-scoped CDP sessions multiplex the same chrome.debugger root.
      // Mirror root events so Runtime/Page/Network listeners observe the
      // domains they enabled through their own synthetic session.
      for (const [auxiliarySessionId, auxiliary] of this.auxiliaryTabSessions) {
        if (auxiliary.tabId === tabId) {
          auxiliary.client.socket.send(
            JSON.stringify({ sessionId: auxiliarySessionId, method, params }),
          );
        }
      }
    }
  }

  // ---------------------------------------------------------------------
  // CDP client side (Playwright connectOverCDP)
  // ---------------------------------------------------------------------

  /** Wire up a newly accepted CDP client WebSocket. */
  attachCdpClientSocket(socket: BridgeSocket): {
    onMessage: (raw: string) => void;
    onClose: () => void;
  } {
    const client: CdpClientState = { socket, autoAttach: false, announcedSessions: new Set() };
    if (this.closing || this.disposed) {
      socket.close(1001, "relay stopped");
      return { onMessage: () => {}, onClose: () => {} };
    }
    this.clients.add(client);
    const onMessage = (raw: string) => {
      if (this.closing || this.disposed) {
        return;
      }
      let parsed: unknown;
      try {
        parsed = JSON.parse(raw);
      } catch {
        client.socket.send(toErrorPayload(null, undefined, "Parse error", -32700));
        return;
      }
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
        client.socket.send(toErrorPayload(null, undefined, "Invalid request", -32600));
        return;
      }
      const request = parsed as Record<string, unknown>;
      if (typeof request.id !== "number" || typeof request.method !== "string") {
        const id = typeof request.id === "number" ? request.id : null;
        const sessionId = typeof request.sessionId === "string" ? request.sessionId : undefined;
        // Flat CDP routes responses by sessionId before matching the request id.
        client.socket.send(toErrorPayload(id, sessionId, "Invalid request", -32600));
        return;
      }
      void this.handleCdpRequest(client, request as CdpRequest);
    };
    const onClose = () => {
      this.clients.delete(client);
      for (const [sessionId, owner] of this.browserSessions) {
        if (owner === client) {
          this.browserSessions.delete(sessionId);
        }
      }
      for (const [sessionId, auxiliary] of this.auxiliaryTabSessions) {
        if (auxiliary.client === client) {
          this.auxiliaryTabSessions.delete(sessionId);
        }
      }
      this.detachAllWhenIdle();
    };
    return { onMessage, onClose };
  }

  /**
   * Drop chrome.debugger sessions once no CDP client is connected so the
   * "Agent Tab Bridge is debugging this browser" infobar only spans active
   * automation.
   */
  private detachAllWhenIdle(): void {
    if (this.clients.size > 0 || !this.extension) {
      return;
    }
    for (const [tabId, tab] of this.tabs) {
      if (tab.attached) {
        const { sessionId, targetId } = tab.attached;
        tab.attached = undefined;
        this.emitDetachedFromTarget(tabId, sessionId, targetId);
        void this.callExtension({ type: "detach", tabId }).catch(() => {});
      }
    }
  }

  private respond(client: CdpClientState, request: CdpRequest, result: unknown): void {
    client.socket.send(
      JSON.stringify({
        id: request.id,
        ...(request.sessionId ? { sessionId: request.sessionId } : {}),
        result: result ?? {},
      }),
    );
  }

  private respondError(
    client: CdpClientState,
    request: CdpRequest,
    message: string,
    code = -32000,
  ): void {
    client.socket.send(toErrorPayload(request.id, request.sessionId, message, code));
  }

  private tabBySessionId(sessionId: string): { tabId: number; child: boolean } | null {
    for (const [tabId, tab] of this.tabs) {
      if (tab.attached?.sessionId === sessionId) {
        return { tabId, child: false };
      }
    }
    const auxiliary = this.auxiliaryTabSessions.get(sessionId);
    if (auxiliary) {
      return { tabId: auxiliary.tabId, child: false };
    }
    const childOwner = this.childSessions.get(sessionId);
    if (childOwner !== undefined) {
      return { tabId: childOwner, child: true };
    }
    return null;
  }

  private tabByTargetId(targetId: string): { tabId: number; tab: TabState } | null {
    for (const [tabId, tab] of this.tabs) {
      if (targetIdForTab(tabId) === targetId) {
        return { tabId, tab };
      }
    }
    return null;
  }

  private async handleCdpRequest(client: CdpClientState, request: CdpRequest): Promise<void> {
    try {
      if (request.sessionId) {
        if (this.browserSessions.get(request.sessionId) === client) {
          await this.handleBrowserScopedRequest(client, request);
          return;
        }
        await this.handleSessionScopedRequest(client, request);
        return;
      }
      await this.handleBrowserScopedRequest(client, request);
    } catch (err) {
      this.respondError(client, request, err instanceof Error ? err.message : String(err));
    }
  }

  private async handleSessionScopedRequest(
    client: CdpClientState,
    request: CdpRequest,
  ): Promise<void> {
    if (classifyCdpMethod(request.method, "page") === CdpMethodPolicy.Deny) {
      this.respondError(
        client,
        request,
        CDP_METHOD_POLICY_ERROR,
        CDP_METHOD_POLICY_ERROR_CODE,
      );
      return;
    }
    const sessionId = request.sessionId as string;
    const auxiliary = this.auxiliaryTabSessions.get(sessionId);
    if (auxiliary && auxiliary.client !== client) {
      this.respondError(client, request, `Session not found: ${sessionId}`, -32001);
      return;
    }
    const route = this.tabBySessionId(sessionId);
    if (!route) {
      this.respondError(client, request, `Session not found: ${sessionId}`, -32001);
      return;
    }
    const result = await this.callExtension({
      type: "cdp",
      tabId: route.tabId,
      ...(route.child ? { sessionId } : {}),
      method: request.method,
      params: request.params,
    });
    this.respond(client, request, result);
  }

  private async handleBrowserScopedRequest(
    client: CdpClientState,
    request: CdpRequest,
  ): Promise<void> {
    if (classifyCdpMethod(request.method, "browser") === CdpMethodPolicy.Deny) {
      this.respondError(
        client,
        request,
        CDP_METHOD_POLICY_ERROR,
        CDP_METHOD_POLICY_ERROR_CODE,
      );
      return;
    }
    switch (request.method) {
      case "Browser.getVersion": {
        const identity = this.extension?.identity;
        this.respond(client, request, {
          protocolVersion: "1.3",
          product: identity?.browserVersion ?? "Brave/unknown",
          revision: "agent-tab-bridge-relay",
          userAgent: identity?.userAgent ?? "unknown",
          jsVersion: "",
        });
        return;
      }
      case "Browser.close": {
        // Safe relay-local cleanup for clients such as Playwright.
        this.respond(client, request, {});
        client.socket.close(1000, "Browser.close");
        return;
      }
      case "Target.setDiscoverTargets": {
        // Intentionally a no-op: approved-session targets are always bridge-synthesized.
        this.respond(client, request, {});
        return;
      }
      case "Target.getTargetInfo": {
        const targetId = request.params?.targetId as string | undefined;
        if (!targetId || targetId === BROWSER_TARGET_ID) {
          this.respond(client, request, {
            targetInfo: {
              targetId: BROWSER_TARGET_ID,
              type: "browser",
              title: "Agent Tab Bridge",
              url: "",
              attached: true,
              canAccessOpener: false,
            },
          });
          return;
        }
        const found = this.tabByTargetId(targetId);
        if (!found) {
          this.respondError(client, request, `No target with given id found: ${targetId}`, -32602);
          return;
        }
        this.respond(client, request, {
          targetInfo: this.targetInfoForTab(found.tab, targetId),
        });
        return;
      }
      case "Target.getTargets": {
        const targetInfos = [...this.tabs.entries()]
          .map(([tabId, tab]) => this.targetInfoForTab(tab, targetIdForTab(tabId)));
        this.respond(client, request, { targetInfos });
        return;
      }
      case "Target.attachToBrowserTarget": {
        const sessionId = `agent-tab-bridge-browser-${this.nextSessionOrdinal++}`;
        this.browserSessions.set(sessionId, client);
        this.respond(client, request, { sessionId });
        return;
      }
      case "Target.setAutoAttach": {
        const autoAttach = request.params?.autoAttach !== false;
        client.autoAttach = autoAttach;
        if (autoAttach) {
          const attachResults = await Promise.allSettled(
            [...this.tabs.keys()].map(async (tabId) => {
              const { targetId, sessionId } = await this.claimAndAttachTab(tabId);
              return { tabId, targetId, sessionId };
            }),
          );
          for (const settled of attachResults) {
            if (settled.status === "fulfilled") {
              this.announceAttachedTab(
                settled.value.tabId,
                settled.value.targetId,
                settled.value.sessionId,
                {
                  onlyAutoAttach: false,
                  onlyClient: client,
                },
              );
          }
          }
        }
        this.respond(client, request, {});
        return;
      }
      case "Target.attachToTarget": {
        const targetId = request.params?.targetId as string | undefined;
        const found = targetId ? this.tabByTargetId(targetId) : null;
        if (!found && targetId) {
          this.respondError(client, request, `No target with given id found: ${targetId}`, -32602);
          return;
        }
        if (!found) {
          this.respondError(client, request, "targetId is required", -32602);
          return;
        }
        const attached = await this.claimAndAttachTab(found.tabId);
        if (request.sessionId && this.browserSessions.get(request.sessionId) === client) {
          // Playwright creates a fresh page-scoped session for helpers such as
          // Target.getTargetInfo and DOM refs. Multiplex it onto the one real
          // chrome.debugger attachment instead of reusing the auto-attach id.
          const sessionId = `agent-tab-bridge-tab-${found.tabId}-${this.nextSessionOrdinal++}`;
          this.auxiliaryTabSessions.set(sessionId, {
            tabId: found.tabId,
            parentSessionId: request.sessionId,
            client,
          });
          this.respond(client, request, { sessionId });
          return;
        }
        this.announceAttachedTab(found.tabId, attached.targetId, attached.sessionId, {
          onlyAutoAttach: false,
          onlyClient: client,
        });
        this.respond(client, request, { sessionId: attached.sessionId });
        return;
      }
      case "Target.detachFromTarget": {
        const sessionId = request.params?.sessionId as string | undefined;
        if (sessionId && this.browserSessions.get(sessionId) === client) {
          this.browserSessions.delete(sessionId);
          for (const [auxiliarySessionId, auxiliary] of this.auxiliaryTabSessions) {
            if (auxiliary.parentSessionId === sessionId && auxiliary.client === client) {
              this.auxiliaryTabSessions.delete(auxiliarySessionId);
            }
          }
          this.respond(client, request, {});
          return;
        }
        const auxiliary = sessionId ? this.auxiliaryTabSessions.get(sessionId) : undefined;
        if (auxiliary?.client === client) {
          this.auxiliaryTabSessions.delete(sessionId as string);
          this.respond(client, request, {});
          return;
        }
        if (auxiliary) {
          this.respondError(client, request, `Session not found: ${String(sessionId)}`, -32001);
          return;
        }
        const route = sessionId ? this.tabBySessionId(sessionId) : null;
        if (route && !route.child) {
          const tab = this.tabs.get(route.tabId);
          if (tab?.attached) {
            const { sessionId: rootSession, targetId } = tab.attached;
            tab.attached = undefined;
            this.emitDetachedFromTarget(route.tabId, rootSession, targetId);
            await this.callExtension({ type: "detach", tabId: route.tabId }).catch(() => {});
          }
        }
        this.respond(client, request, {});
        return;
      }
      case "Target.createTarget": {
        const url = typeof request.params?.url === "string" ? request.params.url : "about:blank";
        const createParams = resolveCreateTargetParams(request.params);
        const command = { type: "createTab", url, ...createParams } as const;
        const created = (await this.callExtension(command)) as { tabId?: unknown } | null;
        const createdTabId =
          created && typeof created.tabId === "number" && Number.isSafeInteger(created.tabId)
            ? created.tabId
            : null;
        if (createdTabId === null) {
          this.respondError(client, request, "extension did not return a valid tabId for createTab");
          return;
        }
        await this.waitForReportedTab(createdTabId);
        this.respond(client, request, { targetId: targetIdForTab(createdTabId) });
        return;
      }
      case "Target.closeTarget": {
        const targetId = request.params?.targetId as string | undefined;
        const found = targetId ? this.tabByTargetId(targetId) : null;
        if (!found) {
          this.respondError(
            client,
            request,
            `No target with given id found: ${String(targetId)}`,
            -32602,
          );
          return;
        }
        await this.callExtension({ type: "closeTab", tabId: found.tabId });
        this.respond(client, request, { success: true });
        return;
      }
      case "Target.activateTarget": {
        const targetId = request.params?.targetId as string | undefined;
        const found = targetId ? this.tabByTargetId(targetId) : null;
        if (!found) {
          this.respondError(
            client,
            request,
            `No target with given id found: ${String(targetId)}`,
            -32602,
          );
          return;
        }
        await this.callExtension({ type: "activateTab", tabId: found.tabId });
        this.respond(client, request, {});
        return;
      }
      default: {
        this.respondError(client, request, `'${request.method}' wasn't found`, -32601);
      }
    }
  }

  /** Close attached debugger sessions, sockets, and reject pending work. */
  dispose(): Promise<void> {
    if (!this.disposePromise) {
      this.closing = true;
      this.disposePromise = this.disposeNow();
    }
    return this.disposePromise;
  }

  private async disposeNow(): Promise<void> {
    this.stopPing();
    const attachedTabIds = [...this.tabs].flatMap(([tabId, tab]) =>
      tab.attached ? [tabId] : [],
    );

    for (const pending of this.pendingExtension.values()) {
      clearTimeout(pending.timer);
      pending.reject(new Error("Agent Tab Bridge relay stopped"));
    }
    this.pendingExtension.clear();
    for (const [tabId, waiters] of this.tabWaiters) {
      for (const waiter of waiters) {
        clearTimeout(waiter.timer);
        waiter.reject(new Error(`tab ${tabId} is no longer available to this approved session`));
      }
    }
    this.tabWaiters.clear();

    // Withdraw the CDP capability before waiting for best-effort debugger
    // detach commands. Requests arriving during that wait must not forward.
    for (const client of this.clients) {
      client.socket.close(1001, "relay stopped");
    }
    this.clients.clear();
    this.browserSessions.clear();
    this.auxiliaryTabSessions.clear();
    this.tabs.clear();
    this.childSessions.clear();

    const detachPromise =
      this.extension && attachedTabIds.length > 0
        ? Promise.allSettled(
            attachedTabIds.map((tabId) => this.callExtension({ type: "detach", tabId })),
          )
        : Promise.resolve([]);
    let timeout!: NodeJS.Timeout;
    await Promise.race([
      detachPromise,
      new Promise<void>((resolve) => {
        timeout = setTimeout(resolve, EXTENSION_DISPOSE_TIMEOUT_MS);
        timeout.unref?.();
      }),
    ]);
    clearTimeout(timeout);
    for (const pending of this.pendingExtension.values()) {
      clearTimeout(pending.timer);
      pending.reject(new Error("Agent Tab Bridge relay stopped"));
    }
    this.pendingExtension.clear();
    this.extension?.socket.close(1001, "relay stopped");
    this.extension = null;
    this.disposed = true;
  }
}

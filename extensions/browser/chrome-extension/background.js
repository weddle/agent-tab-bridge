import {
  AGENT_TAB_GROUP_TITLE,
  buildRelayWsProtocols,
  parsePairingString,
  reconnectDelayMs,
  toRelayTabInfo,
} from "./modules/relay-core.js";

const BADGE = {
  off: { text: "", color: "#000000" },
  connecting: { text: "…", color: "#F59E0B" },
  on: { text: "ON", color: "#0F9D58" },
  error: { text: "!", color: "#B91C1C" },
};
const RELAY_WATCHDOG_ALARM = "agent-tab-bridge-relay-watchdog";
const RELAY_OPENING_DEADLINE_ALARM = "agent-tab-bridge-relay-opening-deadline";
const RELAY_OPENING_TIMEOUT_MS = 30_000;
const AGENT_TAB_GROUP_COLOR = "blue";

/** @type {WebSocket | null} */
let relayWs = null;
let relayState = "off";
let reconnectAttempt = 0;
let reconnectTimer = null;
let relayOpeningDeadlineAt = 0;
let pairingRevision = 0;
let tabsSyncTimer = null;

/** Tab ids with an active chrome.debugger attachment owned by this worker. */
const attachedTabs = new Set();
/** In-flight attach promises per tab id, to coalesce concurrent relay commands. */
const attachingTabs = new Map();

function setBadge(kind) {
  relayState = kind;
  const badge = BADGE[kind] ?? BADGE.off;
  void chrome.action.setBadgeText({ text: badge.text });
  void chrome.action.setBadgeBackgroundColor({ color: badge.color });
}

function stopReconnect() {
  if (reconnectTimer) {
    clearTimeout(reconnectTimer);
    reconnectTimer = null;
  }
}

async function closeRelaySocket() {
  const socket = relayWs;
  relayWs = null;
  if (socket) {
    try {
      socket.close();
    } catch {
      // The socket can change state while an extension event is queued.
    }
  }
  await detachTrackedTabs();
}

function send(message) {
  if (relayWs?.readyState === WebSocket.OPEN) {
    relayWs.send(JSON.stringify(message));
  }
}

async function getConfig() {
  const stored = await chrome.storage.session.get(["relayUrl", "token"]);
  return {
    relayUrl: typeof stored.relayUrl === "string" ? stored.relayUrl : "",
    token: typeof stored.token === "string" ? stored.token : "",
  };
}

async function hasPairing() {
  const { relayUrl, token } = await getConfig();
  return Boolean(relayUrl && token);
}

// ---------------------------------------------------------------------------
// Agent Tabs group management: group membership is the consent boundary.
// ---------------------------------------------------------------------------

async function findAgentTabGroups() {
  try {
    return await chrome.tabGroups.query({ title: AGENT_TAB_GROUP_TITLE });
  } catch {
    return [];
  }
}

async function listSharedTabs() {
  const groups = await findAgentTabGroups();
  const tabs = [];
  for (const group of groups) {
    try {
      tabs.push(...(await chrome.tabs.query({ groupId: group.id })));
    } catch {
      // A tab group can disappear while a tab-list refresh is in progress.
    }
  }
  return tabs.filter((tab) => typeof tab.id === "number");
}

async function isAgentTabGroupId(groupId) {
  if (!Number.isInteger(groupId) || groupId < 0) {
    return false;
  }
  try {
    const group = await chrome.tabGroups.get(groupId);
    return group.title === AGENT_TAB_GROUP_TITLE;
  } catch {
    return false;
  }
}

async function isTabShared(tabId) {
  try {
    const tab = await chrome.tabs.get(tabId);
    return await isAgentTabGroupId(tab.groupId);
  } catch {
    return false;
  }
}

async function addTabToAgentGroup(tabId) {
  const tab = await chrome.tabs.get(tabId);
  if (await isAgentTabGroupId(tab.groupId)) {
    return;
  }

  const groups = await findAgentTabGroups();
  const groupInWindow = groups.find((group) => group.windowId === tab.windowId);
  if (groupInWindow) {
    await chrome.tabs.group({ tabIds: [tabId], groupId: groupInWindow.id });
    return;
  }

  const groupId = await chrome.tabs.group({ tabIds: [tabId] });
  await chrome.tabGroups.update(groupId, {
    title: AGENT_TAB_GROUP_TITLE,
    color: AGENT_TAB_GROUP_COLOR,
  });
}

async function removeTabFromAgentGroup(tabId) {
  if (!(await isTabShared(tabId))) {
    return;
  }
  try {
    await chrome.tabs.ungroup([tabId]);
  } catch {
    // The tab may have closed or been moved before this revocation completed.
  }
}

async function focusWindowForTab(tab) {
  if (typeof tab.windowId === "number") {
    await chrome.windows.update(tab.windowId, { focused: true });
  }
}

function scheduleTabsSync() {
  if (tabsSyncTimer) {
    return;
  }
  tabsSyncTimer = setTimeout(() => {
    tabsSyncTimer = null;
    void syncTabsToRelay();
  }, 150);
}

async function syncTabsToRelay() {
  const sharedTabs = await listSharedTabs();
  const sharedIds = new Set(sharedTabs.map((tab) => tab.id));

  // A tab outside Agent Tabs must never retain a debugger attachment, even if
  // the relay is offline while the user changes a group.
  await Promise.all(
    [...attachedTabs]
      .filter((tabId) => !sharedIds.has(tabId))
      .map((tabId) => detachDebugger(tabId)),
  );

  send({ type: "tabs", tabs: sharedTabs.map(toRelayTabInfo) });
}

// ---------------------------------------------------------------------------
// chrome.debugger transport
// ---------------------------------------------------------------------------

async function assertTabMayBeControlled(tabId) {
  if (!(await isTabShared(tabId))) {
    await detachDebugger(tabId);
    throw new Error(`tab ${tabId} is not in the ${AGENT_TAB_GROUP_TITLE} group`);
  }
}

async function attachDebugger(tabId) {
  const inFlight = attachingTabs.get(tabId);
  if (inFlight) {
    return await inFlight;
  }

  const attachRevision = pairingRevision;
  const attach = (async () => {
    if (!(await hasPairing()) || attachRevision !== pairingRevision) {
      throw new Error("Extension is not paired.");
    }
    await assertTabMayBeControlled(tabId);

    if (!attachedTabs.has(tabId)) {
      try {
        await chrome.debugger.attach({ tabId }, "1.3");
      } catch (error) {
        // An MV3 worker can restart while its existing debugger attachment
        // remains active. In that case Chrome reports the same conflict.
        if (!String(error?.message ?? error).includes("Another debugger is already attached")) {
          throw error;
        }
      }

      if (attachRevision !== pairingRevision || !(await isTabShared(tabId))) {
        await detachDebugger(tabId);
        throw new Error("Tab access was revoked while attaching.");
      }
      attachedTabs.add(tabId);
    }

    const targets = await chrome.debugger.getTargets();
    const target = targets.find((candidate) => candidate.tabId === tabId && candidate.attached);
    return { targetId: target?.id ?? `tab-${tabId}` };
  })();

  attachingTabs.set(tabId, attach);
  try {
    return await attach;
  } finally {
    attachingTabs.delete(tabId);
  }
}

async function detachDebugger(tabId) {
  // Delete before detach so an intentional unshare/unpair does not turn the
  // expected onDetach event into a second group revocation.
  attachedTabs.delete(tabId);
  try {
    await chrome.debugger.detach({ tabId });
  } catch {
    // The tab may be gone, or Chrome may already have detached it.
  }
}

async function detachTrackedTabs() {
  await Promise.all([...attachedTabs].map((tabId) => detachDebugger(tabId)));
}

async function unshareTab(tabId) {
  await detachDebugger(tabId);
  await removeTabFromAgentGroup(tabId);
  scheduleTabsSync();
}

async function forwardDebuggerEvent(source, method, params) {
  if (typeof source.tabId !== "number" || !attachedTabs.has(source.tabId)) {
    return;
  }
  if (!(await isTabShared(source.tabId))) {
    await detachDebugger(source.tabId);
    return;
  }
  send({
    type: "cdpEvent",
    tabId: source.tabId,
    ...(source.sessionId ? { sessionId: source.sessionId } : {}),
    method,
    params,
  });
}

chrome.debugger.onEvent.addListener((source, method, params) => {
  void forwardDebuggerEvent(source, method, params);
});

chrome.debugger.onDetach.addListener((source, reason) => {
  if (typeof source.tabId !== "number" || !attachedTabs.delete(source.tabId)) {
    return;
  }

  // A debugger attachment disappearing outside an explicit unshare/unpair is
  // a consent revocation. Remove it from Agent Tabs before notifying the relay.
  void (async () => {
    if (!(await isTabShared(source.tabId))) {
      return;
    }
    await removeTabFromAgentGroup(source.tabId);
    await syncTabsToRelay();
    send({ type: "detached", tabId: source.tabId, reason });
  })();
});

// ---------------------------------------------------------------------------
// Relay connection
// ---------------------------------------------------------------------------

function clearRelayOpeningDeadline() {
  relayOpeningDeadlineAt = 0;
  void chrome.alarms.clear(RELAY_OPENING_DEADLINE_ALARM);
}

function armRelayOpeningDeadline() {
  relayOpeningDeadlineAt = Date.now() + RELAY_OPENING_TIMEOUT_MS;
  chrome.alarms.create(RELAY_OPENING_DEADLINE_ALARM, { when: relayOpeningDeadlineAt });
}

function scheduleReconnect() {
  if (reconnectTimer) {
    return;
  }
  const delay = reconnectDelayMs(reconnectAttempt);
  reconnectAttempt += 1;
  reconnectTimer = setTimeout(() => {
    reconnectTimer = null;
    void connectRelay();
  }, delay);
}

async function handleRelayCommand(message) {
  const seq = message?.seq;
  try {
    switch (message?.type) {
      case "ping":
        send({ type: "pong" });
        return;
      case "attach": {
        const result = await attachDebugger(message.tabId);
        send({ type: "result", seq, result });
        return;
      }
      case "detach":
        await detachDebugger(message.tabId);
        send({ type: "result", seq, result: {} });
        return;
      case "cdp": {
        if (!attachedTabs.has(message.tabId)) {
          throw new Error(`tab ${message.tabId} is not attached`);
        }
        await assertTabMayBeControlled(message.tabId);
        const target = message.sessionId
          ? { tabId: message.tabId, sessionId: message.sessionId }
          : { tabId: message.tabId };
        const result = await chrome.debugger.sendCommand(
          target,
          message.method,
          message.params ?? {},
        );
        send({ type: "result", seq, result: result ?? {} });
        return;
      }
      case "createTab": {
        const tab = await chrome.tabs.create({
          url: message.url,
          active: message.background !== true,
        });
        if (typeof tab.id !== "number") {
          throw new Error("Browser did not return a tab id.");
        }
        await addTabToAgentGroup(tab.id);
        if (message.focus === true) {
          await focusWindowForTab(tab);
        }
        send({ type: "result", seq, result: { tabId: tab.id } });
        // The relay treats this post-result snapshot as confirmation that the
        // browser has applied the consent group change.
        await syncTabsToRelay();
        return;
      }
      case "closeTab":
        await assertTabMayBeControlled(message.tabId);
        await detachDebugger(message.tabId);
        await chrome.tabs.remove(message.tabId);
        send({ type: "result", seq, result: {} });
        return;
      case "activateTab": {
        await assertTabMayBeControlled(message.tabId);
        const tab = await chrome.tabs.get(message.tabId);
        await chrome.tabs.update(message.tabId, { active: true });
        await focusWindowForTab(tab);
        send({ type: "result", seq, result: {} });
        return;
      }
      default:
        if (typeof seq === "number") {
          send({ type: "error", seq, message: `unknown relay command: ${message?.type}` });
        }
    }
  } catch (error) {
    if (typeof seq === "number") {
      send({ type: "error", seq, message: error instanceof Error ? error.message : String(error) });
    }
  }
}

async function sendHello() {
  const sharedTabs = await listSharedTabs();
  const version = /Brave\/[\d.]+/.exec(navigator.userAgent)?.[0] ?? "Brave";
  send({
    type: "hello",
    userAgent: navigator.userAgent,
    browserVersion: version,
    extensionVersion: chrome.runtime.getManifest().version,
    tabs: sharedTabs.map(toRelayTabInfo),
  });
}

async function connectRelay() {
  const { relayUrl, token } = await getConfig();
  if (!relayUrl || !token) {
    clearRelayOpeningDeadline();
    setBadge("off");
    return;
  }
  if (
    relayWs &&
    (relayWs.readyState === WebSocket.OPEN || relayWs.readyState === WebSocket.CONNECTING)
  ) {
    return;
  }

  setBadge("connecting");
  let socket;
  try {
    socket = new WebSocket(relayUrl, buildRelayWsProtocols(token));
  } catch {
    setBadge("error");
    scheduleReconnect();
    return;
  }

  relayWs = socket;
  armRelayOpeningDeadline();
  socket.addEventListener("open", () => {
    if (relayWs !== socket) {
      socket.close();
      return;
    }
    clearRelayOpeningDeadline();
    reconnectAttempt = 0;
    setBadge("on");
    void sendHello();
    void syncTabsToRelay();
  });
  socket.addEventListener("message", (event) => {
    let message;
    try {
      message = JSON.parse(String(event.data));
    } catch {
      return;
    }
    void handleRelayCommand(message);
  });
  socket.addEventListener("close", () => {
    if (relayWs !== socket) {
      return;
    }
    const closeRevision = pairingRevision;
    relayWs = null;
    clearRelayOpeningDeadline();
    setBadge("error");
    void detachTrackedTabs().finally(() => {
      if (pairingRevision === closeRevision) {
        scheduleReconnect();
      }
    });
  });
}

function handleRelayOpeningDeadline() {
  const socket = relayWs;
  if (!socket) {
    clearRelayOpeningDeadline();
    void connectRelay();
    return;
  }
  if (socket.readyState === WebSocket.OPEN) {
    clearRelayOpeningDeadline();
    return;
  }
  if (
    socket.readyState !== WebSocket.CONNECTING ||
    relayOpeningDeadlineAt === 0 ||
    Date.now() < relayOpeningDeadlineAt
  ) {
    return;
  }

  const closeRevision = pairingRevision;
  relayWs = null;
  clearRelayOpeningDeadline();
  try {
    socket.close();
  } catch {
    // The socket may have changed state while the alarm event was queued.
  }
  setBadge("error");
  void detachTrackedTabs().finally(() => {
    if (pairingRevision === closeRevision) {
      scheduleReconnect();
    }
  });
}

async function unpair() {
  pairingRevision += 1;
  stopReconnect();
  clearRelayOpeningDeadline();
  await closeRelaySocket();
  await chrome.storage.session.remove(["relayUrl", "token"]);
  setBadge("off");
}

// ---------------------------------------------------------------------------
// Popup messages and lifecycle.
// ---------------------------------------------------------------------------

function sendErrorResponse(sendResponse, error) {
  sendResponse({ ok: false, error: error instanceof Error ? error.message : String(error) });
}

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  void (async () => {
    switch (message?.type) {
      case "getStatus": {
        const paired = await hasPairing();
        const sharedTabs = await listSharedTabs();
        sendResponse({ paired, state: relayState, sharedTabCount: sharedTabs.length });
        return;
      }
      case "pair": {
        const parsed = parsePairingString(message.pairingString);
        if (!parsed) {
          sendResponse({ ok: false, error: "Invalid pairing string." });
          return;
        }
        pairingRevision += 1;
        stopReconnect();
        clearRelayOpeningDeadline();
        await closeRelaySocket();
        await chrome.storage.session.set(parsed);
        reconnectAttempt = 0;
        await connectRelay();
        sendResponse({ ok: true });
        return;
      }
      case "unpair":
        await unpair();
        sendResponse({ ok: true });
        return;
      case "toggleShareTab": {
        const tabId = message.tabId;
        if (!Number.isInteger(tabId)) {
          sendResponse({ ok: false, error: "No tab." });
          return;
        }
        if (await isTabShared(tabId)) {
          await unshareTab(tabId);
          sendResponse({ ok: true, shared: false });
        } else {
          await addTabToAgentGroup(tabId);
          scheduleTabsSync();
          sendResponse({ ok: true, shared: true });
        }
        return;
      }
      case "isTabShared":
        sendResponse({ shared: Number.isInteger(message.tabId) && (await isTabShared(message.tabId)) });
        return;
      default:
        sendResponse({ ok: false, error: "Unknown message." });
    }
  })().catch((error) => sendErrorResponse(sendResponse, error));
  return true;
});

chrome.tabs.onRemoved.addListener((tabId) => {
  attachedTabs.delete(tabId);
  scheduleTabsSync();
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  scheduleTabsSync();
  if (typeof changeInfo.groupId !== "number") {
    return;
  }
  void isAgentTabGroupId(changeInfo.groupId).then((isShared) => {
    if (!isShared) {
      void detachDebugger(tabId);
    }
  });
});

chrome.tabs.onActivated.addListener(() => scheduleTabsSync());
chrome.tabGroups.onUpdated.addListener(() => scheduleTabsSync());
chrome.tabGroups.onRemoved.addListener(() => scheduleTabsSync());

// MV3 service workers are ephemeral. The alarm revives a paired worker and
// restarts a dropped loopback connection without persisting any credentials.
chrome.alarms.create(RELAY_WATCHDOG_ALARM, { periodInMinutes: 0.5 });
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === RELAY_WATCHDOG_ALARM) {
    void connectRelay();
  } else if (alarm.name === RELAY_OPENING_DEADLINE_ALARM) {
    handleRelayOpeningDeadline();
  }
});
chrome.runtime.onStartup.addListener(() => void connectRelay());
chrome.runtime.onInstalled.addListener(() => void connectRelay());

void connectRelay();

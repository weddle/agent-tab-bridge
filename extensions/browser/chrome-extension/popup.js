const statusDot = document.getElementById("statusDot");
const connectionStatus = document.getElementById("connectionStatus");
const companionIdentity = document.getElementById("companionIdentity");
const pendingSessions = document.getElementById("pendingSessions");
const activeSessions = document.getElementById("activeSessions");
const sharePanel = document.getElementById("sharePanel");
const sessionChoice = document.getElementById("sessionChoice");
const shareButton = document.getElementById("shareButton");
const forgetCompanionButton = document.getElementById("forgetCompanionButton");
const errorLine = document.getElementById("error");

let state = {
  native: { state: "disconnected", companion: { id: null, name: null, trusted: false, pinned: false } },
  pendingSessions: [],
  activeSessions: [],
  sharedTabs: [],
};
let currentTab = null;
let refreshRevision = 0;

const CONNECTION_LABEL = {
  connected: "Companion connected",
  connecting: "Connecting to companion…",
  disconnected: "Companion disconnected",
  error: "Companion error; try again",
};

function makeElement(tag, className, text) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== undefined) element.textContent = text;
  return element;
}

function clear(element) {
  element.replaceChildren();
}

function abbreviate(value) {
  if (typeof value !== "string" || value.length === 0) return "Not available";
  if (value.length <= 16) return value;
  return `${value.slice(0, 8)}…${value.slice(-6)}`;
}

function safeError(error) {
  let message = error instanceof Error ? error.message : String(error ?? "Unknown error");
  message = message.replace(/\b(?:wss?|https?):\/\/\S+/gi, "local endpoint");
  message = message.replace(/\b[A-Za-z0-9+/=_-]{32,}\b/g, "redacted value");
  return message.length > 220 ? `${message.slice(0, 217)}…` : message;
}

function showError(error) {
  errorLine.textContent = `Action failed: ${safeError(error)}`;
  errorLine.classList.remove("hidden");
}

function hideError() {
  errorLine.textContent = "";
  errorLine.classList.add("hidden");
}

function timestamp(value) {
  if (typeof value === "number" && Number.isFinite(value)) {
    return value < 1_000_000_000_000 ? value * 1000 : value;
  }
  if (typeof value === "string") {
    const parsed = Date.parse(value);
    if (Number.isFinite(parsed)) return parsed;
  }
  return NaN;
}

function remainingMs(session) {
  const expires = timestamp(session?.expiresAt);
  return Number.isFinite(expires) ? Math.max(0, expires - Date.now()) : NaN;
}

function formatRemaining(session) {
  if (session?.expiresAt === null) return "Indefinite · no expiry";
  const remaining = remainingMs(session);
  if (!Number.isFinite(remaining)) return "Expiry unavailable";
  if (remaining <= 0) return "Expired; waiting for cleanup";
  const totalSeconds = Math.ceil(remaining / 1000);
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  if (minutes >= 60) {
    const hours = Math.floor(minutes / 60);
    return `${hours}h ${minutes % 60}m remaining`;
  }
  if (minutes > 0) return `${minutes}m ${seconds}s remaining`;
  return `${seconds}s remaining`;
}

function formatCapabilities(capabilities) {
  if (!Array.isArray(capabilities) || capabilities.length === 0) return "None requested";
  return capabilities.map((capability) => String(capability)).join(", ");
}

function controllerText(session) {
  const label = typeof session?.controllerName === "string" && session.controllerName
    ? session.controllerName
    : "Unnamed controller";
  const principal = typeof session?.controllerId === "string" && session.controllerId
    ? ` · principal ${abbreviate(session.controllerId)}`
    : "";
  return { label, principal };
}

function sessionCard(session, pending) {
  const card = makeElement("article", "card");
  const header = makeElement("div", "card-header");
  const task = makeElement("div", "task", session?.taskLabel || "Unnamed task");
  task.title = "Unverified task label";
  header.append(task, makeElement("span", "meta", formatRemaining(session)));
  card.append(header);

  const controller = controllerText(session);
  const label = makeElement("p", "label", `Unverified controller label: ${controller.label}`);
  label.title = "Display label only; not an authenticated identity";
  card.append(label);
  if (controller.principal) {
    card.append(makeElement("p", "meta", `Authenticated principal${controller.principal}`));
  }
  card.append(makeElement("p", "caps", `Requested capabilities: ${formatCapabilities(session?.capabilities)}`));
  if (!pending) {
    const health = typeof session?.health === "string" && session.health
      ? session.health
      : "active";
    card.append(makeElement("p", "meta", `Session health: ${health}`));
  }

  const actions = makeElement("div", "actions");
  if (pending) {
    const approve = makeElement("button", "primary", "Approve");
    approve.type = "button";
    approve.addEventListener("click", () => void mutate("approveSession", session?.id, approve));
    const decline = makeElement("button", "danger", "Decline");
    decline.type = "button";
    decline.addEventListener("click", () => void mutate("revokeSession", session?.id, decline));
    actions.append(approve, decline);
  } else {
    const revoke = makeElement("button", "danger", "Revoke session");
    revoke.type = "button";
    revoke.addEventListener("click", () => void mutate("revokeSession", session?.id, revoke));
    actions.append(revoke);
    const tabs = state.sharedTabs.filter((tab) => tab?.sessionId === session?.id);
    if (tabs.length > 0) {
      const tabList = makeElement("ul", "tabs");
      tabList.setAttribute("aria-label", "Shared tabs");
      for (const tab of tabs) {
        const item = makeElement("li");
        item.append(
          makeElement("span", "tab-id", `Tab ${String(tab?.tabId ?? "?")}`),
          makeElement("span", "tab-title", tab?.title || "Untitled tab"),
        );
        tabList.append(item);
      }
      card.append(tabList);
    } else {
      card.append(makeElement("p", "meta", "No shared tabs"));
    }
  }
  card.append(actions);
  return card;
}

function renderPending() {
  clear(pendingSessions);
  if (state.pendingSessions.length === 0) {
    pendingSessions.append(makeElement("p", "empty", "No pending approvals."));
    return;
  }
  for (const session of state.pendingSessions) pendingSessions.append(sessionCard(session, true));
}

function selectedSessionId() {
  return sessionChoice.value || state.activeSessions[0]?.id || "";
}

function renderActive() {
  clear(activeSessions);
  clear(sessionChoice);
  if (state.activeSessions.length === 0) {
    activeSessions.append(makeElement("p", "empty", "No active sessions."));
    sharePanel.classList.add("hidden");
    shareButton.disabled = true;
    return;
  }
  sharePanel.classList.remove("hidden");
  for (const session of state.activeSessions) {
    activeSessions.append(sessionCard(session, false));
    const option = makeElement("option", "", session?.taskLabel || "Unnamed task");
    option.value = String(session?.id ?? "");
    option.textContent = `${session?.taskLabel || "Unnamed task"} · ${controllerText(session).label}`;
    sessionChoice.append(option);
  }
  if (state.activeSessions.length > 1) {
    sessionChoice.removeAttribute("aria-label");
  } else {
    sessionChoice.setAttribute("aria-label", "Active session");
  }
  updateShareControl();
}

function selectedSession() {
  const id = selectedSessionId();
  return state.activeSessions.find((session) => String(session?.id) === String(id)) ?? null;
}

function sharedTabForCurrent() {
  if (!Number.isInteger(currentTab?.id)) return null;
  return state.sharedTabs.find((tab) => Number(tab?.tabId) === currentTab.id) ?? null;
}

function updateShareControl() {
  const session = selectedSession();
  const shared = sharedTabForCurrent();
  const ownsCurrent = Boolean(session && shared && String(shared.sessionId) === String(session.id));
  const ownedByOther = Boolean(shared && !ownsCurrent);
  shareButton.textContent = ownsCurrent ? "Unshare current tab" : "Share current tab";
  shareButton.classList.toggle("danger", ownsCurrent);
  shareButton.classList.toggle("primary", !ownsCurrent);
  shareButton.disabled = !session || !Number.isInteger(currentTab?.id) || ownedByOther;
  if (ownedByOther) {
    shareButton.title = "Select the session that owns this tab to unshare it";
  } else {
    shareButton.removeAttribute("title");
  }
}

function render() {
  const native = state.native ?? {};
  const status = typeof native.state === "string" ? native.state : "disconnected";
  statusDot.className = `dot ${status}`;
  connectionStatus.textContent = CONNECTION_LABEL[status] ?? "Companion status unavailable";
  const companion = native.companion ?? {};
  const canForget = companion.trusted === true || companion.pinned === true;
  forgetCompanionButton.disabled = !canForget;
  if (companion.id) {
    const statusLabel = companion.trusted === true ? "Verified companion" : "Pinned companion (not connected)";
    companionIdentity.textContent = `${statusLabel}: ${abbreviate(companion.id)}${companion.name ? ` · ${companion.name}` : ""}`;
  } else if (companion.pinned === true) {
    companionIdentity.textContent = "Stored companion identity needs removal.";
  } else {
    companionIdentity.textContent = "No companion is pinned.";
  }
  renderPending();
  renderActive();
}

async function queryActiveTab() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
    return tab ?? null;
  } catch {
    return null;
  }
}

async function refresh() {
  const revision = ++refreshRevision;
  try {
    const result = await chrome.runtime.sendMessage({ type: "getStatus" });
    if (revision !== refreshRevision) return;
    if (!result?.ok) throw new Error(result?.error ?? "Companion state is unavailable.");
    state = {
      native: result.native ?? {},
      pendingSessions: Array.isArray(result.pendingSessions) ? result.pendingSessions : [],
      activeSessions: Array.isArray(result.activeSessions) ? result.activeSessions : [],
      sharedTabs: Array.isArray(result.sharedTabs) ? result.sharedTabs : [],
    };
    currentTab = await queryActiveTab();
    if (revision !== refreshRevision) return;
    render();
  } catch (error) {
    if (revision !== refreshRevision) return;
    showError(error);
  }
}

async function mutate(type, sessionId, button) {
  if (typeof sessionId !== "string" || sessionId.length === 0) {
    showError(new Error("The session is no longer available. Refresh and try again."));
    return;
  }
  hideError();
  button.disabled = true;
  try {
    const result = await chrome.runtime.sendMessage({ type, sessionId });
    if (!result?.ok) throw new Error(result?.error ?? "The companion rejected this action.");
    await refresh();
  } catch (error) {
    showError(error);
    button.disabled = false;
  }
}

async function onShare() {
  const session = selectedSession();
  if (!session || !Number.isInteger(currentTab?.id)) {
    showError(new Error("Select an active session and keep a browser tab active."));
    return;
  }
  const shared = sharedTabForCurrent();
  const ownsCurrent = shared && String(shared.sessionId) === String(session.id);
  if (shared && !ownsCurrent) {
    showError(new Error("This tab is already shared with another session. Select that session to unshare it first."));
    return;
  }
  hideError();
  shareButton.disabled = true;
  const type = ownsCurrent ? "unshareTab" : "shareTab";
  try {
    const result = await chrome.runtime.sendMessage({ type, sessionId: session.id, tabId: currentTab.id });
    if (!result?.ok) throw new Error(result?.error ?? "The companion rejected this tab action.");
    await refresh();
  } catch (error) {
    showError(error);
    shareButton.disabled = false;
  }
}

async function onForgetCompanion() {
  if (forgetCompanionButton.disabled) {
    return;
  }
  hideError();
  forgetCompanionButton.disabled = true;
  try {
    const result = await chrome.runtime.sendMessage({ type: "forgetCompanion" });
    if (!result?.ok) throw new Error(result?.error ?? "The companion could not be forgotten.");
    await refresh();
  } catch (error) {
    showError(error);
    await refresh();
  }
}


sessionChoice.addEventListener("change", updateShareControl);
shareButton.addEventListener("click", () => void onShare());
forgetCompanionButton.addEventListener("click", () => void onForgetCompanion());

void refresh();
setInterval(() => void refresh(), 2_000);

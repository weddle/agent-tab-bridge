/**
 * Agent Tab Bridge popup.
 *
 * Background runtime contract: getStatus, connectCompanion, approveSession,
 * revokeSession, shareTab, unshareTab, forgetCompanion.
 *
 * Rendering rule: the 2s poll reconciles session cards keyed by session id and
 * only rebuilds a card whose rendered content actually changed. A card is left
 * untouched while it holds keyboard focus or a text selection, or while one of
 * its own mutations is in flight, so a render tick can never steal focus or
 * re-enable a control the user just used.
 */

const statusDot = document.getElementById("statusDot");
const connectionStatus = document.getElementById("connectionStatus");
const companionIdentity = document.getElementById("companionIdentity");
const errorLine = document.getElementById("error");
const firstRun = document.getElementById("firstRun");
const connectButton = document.getElementById("connectCompanionButton");
const pendingSection = document.getElementById("pendingSection");
const pendingHeading = document.getElementById("pendingHeading");
const pendingList = document.getElementById("pendingSessions");
const accessSection = document.getElementById("accessSection");
const accessHeading = document.getElementById("accessHeading");
const accessList = document.getElementById("accessRequests");
const enrollSection = document.getElementById("enrollSection");
const enrollHeading = document.getElementById("enrollHeading");
const enrollList = document.getElementById("enrollRequests");
const activeSection = document.getElementById("activeSection");
const activeHeading = document.getElementById("activeHeading");
const activeList = document.getElementById("activeSessions");
const activeEmpty = document.getElementById("activeEmpty");
const deviceIdentity = document.getElementById("deviceIdentity");
const forgetButton = document.getElementById("forgetCompanionButton");
const forgetAnnounce = document.getElementById("forgetAnnounce");

const profilesBlock = document.getElementById("profilesBlock");
const profilesList = document.getElementById("profilesList");
const grantsBlock = document.getElementById("grantsBlock");
const grantsList = document.getElementById("grantsList");
const POLL_INTERVAL_MS = 2_000;
const FORGET_CONFIRM_MS = 5_000;
const DEVICE_KEY = "\u0000device";
const UNIT = "\u0000";

let state = {
  native: { state: "disconnected", companion: { id: null, name: null, trusted: false, pinned: false } },
  pendingSessions: [],
  activeSessions: [],
  pendingAccess: [],
  pendingEnrollments: [],
  enrolledProfiles: [],
  standingGrants: [],
  sharedTabs: [],
};
let currentTab = null;
let refreshRevision = 0;
let errorText = "";
let forgetConfirmTimer = null;
const CONNECT_KEY = "\u0000connect";

/** Keys with a mutation in flight; their controls are off-limits to renders. */
const inFlight = new Set();
/** Session ids whose Details disclosure the user opened. */
const openDetails = new Set();
/** Session id -> { node, remainingEl, signature } */
const pendingCards = new Map();
const accessCards = new Map();
const enrollCards = new Map();
const activeCards = new Map();

function makeElement(tag, className, text) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== undefined) element.textContent = text;
  return element;
}

function makeButton(label, variant) {
  const button = document.createElement("button");
  button.type = "button";
  button.className = `atb-btn atb-btn--${variant}`;
  button.textContent = label;
  return button;
}

/** Never write text that is already there: aria-live must not re-announce. */
function setText(element, text) {
  if (element.textContent !== text) element.textContent = text;
}

function setHidden(element, hidden) {
  element.classList.toggle("hidden", hidden);
}

function abbreviate(value) {
  if (typeof value !== "string" || value.length === 0) return "Not available";
  if (value.length <= 16) return value;
  return `${value.slice(0, 8)}…${value.slice(-6)}`;
}

function plural(count, noun) {
  return count === 1 ? noun : `${noun}s`;
}

function safeError(error) {
  let message = error instanceof Error ? error.message : String(error ?? "Unknown error");
  message = message.replace(/\b(?:wss?|https?):\/\/\S+/gi, "local endpoint");
  message = message.replace(/\b[A-Za-z0-9+/=_-]{32,}\b/g, "redacted value");
  return message.length > 220 ? `${message.slice(0, 217)}…` : message;
}

function showError(error) {
  errorText = `Action failed: ${safeError(error)}`;
  setText(errorLine, errorText);
  setHidden(errorLine, false);
  renderStatus();
}

/** Contract §2.2: the error region is cleared by the next successful refresh. */
function clearError() {
  if (errorText === "") return;
  errorText = "";
  setText(errorLine, "");
  setHidden(errorLine, true);
  renderStatus();
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
function accessLevel(session) {
  return ["selectedTabs", "domains", "full"].includes(session?.access?.level)
    ? session.access.level
    : "selectedTabs";
}

function formatAccess(session) {
  const access = session?.access;
  if (accessLevel(session) === "full") return "Full website access — any website tab";
  if (accessLevel(session) === "domains") {
    return `Sites: ${(access?.domains ?? []).join(", ")} (including subdomains)`;
  }
  const tabIds = access?.tabIds ?? [];
  return tabIds.length
    ? `Selected tabs: ${tabIds.map((tabId) => `Tab ${tabId}`).join(", ")}`
    : "Selected tabs only — share tabs manually";
}


function sessionKey(session) {
  return typeof session?.id === "string" ? session.id : "";
}

function taskLabel(session) {
  return session?.taskLabel || "Unnamed task";
}

function controllerLabel(session) {
  return session?.controllerName || "Unnamed controller";
}

function healthText(session) {
  if (typeof session?.health === "string" && session.health) return session.health;
  if (typeof session?.state === "string" && session.state) return session.state;
  return "active";
}

function tabsForSession(id) {
  return state.sharedTabs.filter((tab) => String(tab?.sessionId) === id);
}

function sharedTabForCurrent() {
  if (!Number.isInteger(currentTab?.id)) return null;
  return state.sharedTabs.find((tab) => Number(tab?.tabId) === currentTab.id) ?? null;
}

/**
 * Per-card share control state. This replaces the old global session picker
 * and share panel entirely: ownership of the current tab decides the label,
 * so a poll tick can no longer reset which session a share would target.
 */
function shareMode(session) {
  const id = sessionKey(session);
  if (!Number.isInteger(currentTab?.id)) {
    return {
      action: "shareTab",
      label: "Share current tab",
      variant: "primary",
      disabled: true,
      reason: "This page cannot be shared. Switch to a website tab and try again.",
    };
  }
  const shared = sharedTabForCurrent();
  if (shared && String(shared.sessionId) === id) {
    return {
      action: "unshareTab",
      label: "Unshare current tab",
      variant: "secondary",
      disabled: false,
      reason: "",
    };
  }
  if (shared) {
    const owner = state.activeSessions.find((other) => sessionKey(other) === String(shared.sessionId));
    const ownerLabel = owner ? taskLabel(owner) : "another session";
    return {
      action: "shareTab",
      label: "Share current tab",
      variant: "primary",
      disabled: true,
      reason: `This tab is shared with “${ownerLabel}” — unshare it from that session's card.`,
    };
  }
  return {
    action: "shareTab",
    label: "Share current tab",
    variant: "primary",
    disabled: false,
    reason: "",
  };
}

/**
 * Everything a card renders except the ticking time remaining, which is
 * refreshed in place so the clock never forces a rebuild.
 */
function pendingSignature(session) {
  return [
    sessionKey(session),
    taskLabel(session),
    controllerLabel(session),
    typeof session?.controllerId === "string" ? session.controllerId : "",
    formatCapabilities(session?.capabilities),
    JSON.stringify(session?.access ?? null),
    state.enrolledProfiles.some((profile) => profile?.principalId === session?.controllerId) ? "enrolled" : "",
  ].join(UNIT);
}

function activeSignature(session) {
  const id = sessionKey(session);
  const share = shareMode(session);
  const tabs = tabsForSession(id)
    .map((tab) => `${String(tab?.tabId ?? "?")}:${tab?.title ?? ""}`)
    .join(UNIT);
  return [
    id,
    taskLabel(session),
    controllerLabel(session),
    typeof session?.controllerId === "string" ? session.controllerId : "",
    formatCapabilities(session?.capabilities),
    JSON.stringify(session?.access ?? null),
    healthText(session),
    tabs,
    share.label,
    share.variant,
    share.disabled ? "1" : "0",
    share.reason,
  ].join(UNIT);
}

function buildPendingCard(session) {
  const id = sessionKey(session);
  const card = makeElement("article", "atb-card card pending");
  card.classList.add(`access-${accessLevel(session)}`);

  const task = makeElement("div", "task", taskLabel(session));
  task.title = "Unverified task label";
  card.append(task);
  card.append(makeElement("p", "meta", `Requested by ${controllerLabel(session)} (unverified)`));
  if (typeof session?.controllerId === "string" && session.controllerId) {
    card.append(makeElement("p", "meta", `Principal ${abbreviate(session.controllerId)}`));
  }
  card.append(makeElement("p", "meta", `Capabilities: ${formatCapabilities(session?.capabilities)}`));
  card.append(makeElement("p", "access-summary", formatAccess(session)));
  const remainingEl = makeElement("p", "meta remaining", formatRemaining(session));
  card.append(remainingEl);

  let remember = null;
  const isEnrolledProfile = state.enrolledProfiles.some((profile) => profile?.principalId === session?.controllerId);
  if (isEnrolledProfile && accessLevel(session) !== "full") {
    const label = makeElement("label", "meta remember");
    remember = document.createElement("input");
    remember.type = "checkbox";
    remember.className = "atb-remember";
    label.append(remember, document.createTextNode(" Remember for this agent: auto-approve future sessions up to this level (never full access)"));
    card.append(label);
  }

  const decline = makeButton("Decline", "secondary");
  decline.addEventListener("click", () => void mutateSession("revokeSession", id, decline));
  const approve = makeButton("Approve", "primary");
  approve.addEventListener("click", () => void runMutation(id, approve, { type: "approveSession", sessionId: id, remember: remember?.checked === true }, "The companion rejected this action."));
  const actions = makeElement("div", "actions");
  actions.append(decline, approve);
  card.append(actions);

  return { node: card, remainingEl, signature: "" };
}

function buildActiveCard(session) {
  const id = sessionKey(session);
  const card = makeElement("article", "atb-card card");
  card.classList.add(`access-${accessLevel(session)}`);

  const header = makeElement("div", "card-header");
  const task = makeElement("div", "task", taskLabel(session));
  task.title = "Unverified task label";
  const remainingEl = makeElement("span", "remaining", formatRemaining(session));
  header.append(task, remainingEl);
  card.append(header);
  card.append(makeElement("p", "meta", `Requested by ${controllerLabel(session)} (unverified)`));
  card.append(makeElement("p", "access-summary", formatAccess(session)));

  card.append(makeElement("p", "list-label", "Tabs shared with this session"));
  const tabs = tabsForSession(id);
  if (tabs.length === 0) {
    card.append(makeElement("p", "meta", "No shared tabs"));
  } else {
    const list = makeElement("ul", "tabs");
    list.setAttribute("aria-label", "Tabs shared with this session");
    for (const tab of tabs) {
      const item = makeElement("li");
      item.append(
        makeElement("span", "tab-id", `Tab ${String(tab?.tabId ?? "?")}`),
        makeElement("span", "tab-sep", "—"),
        makeElement("span", "tab-title", tab?.title || "Untitled tab"),
      );
      list.append(item);
    }
    card.append(list);
  }

  const details = document.createElement("details");
  details.open = openDetails.has(id);
  details.addEventListener("toggle", () => {
    if (details.open) openDetails.add(id);
    else openDetails.delete(id);
  });
  details.append(
    makeElement("summary", undefined, "Details"),
    makeElement("p", "meta", `Principal ${abbreviate(session?.controllerId)}`),
    makeElement("p", "meta", `Capabilities: ${formatCapabilities(session?.capabilities)}`),
    makeElement("p", "meta", `Access: ${formatAccess(session)}`),
    makeElement("p", "meta", `Session health: ${healthText(session)}`),
    makeElement("p", "meta", `Session id ${abbreviate(session?.id)}`),
  );
  card.append(details);

  const share = shareMode(session);
  const shareButton = makeButton(share.label, share.variant);
  shareButton.disabled = share.disabled;
  if (share.reason) shareButton.title = share.reason;
  shareButton.addEventListener("click", () => void onShare(session, shareButton));
  const end = makeButton("End session", "secondary");
  end.addEventListener("click", () => void mutateSession("revokeSession", id, end));
  const actions = makeElement("div", "actions");
  actions.append(shareButton, end);
  card.append(actions);

  return { node: card, remainingEl, signature: "" };
}

function formatUpgrade(request) {
  if (request?.delta?.kind === "full") return "Upgrade to full website access";
  if (request?.delta?.kind === "domains") return `Add sites: ${(request.delta.domains ?? []).join(", ")} (including subdomains)`;
  return `Adopt tabs: ${(request?.delta?.tabIds ?? []).map((tabId) => `Tab ${tabId}`).join(", ")}`;
}

function accessSignature(request) {
  return [
    sessionKey(request),
    request?.sessionId ?? "",
    request?.taskLabel ?? "",
    request?.controllerName ?? "",
    JSON.stringify(request?.delta ?? null),
    JSON.stringify(request?.currentAccess ?? null),
    JSON.stringify(request?.requestedAccess ?? null),
  ].join(UNIT);
}

function buildAccessCard(request) {
  const id = sessionKey(request);
  const level = request?.requestedAccess?.level ?? "selectedTabs";
  const card = makeElement("article", `atb-card card pending access-${level}`);
  card.append(makeElement("div", "task", request?.taskLabel || "Unnamed task"));
  card.append(makeElement("p", "meta", `Requested by ${request?.controllerName || "Unnamed controller"} (unverified)`));
  card.append(makeElement("p", "access-summary", formatUpgrade(request)));
  const current = { access: request?.currentAccess };
  const requested = { access: request?.requestedAccess };
  card.append(makeElement("p", "meta", `Current access — ${formatAccess(current)}`));
  card.append(makeElement("p", "meta", `Approved access — ${formatAccess(requested)}`));
  const decline = makeButton("Decline", "secondary");
  decline.addEventListener("click", () => void mutateAccess("declineAccess", id, decline));
  const approve = makeButton("Approve upgrade", "primary");
  approve.addEventListener("click", () => void mutateAccess("approveAccess", id, approve));
  const actions = makeElement("div", "actions");
  actions.append(decline, approve);
  card.append(actions);
  return { node: card, remainingEl: null, signature: "" };
}

function enrollSignature(request) {
  return [
    sessionKey(request),
    request?.profileName ?? "",
    request?.profileFingerprint ?? "",
  ].join(UNIT);
}

function buildEnrollCard(request) {
  const id = sessionKey(request);
  const card = makeElement("article", "atb-card card pending access-selectedTabs");
  card.append(makeElement("div", "task", `Enroll agent profile "${request?.profileName ?? "unnamed"}"`));
  card.append(makeElement("p", "meta", `Key ${abbreviate(request?.profileFingerprint)}`));
  card.append(makeElement("p", "meta", "Enter the 6-digit code shown by the agent that requested enrollment. If you did not start that agent, ignore this request; it expires on its own."));
  const input = document.createElement("input");
  input.type = "text";
  input.inputMode = "numeric";
  input.autocomplete = "one-time-code";
  input.maxLength = 6;
  input.placeholder = "6-digit code";
  input.className = "atb-code-input";
  input.setAttribute("aria-label", `Pairing code for profile ${request?.profileName ?? "unnamed"}`);
  const confirm = makeButton("Confirm enrollment", "primary");
  confirm.addEventListener("click", () => {
    const code = input.value.trim();
    if (!/^\d{6}$/.test(code)) {
      showError(new Error("Enter the 6-digit code shown by the requesting agent."));
      return;
    }
    void runMutation(id, confirm, { type: "confirmEnrollment", enrollmentId: id, code }, "The companion rejected this enrollment code.");
  });
  input.addEventListener("keydown", (event) => {
    if (event.key === "Enter") confirm.click();
  });
  const remainingEl = makeElement("p", "meta remaining", formatRemaining(request));
  card.append(remainingEl);
  const actions = makeElement("div", "actions");
  actions.append(input, confirm);
  card.append(actions);
  return { node: card, remainingEl, signature: "" };
}

/** True while the user is typing in, focused on, or selecting text inside node. */
function holdsUserContext(node) {
  const active = document.activeElement;
  if (active && active !== document.body && node.contains(active)) return true;
  const selection = document.getSelection();
  if (selection && selection.rangeCount > 0 && !selection.isCollapsed) {
    if (node.contains(selection.getRangeAt(0).commonAncestorContainer)) return true;
  }
  return false;
}

function reconcile(container, records, sessions, signatureOf, build) {
  const ordered = [];
  const seen = new Set();
  for (const session of sessions) {
    const id = sessionKey(session);
    if (id === "" || seen.has(id)) continue;
    seen.add(id);
    const signature = signatureOf(session);
    let record = records.get(id);
    if (record === undefined) {
      record = build(session);
      record.signature = signature;
      records.set(id, record);
    } else if (record.signature !== signature) {
      // Leave the card alone while the user owns it; the next tick retries.
      if (!inFlight.has(id) && !holdsUserContext(record.node)) {
        const next = build(session);
        next.signature = signature;
        record.node.replaceWith(next.node);
        records.set(id, next);
        record = next;
      }
    }
    if (record.remainingEl) setText(record.remainingEl, formatRemaining(session));
    ordered.push(record.node);
  }
  for (const [id, record] of records) {
    if (seen.has(id)) continue;
    record.node.remove();
    records.delete(id);
  }
  const children = container.childNodes;
  const inOrder = children.length === ordered.length && ordered.every((node, index) => children[index] === node);
  // Re-inserting nodes drops focus, so only reorder when the user is elsewhere.
  if (inOrder) return;
  if (holdsUserContext(container)) {
    for (const node of ordered) {
      if (!node.isConnected) container.append(node);
    }
    return;
  }
  container.replaceChildren(...ordered);
}

/** Header status line, most-important-wins. */
function statusText(nativeStatus, pendingCount, activeCount) {
  if (errorText !== "") return errorText;
  if (pendingCount > 0) return `${pendingCount} ${plural(pendingCount, "approval")} waiting`;
  if (activeCount > 0) return `${activeCount} ${plural(activeCount, "session")} active`;
  if (nativeStatus === "connecting") return "Connecting to companion…";
  if (nativeStatus === "connected") return "Companion connected";
  return "Companion off";
}

function renderStatus() {
  const nativeStatus = typeof state.native?.state === "string" ? state.native.state : "disconnected";
  const pendingCount = state.pendingSessions.length + state.pendingAccess.length;
  const activeCount = state.activeSessions.length;
  const dotState = errorText !== "" ? "error" : nativeStatus;
  const dotClass = `dot ${dotState}`;
  if (statusDot.className !== dotClass) statusDot.className = dotClass;
  setText(connectionStatus, statusText(nativeStatus, pendingCount, activeCount));
}

function renderDevice(companion) {
  const trusted = companion.trusted === true;
  const pinned = companion.pinned === true;
  const id = typeof companion.id === "string" && companion.id ? companion.id : "";
  if (trusted && id) {
    setText(
      deviceIdentity,
      `Verified companion ${abbreviate(id)}${companion.name ? ` · ${companion.name}` : ""}`,
    );
  } else if (pinned && id) {
    setText(deviceIdentity, `Pinned companion (not connected) ${abbreviate(id)}`);
  } else if (pinned) {
    setText(deviceIdentity, "Stored companion identity is unreadable. Forget it to pair again.");
  } else {
    setText(deviceIdentity, "No companion paired.");
  }

  // Never move the Forget control under the user mid-confirm or mid-request.
  if (forgetConfirmTimer !== null || inFlight.has(DEVICE_KEY)) return;
  const canForget = trusted || pinned;
  forgetButton.disabled = !canForget;
  if (canForget) forgetButton.removeAttribute("title");
  else forgetButton.title = "No companion is paired, so there is nothing to forget.";
}

function render() {
  renderStatus();

  const native = state.native ?? {};
  const nativeStatus = typeof native.state === "string" ? native.state : "disconnected";
  const companion = native.companion ?? {};
  const pending = state.pendingSessions;
  const active = state.activeSessions;
  const access = state.pendingAccess;
  const enrollments = state.pendingEnrollments;

  const identityKnown =
    typeof companion.id === "string" && companion.id !== "" &&
    (companion.trusted === true || companion.pinned === true);
  if (identityKnown) setText(companionIdentity, abbreviate(companion.id));
  setHidden(companionIdentity, !identityKnown);

  const isFirstRun =
    nativeStatus === "disconnected" &&
    companion.trusted !== true &&
    companion.pinned !== true &&
    pending.length === 0 &&
    active.length === 0;
  setHidden(firstRun, !isFirstRun);
  if (!inFlight.has(CONNECT_KEY)) {
    connectButton.disabled = nativeStatus === "connecting";
  }

  // Zero pending means no approval chrome at all, heading included.
  setHidden(pendingSection, pending.length === 0);
  setText(pendingHeading, `Approval requests (${pending.length})`);
  reconcile(pendingList, pendingCards, pending, pendingSignature, buildPendingCard);
  setHidden(accessSection, access.length === 0);
  setText(accessHeading, `Access upgrades (${access.length})`);
  reconcile(accessList, accessCards, access, accessSignature, buildAccessCard);
  setHidden(enrollSection, enrollments.length === 0);
  setText(enrollHeading, `Agent enrollments (${enrollments.length})`);
  reconcile(enrollList, enrollCards, enrollments, enrollSignature, buildEnrollCard);


  setHidden(activeSection, nativeStatus !== "connected" && active.length === 0);
  setText(activeHeading, `Active sessions (${active.length})`);
  reconcile(activeList, activeCards, active, activeSignature, buildActiveCard);
  setHidden(activeEmpty, active.length > 0);

  renderProfilesAndGrants();
  renderDevice(companion);
}

function renderProfilesAndGrants() {
  const profiles = state.enrolledProfiles;
  const grants = state.standingGrants;
  setHidden(profilesBlock, profiles.length === 0);
  setHidden(grantsBlock, grants.length === 0);
  if (holdsUserContext(profilesList) || holdsUserContext(grantsList)) return;
  profilesList.replaceChildren(...profiles.map((profile) => {
    const item = makeElement("li");
    item.append(
      makeElement("span", "tab-title", `${profile.name} · ${abbreviate(profile.principalId)}`),
    );
    const revoke = makeButton("Revoke", "secondary");
    if (inFlight.has(profile.principalId)) revoke.disabled = true;
    revoke.addEventListener("click", () => void runMutation(profile.principalId, revoke, { type: "revokeProfile", profileName: profile.name }, "The companion rejected this profile revocation."));
    item.append(revoke);
    return item;
  }));
  grantsList.replaceChildren(...grants.map((grant) => {
    const item = makeElement("li");
    const scope = grant.level === "domains" ? `sites: ${grant.domains.join(", ") || "none"}` : "selected tabs only";
    item.append(makeElement("span", "tab-title", `${grant.controllerName} · auto-approve up to ${scope}`));
    const forget = makeButton("Forget", "secondary");
    if (inFlight.has(`grant:${grant.controllerId}`)) forget.disabled = true;
    forget.addEventListener("click", () => void runMutation(`grant:${grant.controllerId}`, forget, { type: "revokeGrant", controllerId: grant.controllerId }, "The standing grant could not be removed."));
    item.append(forget);
    return item;
  }));
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
    const tab = await queryActiveTab();
    if (revision !== refreshRevision) return;
    state = {
      native: result.native ?? {},
      pendingSessions: Array.isArray(result.pendingSessions) ? result.pendingSessions : [],
      activeSessions: Array.isArray(result.activeSessions) ? result.activeSessions : [],
      pendingAccess: Array.isArray(result.pendingAccess) ? result.pendingAccess : [],
      pendingEnrollments: Array.isArray(result.pendingEnrollments) ? result.pendingEnrollments : [],
      enrolledProfiles: Array.isArray(result.enrolledProfiles) ? result.enrolledProfiles : [],
      standingGrants: Array.isArray(result.standingGrants) ? result.standingGrants : [],
      sharedTabs: Array.isArray(result.sharedTabs) ? result.sharedTabs : [],
    };
    currentTab = tab;
    clearError();
    render();
  } catch (error) {
    if (revision !== refreshRevision) return;
    showError(error);
  }
}

/**
 * Runs one background mutation. The control stays disabled for the whole
 * round trip and is only re-enabled here, never by a render tick. A failure
 * skips the resync so the error survives to be read; the poll resyncs and
 * clears it on its next successful pass.
 */
async function runMutation(key, control, message, fallbackError) {
  clearError();
  inFlight.add(key);
  control.disabled = true;
  let failure = null;
  try {
    const result = await chrome.runtime.sendMessage(message);
    if (!result?.ok) throw new Error(result?.error ?? fallbackError);
  } catch (error) {
    failure = error;
  } finally {
    inFlight.delete(key);
  }
  if (failure !== null) {
    control.disabled = false;
    showError(failure);
    return false;
  }
  await refresh();
  return true;
}

async function mutateSession(type, sessionId, control) {
  if (typeof sessionId !== "string" || sessionId.length === 0) {
    showError(new Error("The session is no longer available. Refresh and try again."));
    return;
  }
  await runMutation(sessionId, control, { type, sessionId }, "The companion rejected this action.");
}

async function mutateAccess(type, accessRequestId, control) {
  if (typeof accessRequestId !== "string" || accessRequestId.length === 0) {
    showError(new Error("The access request is no longer available. Refresh and try again."));
    return;
  }
  await runMutation(accessRequestId, control, { type, accessRequestId }, "The companion rejected this access decision.");
}

async function onShare(session, control) {
  const id = sessionKey(session);
  const mode = shareMode(session);
  if (id === "" || mode.disabled || !Number.isInteger(currentTab?.id)) return;
  await runMutation(
    id,
    control,
    { type: mode.action, sessionId: id, tabId: currentTab.id },
    "The companion rejected this tab action.",
  );
}

function disarmForget() {
  if (forgetConfirmTimer === null) return;
  clearTimeout(forgetConfirmTimer);
  forgetConfirmTimer = null;
  forgetButton.classList.remove("atb-btn--danger-filled");
  forgetButton.classList.add("atb-btn--danger-quiet");
  setText(forgetButton, "Forget companion…");
  setText(forgetAnnounce, "");
}

function armForget() {
  forgetButton.classList.remove("atb-btn--danger-quiet");
  forgetButton.classList.add("atb-btn--danger-filled");
  setText(forgetButton, "Confirm: forget and revoke all access");
  setText(
    forgetAnnounce,
    "Press the button again within 5 seconds to forget the companion and revoke all access.",
  );
  forgetConfirmTimer = setTimeout(disarmForget, FORGET_CONFIRM_MS);
}

connectButton.addEventListener("click", () => {
  if (connectButton.disabled) return;
  void runMutation(
    CONNECT_KEY,
    connectButton,
    { type: "connectCompanion" },
    "The companion could not be connected.",
  );
});

forgetButton.addEventListener("click", () => {
  if (forgetButton.disabled) return;
  if (forgetConfirmTimer === null) {
    armForget();
    return;
  }
  disarmForget();
  void runMutation(
    DEVICE_KEY,
    forgetButton,
    { type: "forgetCompanion" },
    "The companion could not be forgotten.",
  );
});

forgetButton.addEventListener("blur", disarmForget);

void refresh();
setInterval(() => void refresh(), POLL_INTERVAL_MS);

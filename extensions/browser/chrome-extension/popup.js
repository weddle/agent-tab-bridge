const statusDot = document.getElementById("statusDot");
const pairSection = document.getElementById("pairSection");
const connectedSection = document.getElementById("connectedSection");
const pairingInput = document.getElementById("pairingString");
const pairButton = document.getElementById("pairButton");
const unpairButton = document.getElementById("unpairButton");
const shareButton = document.getElementById("shareButton");
const statusLine = document.getElementById("statusLine");
const errorLine = document.getElementById("error");

const STATE_LABEL = {
  on: "Connected to local relay",
  connecting: "Connecting to local relay…",
  error: "Local relay unavailable; reconnecting…",
  off: "Not connected",
};

async function activeTab() {
  const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
  return tab ?? null;
}

async function refresh() {
  const status = await chrome.runtime.sendMessage({ type: "getStatus" });
  statusDot.className = `dot ${status.state}`;
  pairSection.classList.toggle("hidden", status.paired);
  connectedSection.classList.toggle("hidden", !status.paired);
  if (!status.paired) {
    return;
  }

  const label = STATE_LABEL[status.state] ?? STATE_LABEL.off;
  statusLine.textContent = `${label} · ${status.sharedTabCount} shared tab${
    status.sharedTabCount === 1 ? "" : "s"
  }`;

  const tab = await activeTab();
  if (!Number.isInteger(tab?.id)) {
    shareButton.disabled = true;
    shareButton.textContent = "Share this tab";
    delete shareButton.dataset.tabId;
    return;
  }

  const { shared } = await chrome.runtime.sendMessage({ type: "isTabShared", tabId: tab.id });
  shareButton.disabled = false;
  shareButton.textContent = shared ? "Unshare this tab" : "Share this tab";
  shareButton.dataset.tabId = String(tab.id);
}

async function onPair() {
  errorLine.classList.add("hidden");
  pairButton.disabled = true;
  try {
    const result = await chrome.runtime.sendMessage({
      type: "pair",
      pairingString: pairingInput.value,
    });
    if (!result?.ok) {
      throw new Error(result?.error ?? "Pairing failed.");
    }
    pairingInput.value = "";
    await refresh();
  } catch (error) {
    errorLine.textContent = error instanceof Error ? error.message : String(error);
    errorLine.classList.remove("hidden");
  } finally {
    pairButton.disabled = false;
  }
}

async function onUnpair() {
  unpairButton.disabled = true;
  try {
    await chrome.runtime.sendMessage({ type: "unpair" });
    await refresh();
  } finally {
    unpairButton.disabled = false;
  }
}

async function onToggleShare() {
  const tabId = Number.parseInt(shareButton.dataset.tabId ?? "", 10);
  if (!Number.isInteger(tabId)) {
    return;
  }
  shareButton.disabled = true;
  try {
    await chrome.runtime.sendMessage({ type: "toggleShareTab", tabId });
  } finally {
    await refresh();
  }
}

pairButton.addEventListener("click", () => void onPair());
unpairButton.addEventListener("click", () => void onUnpair());
shareButton.addEventListener("click", () => void onToggleShare());

void refresh();
setInterval(() => void refresh(), 2_000);

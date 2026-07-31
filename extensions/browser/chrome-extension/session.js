/**
 * Anchor-page rendering for the approved session.
 *
 * Lives in its own file because MV3's extension-page CSP (`script-src 'self'`)
 * refuses inline scripts. Behaviour is otherwise the query-param rendering the
 * page has always described.
 */

const params = new URLSearchParams(location.search);
const text = (name, fallback) => params.get(name) || fallback;

document.getElementById("description").textContent = text("label", "Approved local controller session");
document.getElementById("controller").textContent = `Requester: ${text("controller", "Unnamed controller")}`;
document.getElementById("session").textContent = `Session: ${text("sessionId", "Unavailable")}`;
document.getElementById("capabilities").textContent = `Approved capabilities: ${text("capabilities", "None")}`;

const access = text("access", "selectedTabs");
const groupSwatch = document.getElementById("groupSwatch");
const groupLabel = document.getElementById("groupLabel");
const authority = document.getElementById("authority");
const revocation = document.getElementById("revocation");

if (access === "full") {
  groupSwatch.classList.add("full");
  groupLabel.textContent = "This full-access session's tab group is red.";
  authority.textContent = "This session may open and adopt any ordinary website tab.";
  revocation.textContent = "Moving an adopted tab out of this group revokes access to that tab immediately.";
} else if (access === "domains") {
  groupSwatch.classList.add("domains");
  groupLabel.textContent = "This domain-scoped session's tab group is orange.";
  authority.textContent = `This session may open and adopt ${text("domains", "the approved domains")} and their subdomains.`;
  revocation.textContent = "Leaving the approved domains or moving a tab out of this group revokes access immediately.";
} else {
  const tabIds = params.get("tabIds");
  groupLabel.textContent = "This selected-tab session's tab group is blue.";
  authority.textContent = tabIds
    ? `This session may adopt the approved tabs: ${tabIds}.`
    : "Only website tabs deliberately shared with this session can be controlled.";
  revocation.textContent = "Move another tab into this group, or use Share in the Agent Tab Bridge popup. Moving it out revokes access immediately.";
}

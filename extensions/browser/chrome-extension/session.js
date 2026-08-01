/**
 * Anchor-page rendering for the approved session.
 *
 * Lives in its own file because MV3's extension-page CSP (`script-src 'self'`)
 * refuses inline scripts. Behaviour is otherwise the query-param rendering the
 * page has always described.
 */

import {
  FULL_ACCESS_CONSEQUENCE,
  renderAccessScope,
  renderClaimedString,
  verifiedIdentityDetails,
} from "./modules/ui-vocabulary.js";

const params = new URLSearchParams(location.search);
const text = (name, fallback) => params.get(name) || fallback;

const description = document.getElementById("description");
description.textContent = renderClaimedString(text("label", "Approved local controller session"));
description.title = "Unverified session label";

const identity = verifiedIdentityDetails("Local controller", text("controllerFingerprint", "unavailable"));
const controller = document.getElementById("controller");
controller.textContent = identity.text;
controller.title = identity.fullValue;
controller.setAttribute("aria-label", identity.ariaLabel);
document.getElementById("session").textContent = `Session: ${text("sessionId", "Unavailable")}`;
const sessionState = document.getElementById("sessionState");
const reconnecting = text("state", "active") === "reconnecting";
sessionState.textContent = reconnecting
  ? "Reconnecting — the session is paused while this browser resumes."
  : "Active";
sessionState.classList.toggle("reconnecting", reconnecting);
document.getElementById("capabilities").textContent = `Approved capabilities: ${text("capabilities", "None")}`;

const access = text("access", "selectedTabs");
const groupSwatch = document.getElementById("groupSwatch");
const groupLabel = document.getElementById("groupLabel");
const authority = document.getElementById("authority");
const revocation = document.getElementById("revocation");

if (access === "full") {
  groupSwatch.classList.add("full");
  groupLabel.textContent = "This full-access session's tab group is red.";
  authority.textContent = FULL_ACCESS_CONSEQUENCE;
  revocation.textContent = "Moving an adopted tab out of this group revokes access to that tab immediately.";
} else if (access === "domains") {
  groupSwatch.classList.add("domains");
  groupLabel.textContent = "This domain-scoped session's tab group is orange.";
  authority.textContent = `This session may open and adopt ${renderAccessScope({ level: "domains", domains: text("domains", "the approved domains").split(", "), tabIds: [] })}.`;
  revocation.textContent = "Leaving the approved domains or moving a tab out of this group revokes access immediately.";
} else {
  const tabIds = params.get("tabIds");
  groupLabel.textContent = "This selected-tab session's tab group is blue.";
  authority.textContent = tabIds
    ? `This session may adopt the approved tabs: ${tabIds}.`
    : "Only website tabs deliberately shared with this session can be controlled.";
  revocation.textContent = "Move another tab into this group, or use Share in the Agent Tab Bridge popup. Moving it out revokes access immediately.";
}

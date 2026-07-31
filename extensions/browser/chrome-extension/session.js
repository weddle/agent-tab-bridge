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

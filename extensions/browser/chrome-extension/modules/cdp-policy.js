// Pure, default-deny CDP boundary for an extension-attached page target.

const PAGE_DOMAINS = new Set([
  "Accessibility",
  "CSS",
  "DOM",
  "Debugger",
  "Emulation",
  "Fetch",
  "Input",
  "Log",
  "Network",
  "Page",
  "Performance",
  "Runtime",
]);

const EXCLUDED_METHODS = new Set([
  "DOM.getFileInfo",
  "Page.setDownloadBehavior",
  "Network.clearBrowserCache",
  "Network.clearBrowserCookies",
  "Network.deleteCookies",
  "Network.getAllCookies",
  "Network.getCookies",
  "Network.setCookie",
  "Network.setCookies",
]);

/** Permit only CDP domains safe for a shared page target; every unknown domain is denied. */
export function isPermittedPageCdpMethod(method) {
  if (typeof method !== "string") {
    return false;
  }
  const separator = method.indexOf(".");
  if (separator <= 0 || separator === method.length - 1) {
    return false;
  }
  return PAGE_DOMAINS.has(method.slice(0, separator)) && !EXCLUDED_METHODS.has(method);
}

/**
 * Shared consent-language renderers for the extension UI.
 *
 * These functions return text, not HTML. Callers attach the returned metadata to
 * their own elements so unverified strings can never become markup or policy.
 */

const FINGERPRINT_PREFIX = "sha256/";

function identityArgs(labelOrIdentity, fingerprint) {
  if (labelOrIdentity && typeof labelOrIdentity === "object") {
    return {
      label: typeof labelOrIdentity.label === "string" ? labelOrIdentity.label : "Verified identity",
      fingerprint: labelOrIdentity.fingerprint,
    };
  }
  return {
    label: typeof labelOrIdentity === "string" && labelOrIdentity ? labelOrIdentity : "Verified identity",
    fingerprint,
  };
}

function normalizedFingerprint(value) {
  if (typeof value !== "string" || value.length === 0) return "sha256/unavailable";
  return value.startsWith(FINGERPRINT_PREFIX) ? value : `${FINGERPRINT_PREFIX}${value}`;
}

/** Return the complete verified identity metadata; fullValue is for on-demand display. */
export function verifiedIdentityDetails(labelOrIdentity, fingerprint) {
  const args = identityArgs(labelOrIdentity, fingerprint);
  const fullValue = normalizedFingerprint(args.fingerprint);
  const encoded = fullValue.slice(FINGERPRINT_PREFIX.length);
  const shortValue = `${FINGERPRINT_PREFIX}${encoded.slice(0, 8)}`;
  return {
    label: args.label,
    fingerprint: shortValue,
    fullValue,
    text: `${args.label} · verified key ${shortValue}`,
    ariaLabel: `${args.label} · verified key ${fullValue}`,
  };
}

/** Render a verified identity line; callers should expose fullValue on title/details. */
export function renderVerifiedIdentity(labelOrIdentity, fingerprint) {
  return verifiedIdentityDetails(labelOrIdentity, fingerprint).text;
}

/**
 * Render requester-supplied context. Claims are always quoted and explicitly
 * unverified; this output is descriptive only and must never enter policy.
 */
export function renderClaimedString(value) {
  const claimed = typeof value === "string" && value.length > 0 ? value : "Unnamed";
  return `“${claimed}” (unverified)`;
}

export function claimedStringDetails(value) {
  return { text: renderClaimedString(value), policyRelevant: false };
}

export function renderAccessScope(access) {
  const level = access?.level;
  if (level === "full") return "Full access";
  if (level === "domains") {
    const domains = Array.isArray(access.domains) ? access.domains : [];
    return domains.length ? `Sites: ${domains.join(", ")} (including subdomains)` : "Sites: none";
  }
  const tabIds = Array.isArray(access?.tabIds) ? access.tabIds : [];
  return tabIds.length ? `Selected tabs: ${tabIds.map((id) => `Tab ${id}`).join(", ")}` : "Selected tabs only";
}

export function renderScopeChips(access) {
  if (access?.level === "full") return ["Full access"];
  if (access?.level === "domains") return (access.domains ?? []).map((domain) => `Site: ${domain}`);
  return (access?.tabIds ?? []).map((id) => `Tab ${id}`);
}

export const FULL_ACCESS_CONSEQUENCE =
  "It can open any website and control tabs in this session's group; tabs outside the group stay outside it.";

export function isRememberableAccess(access) {
  return access?.level === "selectedTabs" || access?.level === "domains";
}

export function isLocalOnlyGrant(grant) {
  return grant?.route?.kind === "local" && grant?.route?.routePolicy === "localOnly";
}

export function renderStandingGrantScope(grant) {
  const access = grant?.route?.accessCeiling ?? grant;
  const local = isLocalOnlyGrant(grant);
  const scope = renderAccessScope(access);
  return local ? scope : `${scope} · machine scope unavailable`;
}

export function rememberedGrantLabel() {
  return "Remembered grant";
}

export function renderRememberedGrantChip() {
  return rememberedGrantLabel();
}

export function renderHubConnectionStatus(value) {
  if (value === "connected") return { state: "connected", text: "connected" };
  if (value === "connecting") return { state: "connecting", text: "connecting" };
  if (value === "unreachable") return { state: "connecting", text: "unreachable" };
  return { state: "disconnected", text: "off" };
}

export function renderPairingFailure(value) {
  const code = typeof value === "string" ? value : value?.code;
  if (code === "wrong-code") return "The pairing code was incorrect. A fresh code is required.";
  if (code === "expired-code") return "The pairing code expired. A fresh code is required.";
  if (code === "key-mismatch") return "Pairing refused: the verified key does not match the invitation.";
  if (code === "duplicate-identity") return "Pairing refused: this identity is already enrolled.";
  if (code === "attempts-exhausted") return "Pairing refused: attempts are exhausted. Request a fresh code.";
  if (code === "replayed-confirmation") return "Pairing refused: this confirmation was already used.";
  if (code === "protocol-downgrade") return "Pairing refused: the protocol does not meet the required version.";
  return "Pairing failed. Request a fresh code.";
}

export function renderSessionState(value) {
  return value === "reconnecting"
    ? { state: "connecting", text: "reconnecting" }
    : { state: "connected", text: "active" };
}

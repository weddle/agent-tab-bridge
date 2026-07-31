export const MAX_STABLE_SESSION_KEY_LENGTH = 128;

/**
 * A user-selected identifier for an in-memory reusable controller session.
 * It is deliberately safe to carry over the local NDJSON broker protocol and
 * is never forwarded to the extension or persisted.
 */
export function isStableSessionKey(value: unknown): value is string {
  return typeof value === "string"
    && value.length > 0
    && value.length <= MAX_STABLE_SESSION_KEY_LENGTH
    && /^[A-Za-z0-9][A-Za-z0-9._:-]*$/.test(value);
}

export function assertStableSessionKey(value: unknown): string {
  if (!isStableSessionKey(value)) {
    throw new Error(`session key must be 1-${MAX_STABLE_SESSION_KEY_LENGTH} characters using letters, numbers, '.', '_', ':', or '-'`);
  }
  return value;
}

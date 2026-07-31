# Agent Tab Bridge — Design Language

Status: **locked** 2026-07-31. Authored by Fable (design lead); reviewed by Sol and
Kimi; finalized by design-lead judgment. Scope: every user-visible surface —
extension popup, tab groups and in-browser signals, toolbar badge, session page,
enrollment ceremonies, CLI, hub and connector status output. This is a design
language, not a pixel spec: it fixes vocabulary, semantics, and rules so any surface
built later is recognizably the same product. Where it is silent, implementers choose.

## 1. Principles

1. **Consent is a place.** All authority changes happen in the browser popup, on the
   machine whose browser is affected. No other surface — CLI, hub, connector, agent —
   can grant, extend, or remember access, and surfaces that cannot grant authority
   never look like they can.
2. **Color is authority.** One access treatment — the combination of color, chip, and
   tab-group tint — encodes the access ceiling everywhere it appears. Blue = selected
   tabs. Orange = sites (listed domains). Red = full access. Grey = pending/none. The
   access treatment is reserved: status indicators never borrow its palette, and
   errors are stated in words, not color.
3. **Verified is distinct from claimed.** Keys are what get verified; names are
   aliases. Facts bound to verified keys (controller principal, hub, endpoint) render
   as labeled text with a fingerprint (`den-server · verified key sha256/XXXXXXXX`,
   full value on demand); the alias is user-chosen at pairing, not proven. Strings
   supplied by the requester (task label, machine name) always render quoted with an
   explicit "unverified" treatment and never participate in policy. The UI never
   upgrades a claim typographically.
4. **Progressive disclosure.** A single-machine user never sees mesh vocabulary. Hub
   rows, via-lines, and browser pickers appear only once a hub or second endpoint
   actually exists. Installing mesh-capable code changes nothing visually.
5. **Calm surfaces.** Approvals never raise OS notifications, sounds, or focus theft;
   attention is requested via the toolbar badge and satisfied in the popup. A render
   tick never rebuilds a control the user is using (existing popup contract).
   Read-only status mechanisms outside the popup remain open to implementers.
6. **Every state names its exit.** Degraded states say what gate failed and the one
   action that clears it. No dead-end copy.

## 2. Vocabulary (canonical, user-facing)

| Term | Meaning | Never called |
|---|---|---|
| companion | the local `atb` software as a whole | daemon, supervisor, shim, edge (internal) |
| this browser | one extension endpoint | endpoint (internal) |
| agent profile | named controller keypair (`hermes-research`) | user, account |
| session | one approved task session | connection, tunnel |
| shared tab | tab inside a session's group | debugged tab |
| standing grant | remembered auto-approval for one profile | trust, whitelist |
| home hub | the optional `atb hub` service | relay, server, broker |
| pairing code | short ceremony code | PIN, password, OTP |

Internal architecture nouns (edge, shim, broker, connector, route) stay out of
user-facing copy. The CLI may use `hub`, `browser`, `profile`, `session` in flags and
output. User-facing copy says "`atb` on the browser machine", never "the edge".

## 3. Badge and status

- Toolbar badge (existing semantics kept): grey `OFF` companion off · amber `…`
  connecting · amber count = approvals waiting · green count = active sessions ·
  empty = idle. Badge signals attention, not authority. When any active session is
  remote, the hover title notes it; no new badge color.
- Status dots: green connected · amber connecting/attention · grey off/error, always
  with adjacent text (`aria-live=polite`). Dots never appear without words; red
  belongs to full access alone.

## 4. Popup information architecture

Order (attention first, standing state last):

1. Header: product name, connection status, companion identity line.
2. First-run guidance (only when unpaired).
3. **Approval requests** — pending session cards.
4. **Access upgrades** — pending upgrade cards.
5. **Agent enrollments** — pending pairing-code cards.
6. **Active sessions** — one card per session.
7. **Device** (footer): companion identity + fingerprint; enrolled agent profiles
   (name, fingerprint, Revoke); standing grants (profile, scope ceiling, route badge,
   Forget); **Home hub** row (only when a hub is paired): hub alias + verified key,
   connection state, "Enabled for this browser" toggle, and a machine-wide
   **Forget hub…** action — the toggle and Forget are distinct controls with distinct
   copy, and the toggle must not read as unpairing the machine; Forget companion.

Card anatomy (shared by all card types):

```
[access-color edge]
WHO    verified: profile name · sha256/XXXXXXXX   (or "Local controller")
VIA    only when remote: via home hub den-server · verified key sha256/YYYYYYYY
WHAT   scope chips + TTL; upgrades show the delta AND the resulting ceiling
SAID   quoted unverified context: “Research task” — requested by agent (unverified)
       machine label, if supplied: from “nuc-container-7” (unverified)
ACTS   approve/decline; destructive actions use a quiet-danger style; Remember
       checkbox only when the profile is enrolled and the scope is rememberable
```

Rules:

- Full-access requests use the red treatment plus one sentence of consequence, stated
  precisely: it can open any website and control tabs in this session's group; tabs
  outside the group stay outside it. Remember is never available for full access.
- Selected-tab chips expand to the exact tab list on demand.
- Sessions auto-approved by a standing grant appear with a **remembered grant** chip
  and an inline Forget affordance — auto-approval is an authority event and must be
  visible where it happened.
- Machine-scoped actions say so: profile enrollment copy states the profile is
  enrolled for this machine (all its browsers); profile revocation confirms it ends
  that profile's sessions and grants across all browsers on this machine.

## 5. Ceremonies

One ceremony shape everywhere:

- The **secret is born where the key lives**; the **code is confirmed where trust is
  granted**. Profile enrollment: `atb` prints the code; the user confirms in the
  popup. Hub pairing: the hub admin surface prints the code; `atb` on the browser
  machine confirms it (the popup then shows a passive "machine paired with hub"
  identity line — pairing grants nothing by itself).
- **Fingerprint match is load-bearing and comes first.** The pending card shows the
  enrolling key's fingerprint before code entry, and ceremony copy instructs the user
  to match it against the requester's display *before* confirming — for remote
  enrollment this comparison is the substitution defense. Both sides show the same
  resulting fingerprint at completion.
- Local profile enrollment keeps today's parameters (6 digits, 2-minute expiry,
  bounded attempts, single-use, never logged, never redisplayed). Hub pairing uses
  the parameters of the reviewed PAKE ceremony; the *shape* (short code, short life,
  born-here-confirmed-there) is the design contract, not the exact digits.
- Every ceremony ends by stating what was enrolled and what it does **not** grant.
- Failure states render where the ceremony lives: wrong/expired code and exhausted
  attempts resolve to a fresh code, never a retry of a dead one; key mismatch or a
  revoked/duplicate identity is a refusal that names the conflict.
- Enabling a browser for the hub is a toggle, not a ceremony — local consent scoping
  protected by the popup itself.

## 6. Tab groups and in-browser signals

- Group title keeps the fixed product prefix before the quoted, truncated session
  label (anti-spoofing: claimed text never leads). Group color = access ceiling.
- Remote sessions carry a route marker in the group title (suffix; exact glyph/word
  is implementer's choice) — route is salient at the tab strip, not only on the
  session page.
- The Chromium debugger banner is never suppressed, restyled, or apologized for; it
  is the honesty signal.
- Session page states: quoted session label, verified controller fingerprint, scope
  in words, via-hub line when remote, and the two revocation gestures (drag the tab
  out; End session).

## 7. CLI grammar

- Noun-verb: `atb open|close|url|run|tabs|claim-tab|browsers|profile <…>|hub <…>|status`. Existing verbs keep their shapes; mesh adds `browsers` and `hub`.
  `--browser <label|fingerprint>` selects among endpoints; omitted only when exactly
  one is live — the CLI never guesses among several.
- Machine-consumable values (`BROWSER_CDP_URL`, pairing codes) print alone on stdout;
  diagnostics and context go to stderr or behind `--verbose`. Session URLs keep
  today's rule: printed on request, never written to disk.
- Exit codes are the API: 0 ok, nonzero refusal/failure. Refusals name the gate:
  `refused: full access requires approval in the browser (open the Agent Tab Bridge
  popup)`.
- Degradation is explicit and names what still works: `hub unreachable (desk-brave
  and 2 other browsers offline); local browsers still available`.

## 8. Hub and connector status surfaces

- The hub has **no interactive web UI** — it must never look like the place authority
  lives. `atb hub status` prints identity fingerprint, listen address, enrolled
  machines (alias + fingerprint + presence), connectors admitted. One fact per row.
  Read-only status surfaces beyond the CLI are open to implementers under Principle 1.
- Connector session start: `BROWSER_CDP_URL` alone on stdout; verified endpoint and
  via-hub facts on stderr/`--verbose`.
- All components log unverified strings quoted.

## 9. Voice and tone

- Sentence case, terse, factual. No exclamation points, no praise, no "simply".
- Security copy states what a thing does **not** grant, one sentence, at the moment
  of the relevant action.
- Counts in headings ("Approval requests (2)") — the popup is an inventory, not a feed.

## 10. Degraded and recovery states

| State | Surface | Treatment |
|---|---|---|
| Companion off | popup | grey dot, "Companion not running. It starts with your browser — reconnect from here." |
| Hub configured, unreachable | popup Device row + CLI | amber dot on the hub row only; session list untouched; copy names local availability |
| **Hub lost mid-session** | popup + agent | routed sessions **end immediately**: card removed, connector loopback socket closes, CLI prints `session ended: hub connection lost` |
| **Endpoint lost (browser/SW restarting)** | supervisor + agent | session records suspended for the bounded grace (~2 min): the agent-visible `BROWSER_CDP_URL` stays valid but stalls; on same-identity re-handshake the session resumes behind the same URL; at expiry it fails closed and the socket closes. The popup, if reachable, shows the session as reconnecting; it may itself be gone — the CLI/connector carries this state |
| Browser not enabled for hub | requester CLI | refusal naming the gate: enable this browser for the hub in its popup |
| Empty sections | popup | hidden entirely, except Active sessions ("No active sessions.") |

Design debt acknowledged (not blocking): popup overflow past ~6 concurrent sessions;
defer until real.

## Review disposition (for the record)

Adopted from review: delta+ceiling on upgrade cards, precise full-access consequence
copy, alias-vs-verified-key rendering, machine-scope impact copy, distinct hub
toggle/forget controls, ceremony failure states, fingerprint-match-first enrollment,
stdout/stderr separation, product-prefixed group titles, remote route marker in
group titles, remembered-grant chip, hub-row conditionality, badge `OFF` fact fix,
companion-off copy fix, removal of red from status, and cuts of time-format/layout
overspecification. Held against review, by design-lead judgment: approvals stay
OS-notification-free (consent must be answered where it is granted); the hub keeps
no interactive web UI (authority-honesty outweighs convenience); the ceremony
*shape* stays universal even though PAKE parameters may differ.

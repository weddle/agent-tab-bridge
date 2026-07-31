# Agent Tab Bridge — Milestones

Status: **locked** 2026-07-31, three-architect consensus (Fable, Sol, Kimi) after
independent drafting and two debate rounds. Target end state: [ARCHITECTURE.md](ARCHITECTURE.md)
+ [DESIGN.md](DESIGN.md). Each milestone is a checkpoint: binary, observable proof;
the product ships/works at every one. Minimum viable specification — decomposition
guidance, not a test plan. Packaging/installers/key-custody remain on the ROADMAP
Release 1 track and are deliberately outside this effort.

## M1 — Endpoint-ready local model (no visible change)

Scope: stable machine/endpoint IDs; route-aware session and standing-grant DTOs with
canonical encoding; legacy grants migrate **local-only**; endpoint-bound v2 auth
transcript replaces `profileAuthTranscript` (nonce+name) locally — hub/route/stream
fields are reserved and join in M5.
Proof: suite green; single-browser UX unchanged; migrated grants render local-only;
replayed or field-substituted auth transcripts rejected with no hub in the loop.

## M2 — Supervisor/shim cutover + local multi-browser

Scope: registered Native Messaging executable becomes a thin stdio↔socket shim; lazy
ref-counted per-machine supervisor owns identity, broker, sessions, relays; state
split machine-scoped vs endpoint-scoped; per-endpoint 0600 sockets + live-endpoint
registry; `atb browsers`, `--browser`, refusal on ambiguity; local consent-display
honesty from DESIGN.md (remembered-grant chip, quoted unverified labels, upgrade
delta+ceiling, status-color resolution, machine-scope enrollment copy).
Proof: Brave and Chrome run concurrent sessions on one machine (impossible today);
unqualified CLI with two endpoints refuses to guess; each browser controls only its
own groups; closing the last browser with no work tears down supervisor, sockets,
and registry; single-browser UX otherwise byte-identical.

## M3 — Bounded endpoint recovery

Scope: on Native Messaging loss, suspend authority and retain session records for
the bounded (~2 min) grace; resume only after the same pinned extension identity
re-handshakes and re-syncs; the agent-visible `BROWSER_CDP_URL` stays stable (stall,
then resume); fail-closed revocation and group cleanup at expiry; reconnecting
states per DESIGN.md.
Proof: extension reload mid-session — same CDP URL stalls then resumes with no
re-approval; full browser quit — session revoked, no orphaned tab groups; wrong
identity or expiry closes fail-closed.

## M4 — Hub pairing and presence (no routing)

Scope: `atb hub` daemon (explicitly enabled LAN listener); machine↔hub PAKE/SAS
ceremony; pinned outbound TLS from the edge; presence + directory of enabled
endpoints; per-browser "Enabled for this browser" toggle; popup hub row per
DESIGN.md; mesh code inert when unconfigured.
Proof: two machines pair with fingerprint match; only enabled endpoints appear at
the hub; disable/unpair leaves zero LAN listener and no reconnect loop (port-scan
check) without disturbing a simultaneous local session.

## M5 — Remote control plane (non-authorizing)

Scope: hub routes broker commands addressed (machine, endpoint, principal, stable
key); full v2 transcripts with hub/route/stream binding; profile auth terminates at
the edge, relayed opaquely; remote fingerprint-match-first enrollment; edge-signed
enrollment statements populate the directory; approval cards render verified
principal + via-hub + quoted unverified context; route-policy standing grants.
**Hard boundary: non-authorizing** — no remote session becomes active; pending
requests are proven by decline/cancel behind the development gate. Approval→data
enablement lands atomically in M6.
Proof: from the server, enroll a profile and raise a session request that appears
correctly rendered in the desktop popup and is declined; a forged hub authentication
assertion is rejected by the edge; a legacy local-only grant does not auto-approve a
remote request.

## M6 — E2E data plane + connector

Scope: signed-ephemeral-ECDH profile↔edge channel (HKDF→AEAD, monotonic counters,
replay rejection); hub stitches opaque ciphertext only; harness connector dials
outbound and mints a task-scoped loopback `BROWSER_CDP_URL`; approval atomically
enables E2E data; remote route marker on tab groups.
Proof: an agent on machine A (containerized is acceptable here) drives an approved
tab on machine B through the hub via its loopback URL; a hub-side frame dump shows
only ciphertext; a replayed frame is rejected; dragging the tab out of its group
kills control immediately.

## M7 — Revocation fan-out + degradation parity (final)

Scope: profile/endpoint/hub/device revocation propagates hub→edge→extension
immediately (grants deleted, sessions killed); hub loss closes routed sessions and
connector URLs while local sessions continue; reconnection restores presence, never
sessions; remembered remote grants (same profile, same hub) auto-approve at the
remembered scope while widening still prompts; minimal operator docs harvested.
Proof: one scripted three-machine pass — containerized Hermes on the server drives a
desktop tab; popup revocation of its profile kills the remote session immediately;
hub kill leaves a local session running and remote establishment failing closed with
actionable status; unconfigured mesh emits no LAN traffic.

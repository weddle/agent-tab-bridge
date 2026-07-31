# Agent Tab Bridge — Work Packets

Status: **locked** 2026-07-31, three-architect consensus (Fable, Sol, Kimi) after
independent drafting and two debate rounds. Maps to [MILESTONES.md](MILESTONES.md);
end state in [ARCHITECTURE.md](ARCHITECTURE.md) + [DESIGN.md](DESIGN.md).

Packets are role definitions, not model or agent assignments. Each packet is bounded
so one worker owns it without mid-flight coordination; cross-packet contracts are
stated up front. Minimum viable specification: scope boundaries and worker
requirements only. Tests ride inside packets and prove milestone invariants only —
if test effort exceeds development effort, the packet is being executed wrong.

Levels: `mid` = solid mid-level implementation · `senior` = senior judgment
(architecture-touching decisions) · `expert` = specialist. Sizes: S/M/L.

## Packets

### WP1 — Endpoint contracts + auth v2 precursor (M1) · senior · M
TS systems / data modeling. Stable machine/endpoint IDs; route-aware session and
grant DTOs with canonical encoding; machine-vs-endpoint state split in
`CompanionStateStore`; legacy-grant local-only migration; endpoint-bound v2 auth
transcript replacing nonce+name (routed fields reserved, not implemented). The
transcript schema is a contract consumed by broker, client, and later the relayed
path — it stays in this packet. No behavior change beyond the transcript.

### WP2 — Supervisor + shim lifecycle (M2) · senior · L
TS process/systems refactor. Thin stdio↔socket NM shim; lazy ref-counted supervisor
(spawn election, idle-grace exit, cleanup); ownership of machine identity, broker,
sessions, relays; serialized state writes. The biggest structural change; lifecycle
races live here.

### WP3 — Endpoint IPC, registry, CLI selection (M2) · mid · M
Node IPC + CLI ergonomics. Per-endpoint 0600 sockets; stale-safe live-endpoint
registry; `atb browsers`, `--browser`, ambiguity refusal; stdout/stderr contract per
DESIGN.md §7. Consumes WP2's socket layout.

### WP4 — Local consent-language UI (M2–M3) · mid · M
MV3 extension UI. Remembered-grant chip, quoted unverified labels, upgrade
delta+ceiling, authority-vs-status color resolution, machine-scope enrollment copy,
reconnecting states. Lands the shared vocabulary once: verified/claimed rendering
helpers and color tokens that WP9 inherits rather than re-decides.

### WP5 — Recovery state machine (M3) · senior · L
TS systems + MV3 lifecycle. Authority suspension on endpoint loss; bounded grace;
same-pinned-identity resume behind a stable relay URL; fail-closed expiry;
extension-side re-handshake resync, group rebind, orphaned-group cleanup.

### WP6 — Hub service core (M4) · mid · M
TS network service (new binary). Explicitly enabled LAN listener; framing; machine/
endpoint presence and directory; enable filtering; inert-when-unconfigured;
`atb hub status` operator output. Consumes WP7's pairing contract.

### WP7 — Hub pairing + hop security (M4) · mid · M · review gate RG1
Protocol integration (prescribed reviewed SPAKE2+-class library + pinned TLS 1.3 —
construction selection is not open). Owns the entire ceremony security object:
ceremony UX per DESIGN.md §5, transcript binding of both long-term keys and roles,
key confirmation, pinned-keyset handoff. Contract out: `{pinned peer key, roles,
presence protocol}` consumed by WP6. Disable/forget semantics.

### WP8 — Remote control plane (M5) · senior · L · review gate RG2
Distributed protocol design + implementation. Addressed opaque broker routing
(machine, endpoint, principal, stable key); full v2 transcripts with hub/route/
stream binding; edge-terminated relayed profile auth and enrollment; signed
enrollment statements; route-policy grant enforcement; the non-authorizing
development gate. The zero-authority invariant lives here.

### WP9 — Mesh consent surfaces (M4–M6) · mid · M
MV3 UI + CLI copy. Hub row/toggle/forget, remote approval identity lines
(verified principal, via-hub, quoted claims), fingerprint-match-first enrollment
flow, ceremony failure states, tab-group route marker, badge remote note, degraded/
actionable states. Inherits WP4 vocabulary; starts after WP8 shapes are stable
enough to render.

### WP10 — E2E session channel library (M6) · expert · M · review gate RG3
Cryptographic protocol implementation, as a narrow reusable library. Signed
ephemeral ECDH (static P-256 signs, never keys ECDH directly), HKDF→directional
AEAD, monotonic counters, replay rejection, close/rekey semantics. Contract out:
`SecureSessionChannel` — "an authenticated duplex stream to session X" — consumed by
WP11. The only expert implementation packet.

### WP11 — Data routing + connector (M6) · mid · L
Node networking / CDP integration. Hub ciphertext stream stitcher; relay front-door/
transport-adapter split at the edge (backpressure, cancellation, close propagation);
harness connector: outbound dial, channel termination via WP10's contract, loopback
CDP discovery + `BROWSER_CDP_URL` minting, stdout contract.

### WP12 — Revocation + degradation orchestration (M7) · mid · M
TS systems + extension. Hub→edge→extension revocation fan-out with grant deletion;
hub-loss split behavior (local survives, remote fails closed); presence-only
reconnect; remote standing-grant auto-approval with widening prompts.

### WP13 — Live checkpoint driver + docs harvest (M2–M7) · mid · recurring S, M total
Cross-machine verification driving with the user in the loop. Owns each milestone's
binary proof (Brave+Chrome concurrency, recovery stall/resume, pairing, decline-only
control plane, two-machine E2E, final three-machine container scripted pass),
records outcomes, adds a regression only when it defends a discovered contract.
Harvests minimal operator docs at M7; docs otherwise ride inside feature packets.

### RG1–RG3 — Security review gates · expert reviewer · S each
Findings-only, scoped to trust claims; no general audits, no hub/UI/connector
mechanics. RG1 (M4): PAKE/TLS binding and downgrade. RG2 (M5): zero-authority
claims — transcript binding, edge-terminated auth, standing-grant impersonation
boundary (includes the WP1 transcript in its relayed context). RG3 (M6): E2E channel
construction. M1 earns no standalone gate.

## Level census

- **senior**: WP1, WP2, WP5, WP8
- **expert**: WP10 + RG1–RG3 (review passes only)
- **mid**: WP3, WP4, WP6, WP7, WP9, WP11, WP12, WP13

## Cross-packet contracts (stated once, owned by the earlier packet)

1. WP1 → all: ID/DTO/transcript schemas.
2. WP2 → WP3/WP5: socket layout, supervisor lifecycle events.
3. WP7 → WP6: `{pinned peer key, roles, presence protocol}`.
4. WP4 → WP9: verified/claimed rendering helpers, color tokens.
5. WP8 → WP9/WP11/WP12: routed command shapes, session addressing.
6. WP10 → WP11: `SecureSessionChannel`.

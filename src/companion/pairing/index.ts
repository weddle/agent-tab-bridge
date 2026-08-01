import { randomBytes } from "node:crypto";
import { fingerprintSpki, signTranscript, verifyTranscript, type StoredIdentity } from "../identity.js";
import { PAKE_CIPHER_SUITE, defaultPakeEngine, type PakeEngine, type PakeProverStart, type PakeSecrets } from "./pake.js";

export const PAIRING_PROTOCOL_VERSION = "atb-pairing-v1" as const;
export const PRESENCE_PROTOCOL = "atb-presence-v1" as const;
export const PAIRING_CODE_LENGTH = 6 as const;
export const PAIRING_TTL_MS = 2 * 60_000;
/** A code is consumed by its first authenticated PAKE attempt; retry means a fresh code. */
export const PAIRING_MAX_ATTEMPTS = 1;

export type PairingRole = "machine" | "hub";
export interface PairingRoles { readonly machine: readonly string[]; readonly hub: readonly string[]; }
export interface PinnedPeerKey { readonly principalId: string; readonly publicKeySpki: string; readonly fingerprint: string; }
/** The frozen WP7a handoff contract consumed by hub presence and supervisor integration. */
export interface PinnedPeerKeyset {
  readonly pinnedPeerKey: PinnedPeerKey;
  readonly roles: PairingRoles;
  readonly presenceProtocol: typeof PRESENCE_PROTOCOL;
  readonly protocolVersion: typeof PAIRING_PROTOCOL_VERSION;
  readonly cipherSuite: typeof PAKE_CIPHER_SUITE;
}
export type PairingFailureCode = "wrong-code" | "expired-code" | "attempts-exhausted" | "key-mismatch" | "duplicate-identity" | "replayed-confirmation" | "protocol-downgrade";
export class PairingFailure extends Error {
  constructor(readonly code: PairingFailureCode, message: string = code) { super(message); this.name = "PairingFailure"; }
}

export interface PairingInvitation {
  readonly protocolVersion: typeof PAIRING_PROTOCOL_VERSION;
  readonly cipherSuite: typeof PAKE_CIPHER_SUITE;
  readonly presenceProtocol: typeof PRESENCE_PROTOCOL;
  readonly ceremonyId: string;
  readonly expiresAt: number;
  readonly hub: PinnedPeerKey;
  readonly roles: PairingRoles;
}
export interface MachineHello { readonly invitation: PairingInvitation; readonly machine: PinnedPeerKey; readonly proverShare: string; readonly machineSignature: string; }
export interface HubResponse { readonly ceremonyId: string; readonly verifierShare: string; readonly verifierConfirmation: string; readonly hubSignature: string; }
export interface MachineConfirmation { readonly ceremonyId: string; readonly proverConfirmation: string; readonly machineSignature: string; }
export interface MachinePairingResult { readonly confirmation: MachineConfirmation; readonly pairing: PinnedPeerKeyset; }
export interface HubPairingResult { readonly pairing: PinnedPeerKeyset; readonly sharedKey: Uint8Array; }
export interface HubCeremonyStart { readonly code: string; readonly invitation: PairingInvitation; readonly ceremony: HubPairingCeremony; }
export interface HubCeremonyOptions { readonly identity: StoredIdentity; readonly roles: PairingRoles; readonly now?: () => number; readonly random?: (length: number) => Uint8Array; readonly isDuplicateIdentity?: (principalId: string) => boolean; readonly pake?: PakeEngine; }
export interface MachineCeremonyOptions { readonly identity: StoredIdentity; readonly invitation: PairingInvitation; readonly code: string; readonly confirmedHubFingerprint: string; readonly pake?: PakeEngine; }

const encoder = new TextEncoder();
const toB64 = (value: Uint8Array): string => Buffer.from(value).toString("base64url");
const fromB64 = (value: string): Uint8Array => Buffer.from(value, "base64url");
const keyFrom = (identity: Pick<StoredIdentity, "principalId" | "publicKeySpki">): PinnedPeerKey => ({ principalId: identity.principalId, publicKeySpki: identity.publicKeySpki, fingerprint: fingerprintSpki(identity.publicKeySpki) });

function stableRoles(roles: PairingRoles): PairingRoles {
  const normalize = (values: readonly string[]): readonly string[] => [...new Set(values)].sort();
  return { machine: normalize(roles.machine), hub: normalize(roles.hub) };
}
function validKey(key: PinnedPeerKey): boolean { return key.principalId === fingerprintSpki(key.publicKeySpki) && key.fingerprint === key.principalId; }
function canonical(value: unknown): Uint8Array { return encoder.encode(JSON.stringify(value)); }
function context(invitation: PairingInvitation, machine: PinnedPeerKey): Uint8Array {
  return canonical({ protocolVersion: invitation.protocolVersion, cipherSuite: invitation.cipherSuite, presenceProtocol: invitation.presenceProtocol, ceremonyId: invitation.ceremonyId, hub: invitation.hub, machine, roles: invitation.roles });
}
function helloTranscript(hello: Omit<MachineHello, "machineSignature">): Uint8Array { return canonical({ type: "atb-pairing-hello-v1", invitation: hello.invitation, machine: hello.machine, proverShare: hello.proverShare }); }
function responseTranscript(hello: MachineHello, response: Omit<HubResponse, "hubSignature">): Uint8Array { return canonical({ type: "atb-pairing-response-v1", hello, response }); }
function confirmationTranscript(hello: MachineHello, response: HubResponse, confirmation: Omit<MachineConfirmation, "machineSignature">): Uint8Array { return canonical({ type: "atb-pairing-confirmation-v1", hello, response, confirmation }); }
function validInvitation(invitation: PairingInvitation, now: number): void {
  if (invitation.protocolVersion !== PAIRING_PROTOCOL_VERSION || invitation.cipherSuite !== PAKE_CIPHER_SUITE || invitation.presenceProtocol !== PRESENCE_PROTOCOL) throw new PairingFailure("protocol-downgrade");
  if (invitation.expiresAt <= now) throw new PairingFailure("expired-code");
  if (!validKey(invitation.hub)) throw new PairingFailure("key-mismatch");
}
function pairing(peer: PinnedPeerKey, roles: PairingRoles): PinnedPeerKeyset { return { pinnedPeerKey: peer, roles: stableRoles(roles), presenceProtocol: PRESENCE_PROTOCOL, protocolVersion: PAIRING_PROTOCOL_VERSION, cipherSuite: PAKE_CIPHER_SUITE }; }
function pairingCode(random: (length: number) => Uint8Array): string {
  const digits: string[] = [];
  for (let batch = 0; batch < 32 && digits.length < PAIRING_CODE_LENGTH; batch += 1) {
    for (const byte of random(16)) {
      if (byte < 250) digits.push(String(byte % 10));
      if (digits.length === PAIRING_CODE_LENGTH) return digits.join("");
    }
  }
  throw new Error("secure random source did not yield enough code digits");
}

/** Starts at the hub, where the one-time secret is born and displayed. */
export function startHubPairing(options: HubCeremonyOptions): HubCeremonyStart {
  const now = options.now ?? Date.now;
  const random = options.random ?? randomBytes;
  const ceremonyId = toB64(random(16));
  const code = pairingCode(random);
  const invitation: PairingInvitation = { protocolVersion: PAIRING_PROTOCOL_VERSION, cipherSuite: PAKE_CIPHER_SUITE, presenceProtocol: PRESENCE_PROTOCOL, ceremonyId, expiresAt: now() + PAIRING_TTL_MS, hub: keyFrom(options.identity), roles: stableRoles(options.roles) };
  return { code, invitation, ceremony: new HubPairingCeremony(options, invitation, code) };
}

/** Holds only one in-memory ceremony; callers own transport and durable storage. */
export class HubPairingCeremony {
  private attempts = 0;
  private completed = false;
  private hello?: MachineHello;
  private secrets?: PakeSecrets;
  constructor(private readonly options: HubCeremonyOptions, readonly invitation: PairingInvitation, private readonly code: string) {}
  respond(hello: MachineHello, confirmedMachineFingerprint: string): HubResponse {
    this.assertLive(true);
    validInvitation(hello.invitation, (this.options.now ?? Date.now)());
    if (JSON.stringify(hello.invitation) !== JSON.stringify(this.invitation)) throw new PairingFailure("key-mismatch");
    if (!validKey(hello.machine) || hello.machine.fingerprint !== confirmedMachineFingerprint) throw new PairingFailure("key-mismatch");
    if (this.options.isDuplicateIdentity?.(hello.machine.principalId)) throw new PairingFailure("duplicate-identity");
    if (!verifyTranscript(hello.machine.publicKeySpki, helloTranscript(hello), hello.machineSignature)) throw new PairingFailure("key-mismatch");
    const pake = this.options.pake ?? defaultPakeEngine;
    const registration = pake.register(this.code, hello.machine.principalId, this.invitation.hub.principalId, context(this.invitation, hello.machine));
    const response = pake.respond(registration, fromB64(hello.proverShare), hello.machine.principalId, this.invitation.hub.principalId, context(this.invitation, hello.machine));
    this.attempts += 1;
    this.hello = hello;
    this.secrets = response.secrets;
    const unsigned = { ceremonyId: this.invitation.ceremonyId, verifierShare: toB64(response.share), verifierConfirmation: toB64(response.secrets.verifierConfirmation) };
    return { ...unsigned, hubSignature: signTranscript(this.options.identity.privateKeyPkcs8, responseTranscript(hello, unsigned)) };
  }
  complete(response: HubResponse, confirmation: MachineConfirmation): HubPairingResult {
    this.assertLive();
    if (!this.hello || !this.secrets || response.ceremonyId !== this.invitation.ceremonyId || confirmation.ceremonyId !== this.invitation.ceremonyId) throw new PairingFailure("key-mismatch");
    const unsigned = { ceremonyId: confirmation.ceremonyId, proverConfirmation: confirmation.proverConfirmation };
    if (!verifyTranscript(this.hello.machine.publicKeySpki, confirmationTranscript(this.hello, response, unsigned), confirmation.machineSignature)) throw new PairingFailure("key-mismatch");
    const pake = this.options.pake ?? defaultPakeEngine;
    if (!pake.verify(this.secrets.proverConfirmation, fromB64(confirmation.proverConfirmation))) throw new PairingFailure("wrong-code");
    this.completed = true;
    return { pairing: pairing(this.hello.machine, this.invitation.roles), sharedKey: this.secrets.sharedKey };
  }
  private assertLive(consumingAttempt = false): void {
    if (this.completed) throw new PairingFailure("replayed-confirmation");
    if ((this.options.now ?? Date.now)() >= this.invitation.expiresAt) throw new PairingFailure("expired-code");
    if (consumingAttempt && this.attempts >= PAIRING_MAX_ATTEMPTS) throw new PairingFailure("attempts-exhausted");
  }
}

/** Starts at the machine after the user has matched the displayed hub fingerprint. */
export class MachinePairingCeremony {
  private start?: PakeProverStart;
  private hello?: MachineHello;
  constructor(private readonly options: MachineCeremonyOptions) {}
  createHello(): MachineHello {
    validInvitation(this.options.invitation, Date.now());
    if (this.options.confirmedHubFingerprint !== this.options.invitation.hub.fingerprint || !validKey(this.options.invitation.hub)) throw new PairingFailure("key-mismatch");
    const machine = keyFrom(this.options.identity);
    const pake = this.options.pake ?? defaultPakeEngine;
    const registration = pake.register(this.options.code, machine.principalId, this.options.invitation.hub.principalId, context(this.options.invitation, machine));
    this.start = pake.startProver(registration);
    const unsigned = { invitation: this.options.invitation, machine, proverShare: toB64(this.start.share) };
    this.hello = { ...unsigned, machineSignature: signTranscript(this.options.identity.privateKeyPkcs8, helloTranscript(unsigned)) };
    return this.hello;
  }
  complete(response: HubResponse): MachinePairingResult {
    if (!this.hello || !this.start) throw new PairingFailure("key-mismatch", "machine hello has not been created");
    if (response.ceremonyId !== this.options.invitation.ceremonyId || !verifyTranscript(this.options.invitation.hub.publicKeySpki, responseTranscript(this.hello, { ceremonyId: response.ceremonyId, verifierShare: response.verifierShare, verifierConfirmation: response.verifierConfirmation }), response.hubSignature)) throw new PairingFailure("key-mismatch");
    const pake = this.options.pake ?? defaultPakeEngine;
    const machine = this.hello.machine;
    const registration = pake.register(this.options.code, machine.principalId, this.options.invitation.hub.principalId, context(this.options.invitation, machine));
    const secrets = pake.finishProver(registration, this.start, fromB64(response.verifierShare), machine.principalId, this.options.invitation.hub.principalId, context(this.options.invitation, machine));
    if (!pake.verify(secrets.verifierConfirmation, fromB64(response.verifierConfirmation))) throw new PairingFailure("wrong-code");
    const unsigned = { ceremonyId: response.ceremonyId, proverConfirmation: toB64(secrets.proverConfirmation) };
    const confirmation = { ...unsigned, machineSignature: signTranscript(this.options.identity.privateKeyPkcs8, confirmationTranscript(this.hello, response, unsigned)) };
    return { confirmation, pairing: pairing(this.options.invitation.hub, this.options.invitation.roles) };
  }
}

/** In-memory representation for machine-wide durable storage owners; forget leaves no pairing residue. */
export class PairingState {
  private value?: PinnedPeerKeyset;
  get(): PinnedPeerKeyset | undefined { return this.value && structuredClone(this.value); }
  save(value: PinnedPeerKeyset): void { this.value = structuredClone(value); }
  forget(): void { this.value = undefined; }
}

declare interface PakeSharedValues { readonly Z: Uint8Array; readonly V: Uint8Array; }
declare interface PakeFinalKeys { readonly K_shared: Uint8Array; readonly confirmP: Uint8Array; readonly confirmV: Uint8Array; }
declare const p256: {
  deriveScalars(material: Uint8Array): { readonly w0: Uint8Array; readonly w1: Uint8Array };
  registerVerifier(w1: Uint8Array): Uint8Array;
  clientStart(w0: Uint8Array): { readonly x: Uint8Array; readonly shareP: Uint8Array };
  serverRespond(input: { readonly w0: Uint8Array; readonly L: Uint8Array; readonly shareP: Uint8Array }): { readonly shareV: Uint8Array } & PakeSharedValues;
  clientFinish(input: { readonly w0: Uint8Array; readonly w1: Uint8Array; readonly x: Uint8Array; readonly shareV: Uint8Array }): PakeSharedValues;
  deriveKeys(input: { readonly context: Uint8Array; readonly idProver: Uint8Array; readonly idVerifier: Uint8Array; readonly w0: Uint8Array; readonly shareP: Uint8Array; readonly shareV: Uint8Array; readonly Z: Uint8Array; readonly V: Uint8Array }): PakeFinalKeys;
  verifyConfirmation(expected: Uint8Array, received: Uint8Array): boolean;
  __clientStartWithScalar(w0: Uint8Array, scalar: bigint): { readonly x: Uint8Array; readonly shareP: Uint8Array };
  __serverRespondWithScalar(input: { readonly w0: Uint8Array; readonly L: Uint8Array; readonly shareP: Uint8Array }, scalar: bigint): { readonly shareV: Uint8Array } & PakeSharedValues;
};
export { p256 };

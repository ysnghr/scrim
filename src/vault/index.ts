// Session-scoped token vault.
// Storage: in-memory map plus an encrypted file at .scrim/vault.bin (key derived per session).
// Never transmitted; never logged. Wiped on session end.
// Fail-closed: any read/write error throws so callers can reject the tool call.

export interface Vault {
  tokenize(value: string, klass: string): string;     // returns ⟦scrim:class:id⟧
  resolve(token: string): string | null;              // null if unknown
  size(): number;
  wipe(): void;
}

export function openVault(_sessionId: string, _root: string): Vault {
  throw new Error("openVault: not implemented yet");
}

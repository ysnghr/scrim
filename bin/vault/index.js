// Session-scoped token vault.
// Storage: in-memory map plus an encrypted file at .scrim/vault.bin (key derived per session).
// Never transmitted; never logged. Wiped on session end.
// Fail-closed: any read/write error throws so callers can reject the tool call.
export function openVault(_sessionId, _root) {
    throw new Error("openVault: not implemented yet");
}

// AES-256-GCM helpers for the session vault.
//
// Packed format on disk: iv(12) || tag(16) || ciphertext(...)
// IVs are 96-bit random — collision probability is negligible at vault scale.
// On any decrypt failure (wrong key, truncated file, tampered bytes) Node
// throws and the caller treats it as fail-closed.
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
const ALGO = "aes-256-gcm";
const IV_LEN = 12;
const TAG_LEN = 16;
export const KEY_LEN = 32;
export function generateKey() {
    return randomBytes(KEY_LEN);
}
export function encrypt(key, plaintext) {
    if (key.length !== KEY_LEN)
        throw new Error("scrim: vault key must be 32 bytes");
    const iv = randomBytes(IV_LEN);
    const cipher = createCipheriv(ALGO, key, iv);
    const ct = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
    const tag = cipher.getAuthTag();
    return Buffer.concat([iv, tag, ct]);
}
export function decrypt(key, packed) {
    if (key.length !== KEY_LEN)
        throw new Error("scrim: vault key must be 32 bytes");
    if (packed.length < IV_LEN + TAG_LEN)
        throw new Error("scrim: vault payload truncated");
    const iv = packed.subarray(0, IV_LEN);
    const tag = packed.subarray(IV_LEN, IV_LEN + TAG_LEN);
    const ct = packed.subarray(IV_LEN + TAG_LEN);
    const decipher = createDecipheriv(ALGO, key, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ct), decipher.final()]).toString("utf8");
}

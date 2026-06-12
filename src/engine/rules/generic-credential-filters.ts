// Post-match filters for the generic-credential-assignment rule.
//
// The catchall rule fires on `password = ...`, `secret = ...`, `api_key = ...`
// shapes and is responsible for catching secrets that have no vendor-specific
// prefix. Its single Shannon-entropy gate at 3.0 was a one-knob signal — it
// missed real low-entropy passwords (`Password1` ≈ 2.95) and over-fired on
// benign high-entropy strings (`secret = "Hello, World!"`).
//
// We layer three orthogonal signals on top of (a now-lower) entropy threshold:
//
//   1. Placeholder denylist — common dummy values that look like secrets but
//      aren't. Case-insensitive whole-value match.
//   2. Value-shape filters — strings that have a recognizable non-secret shape
//      (IP address, URL, English-with-punctuation greeting) are rejected even
//      if their entropy is high. URLs containing real credentials are caught
//      by the separate url-basic-auth rule which strips the URL chrome and
//      tokenizes only the password portion.
//   3. Entropy threshold (lowered from 3.0 → 2.7) — still the long-tail
//      catch-all for truly random values that don't match a vendor prefix.
//
// The threshold is exposed via policy (detection.entropy.generic_credential)
// so users in noisy environments can raise it without forking.

import { shannonEntropy } from "./secrets-rules.js";

// Whole-value placeholder patterns. Each entry is a regex that must match the
// ENTIRE captured value (no partial matches), case-insensitively. Add new
// entries here when a real-world false positive surfaces — better than
// nudging the entropy knob.
const PLACEHOLDER_DENYLIST: RegExp[] = [
  // Bare placeholders. We intentionally do NOT add `\d*` here — `Password1`,
  // `secret2024`, etc. are weak-but-real chosen passwords; only the literal
  // tokens are placeholders.
  /^password$/i,
  /^p[a@]ssw[o0]rd$/i,
  /^secret$/i,
  /^xxx+$/i,
  /^y+e+s+$/i,
  // `changeme` and `changeme123` are both "I will change this later" — the
  // \d* here is OK because the prefix is itself a convention.
  /^change[\s\-_]?me\d*$/i,
  /^your[_\-\s]?(?:api[_\-\s]?key|secret|token|password|pass)$/i,
  /^placeholder$/i,
  /^example$/i,
  /^todo$/i,
  /^fixme$/i,
  /^test(?:ing)?$/i,
  /^demo$/i,
  /^foo(?:bar)?$/i,
  /^bar$/i,
  /^baz$/i,
  /^hunter2$/i,             // the canonical joke placeholder
  /^correct[_\-\s]?horse[_\-\s]?battery[_\-\s]?staple$/i,
  /^hello[,!\s]+world[!.]?$/i,
  // URL scheme names that get captured when the value-shape filter can't
  // see the trailing `://` (the rule's char class stops at `:`). Treat
  // these as placeholders so e.g. `password = postgres://...` doesn't
  // flag `postgres` itself as a secret.
  /^postgres(?:ql)?$/i,
  /^mongodb(?:\+srv)?$/i,
];

export function isPlaceholder(value: string): boolean {
  for (const re of PLACEHOLDER_DENYLIST) if (re.test(value)) return true;
  return false;
}

// IPv4 + a coarse IPv6 shape. Used to reject `password = 127.0.0.1` —
// almost always a hostname misuse, never a real credential.
const IPV4 = /^\d{1,3}(?:\.\d{1,3}){3}$/;
const IPV6_HEX = /^[0-9a-fA-F:]+$/;

export function looksLikeIp(value: string): boolean {
  if (IPV4.test(value)) {
    return value.split(".").every((p) => {
      const n = Number(p);
      return n >= 0 && n <= 255;
    });
  }
  if (value.includes(":") && IPV6_HEX.test(value)) {
    // Crude: at least 2 colons and one hex group >= 2 chars.
    const parts = value.split(":");
    return parts.length >= 3 && parts.some((p) => p.length >= 2);
  }
  return false;
}

const URL_SHAPE = /^[a-z][a-z0-9+.\-]*:\/\//i;

export function looksLikeUrl(value: string): boolean {
  return URL_SHAPE.test(value);
}

// English-with-punctuation: spaces + commas + sentence punctuation. Catches
// `secret = "Hello, World!"` and similar prose that bypasses entropy because
// of varied character classes.
export function looksLikePunctuationGreeting(value: string): boolean {
  // Must contain at least one space AND at least one ASCII punctuation char.
  if (!/\s/.test(value)) return false;
  if (!/[,.!?;:]/.test(value)) return false;
  // The value is "mostly" letters + spaces + punctuation (no long runs of
  // hex/base64-like noise).
  const letterLike = (value.match(/[A-Za-z\s,.!?;:'"]/g) ?? []).length;
  return letterLike / value.length >= 0.85;
}

export interface GenericCredentialFilterOptions {
  // Minimum Shannon entropy required after all other filters pass.
  entropyThreshold: number;
}

export function acceptGenericCredential(
  value: string,
  opts: GenericCredentialFilterOptions,
): boolean {
  if (isPlaceholder(value)) return false;
  if (looksLikeIp(value)) return false;
  if (looksLikeUrl(value)) return false;
  if (looksLikePunctuationGreeting(value)) return false;
  if (shannonEntropy(value) < opts.entropyThreshold) return false;
  return true;
}

export const DEFAULT_GENERIC_CREDENTIAL_ENTROPY = 2.7;

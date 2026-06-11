// Session-scoped token vault.
//
// Storage layout (under `<repoRoot>/.scrim/vault/`):
//   key            32-byte AES-256 key, mode 0600. Written once by whichever
//                  process opens the vault first (usually the MCP server) and
//                  read by the hooks. Generating a new key invalidates every
//                  existing token — that's the intended "session end" behavior.
//   session.bin    Encrypted JSON state (iv || tag || ciphertext). Written
//                  atomically via tmp + rename so concurrent readers never see
//                  a torn file.
//
// Concurrency note: the MCP server is the only writer; hooks only read. Within
// the MCP server we serialize tokenize() with a simple in-memory pending chain.
// Across processes, reads might race a write, but atomic rename guarantees the
// reader sees either the old complete state or the new complete state — never
// both. A token issued after the read just isn't resolvable yet; the hook treats
// that as fail-closed and rejects the write.

import {
  mkdirSync,
  readFileSync,
  writeFileSync,
  renameSync,
  existsSync,
  unlinkSync,
  rmSync,
  chmodSync,
} from "node:fs";
import { join, dirname } from "node:path";
import { createHash, randomBytes } from "node:crypto";
import { encrypt, decrypt, generateKey, KEY_LEN } from "./crypto.js";
import { formatToken, parseTokens } from "../tokens.js";

export interface VaultEntry {
  klass: string;
  value: string;        // present in-memory only
  valueHash: string;    // sha256(value), used for value→token reverse lookup
  ruleId: string;
  createdAt: string;    // ISO-8601
}

export interface VaultStats {
  size: number;
  createdAt: string;
}

export interface Vault {
  // Returns the existing token for `value` if one was minted earlier this
  // session, otherwise mints a new one and persists it.
  tokenize(value: string, klass: string, ruleId?: string): string;
  // Returns the original value for a token, or null if unknown.
  resolve(token: string): string | null;
  // Convenience: resolve every token in `text`. Returns the rewritten string
  // and the list of tokens that could not be resolved.
  resolveAll(text: string): { output: string; missing: string[] };
  // Update the value an existing token resolves to. The token slug stays the
  // same so existing context references keep working; future detokenize calls
  // restore the new value. Throws if the token is unknown.
  updateValue(token: string, newValue: string): { previousValueHash: string };
  // Number of distinct values currently tokenized.
  size(): number;
  // Vault metadata for /scrim:status.
  stats(): VaultStats;
  // Remove the vault files from disk and clear in-memory state.
  wipe(): void;
  // Drain the eviction queue (LRU evictions accumulated since last call) so
  // the caller can audit them. Returns evicted tokens in eviction order.
  drainEvicted(): string[];
}

type StoredEntry = Omit<VaultEntry, "value"> & { value: string };

interface VaultState {
  createdAt: string;
  // Map preserves insertion order; we use that for LRU. Existing-entry access
  // re-inserts at the tail (MRU). Eviction takes the head (LRU).
  entries: Map<string, StoredEntry>;
  byHash: Map<string, string>; // valueHash → token
}

// On-disk format (kept for backwards compat with existing vault files). Stored
// as plain objects so JSON.stringify works; converted to Maps in memory.
interface PersistedState {
  createdAt: string;
  entries: Record<string, StoredEntry>;
  byHash: Record<string, string>;
}

interface VaultPaths {
  dir: string;
  keyPath: string;
  vaultPath: string;
}

function paths(repoRoot: string): VaultPaths {
  const dir = join(repoRoot, ".scrim", "vault");
  return { dir, keyPath: join(dir, "key"), vaultPath: join(dir, "session.bin") };
}

function loadOrCreateKey(p: VaultPaths): Buffer {
  if (existsSync(p.keyPath)) {
    const key = readFileSync(p.keyPath);
    if (key.length !== KEY_LEN) {
      throw new Error(`scrim: vault key at ${p.keyPath} is not ${KEY_LEN} bytes`);
    }
    return key;
  }
  mkdirSync(p.dir, { recursive: true });
  const key = generateKey();
  writeFileAtomic(p.keyPath, key, 0o600);
  return key;
}

function loadState(p: VaultPaths, key: Buffer): VaultState {
  if (!existsSync(p.vaultPath)) {
    return { createdAt: new Date().toISOString(), entries: new Map(), byHash: new Map() };
  }
  const packed = readFileSync(p.vaultPath);
  let json: string;
  try {
    json = decrypt(key, packed);
  } catch (err) {
    // Fail-closed: a corrupt or mis-keyed vault must not silently reset to
    // empty, because that would let a write hook pass tokens through unmasked.
    throw new Error(
      `scrim: vault at ${p.vaultPath} could not be decrypted (key mismatch or corruption)`,
      { cause: err },
    );
  }
  const parsed = JSON.parse(json) as PersistedState;
  if (!parsed.entries || !parsed.byHash) {
    throw new Error("scrim: vault payload is missing required fields");
  }
  return {
    createdAt: parsed.createdAt,
    entries: new Map(Object.entries(parsed.entries)),
    byHash: new Map(Object.entries(parsed.byHash)),
  };
}

function writeFileAtomic(path: string, data: Buffer, mode: number): void {
  mkdirSync(dirname(path), { recursive: true });
  const tmp = `${path}.tmp.${process.pid}.${randomBytes(4).toString("hex")}`;
  writeFileSync(tmp, data, { mode });
  try {
    chmodSync(tmp, mode);
  } catch {
    // Best-effort; some filesystems ignore mode bits.
  }
  renameSync(tmp, path);
}

function sha256Hex(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function newId(): string {
  // 4 bytes → 8 hex chars; per-session id space of 2^32 is plenty.
  return randomBytes(4).toString("hex");
}

class FileVault implements Vault {
  // Tokens evicted by LRU since the last drainEvicted() call. Held in-process
  // so the MCP server (which owns the long-lived vault handle) can audit them
  // immediately after the mint that caused the eviction.
  private evicted: string[] = [];

  constructor(
    private readonly p: VaultPaths,
    private readonly key: Buffer,
    private state: VaultState,
    private readonly maxEntries: number,
  ) {}

  tokenize(value: string, klass: string, ruleId: string = klass): string {
    if (value.length === 0) {
      throw new Error("scrim: refusing to tokenize empty value");
    }
    const valueHash = sha256Hex(value);
    const existing = this.state.byHash.get(valueHash);
    if (existing) {
      // Cache hit: bump to MRU by delete+re-insert.
      const entry = this.state.entries.get(existing);
      if (entry) {
        this.state.entries.delete(existing);
        this.state.entries.set(existing, entry);
      }
      return existing;
    }

    let id = newId();
    // Vanishingly unlikely id collision; loop just in case.
    while (this.state.entries.has(formatToken(klass, id))) id = newId();
    const token = formatToken(klass, id);

    this.state.entries.set(token, {
      klass,
      value,
      valueHash,
      ruleId,
      createdAt: new Date().toISOString(),
    });
    this.state.byHash.set(valueHash, token);
    this.enforceCap();
    this.persist();
    return token;
  }

  resolve(token: string): string | null {
    const entry = this.state.entries.get(token);
    if (!entry) return null;
    // Bump to MRU on resolve too — a token actively used by the agent should
    // not be a candidate for eviction.
    this.state.entries.delete(token);
    this.state.entries.set(token, entry);
    return entry.value;
  }

  resolveAll(text: string): { output: string; missing: string[] } {
    const tokens = parseTokens(text);
    if (tokens.length === 0) return { output: text, missing: [] };
    const missing: string[] = [];
    let out = "";
    let cursor = 0;
    for (const t of tokens) {
      out += text.slice(cursor, t.start);
      const v = this.resolve(t.raw);
      if (v == null) {
        missing.push(t.raw);
        out += t.raw;
      } else {
        out += v;
      }
      cursor = t.end;
    }
    out += text.slice(cursor);
    return { output: out, missing };
  }

  updateValue(token: string, newValue: string): { previousValueHash: string } {
    if (newValue.length === 0) {
      throw new Error("scrim: refusing to set empty value");
    }
    const entry = this.state.entries.get(token);
    if (!entry) {
      throw new Error(`scrim: unknown token: ${token}`);
    }
    const prior = entry.valueHash;
    const next = sha256Hex(newValue);
    // Drop the old byHash mapping so a future re-encounter of the prior value
    // re-mints a fresh token rather than reusing this one.
    this.state.byHash.delete(prior);
    entry.value = newValue;
    entry.valueHash = next;
    // If the new value collides with an existing token, the existing token wins
    // its byHash slot. We don't merge tokens — that would invalidate the slug
    // in already-issued content.
    if (!this.state.byHash.has(next)) {
      this.state.byHash.set(next, token);
    }
    // Bump to MRU.
    this.state.entries.delete(token);
    this.state.entries.set(token, entry);
    this.persist();
    return { previousValueHash: prior };
  }

  size(): number {
    return this.state.entries.size;
  }

  stats(): VaultStats {
    return { size: this.size(), createdAt: this.state.createdAt };
  }

  wipe(): void {
    this.state = { createdAt: new Date().toISOString(), entries: new Map(), byHash: new Map() };
    this.evicted = [];
    for (const path of [this.p.vaultPath, this.p.keyPath]) {
      try {
        if (existsSync(path)) unlinkSync(path);
      } catch {
        // best-effort
      }
    }
    try {
      rmSync(this.p.dir, { recursive: true, force: true });
    } catch {
      // best-effort
    }
  }

  drainEvicted(): string[] {
    const out = this.evicted;
    this.evicted = [];
    return out;
  }

  // Remove LRU entries until size <= maxEntries. Records each evicted token
  // for the caller to audit. maxEntries === 0 disables the cap.
  private enforceCap(): void {
    if (this.maxEntries <= 0) return;
    while (this.state.entries.size > this.maxEntries) {
      const lru = this.state.entries.keys().next();
      if (lru.done) break;
      const token = lru.value;
      const entry = this.state.entries.get(token);
      this.state.entries.delete(token);
      if (entry) this.state.byHash.delete(entry.valueHash);
      this.evicted.push(token);
    }
  }

  private persist(): void {
    const persisted: PersistedState = {
      createdAt: this.state.createdAt,
      entries: Object.fromEntries(this.state.entries),
      byHash: Object.fromEntries(this.state.byHash),
    };
    const json = JSON.stringify(persisted);
    const packed = encrypt(this.key, json);
    writeFileAtomic(this.p.vaultPath, packed, 0o600);
  }
}

export interface OpenVaultOptions {
  maxEntries?: number;   // LRU cap; 0 disables eviction. Default: 10_000.
}

export function openVault(repoRoot: string, opts: OpenVaultOptions = {}): Vault {
  const p = paths(repoRoot);
  const key = loadOrCreateKey(p);
  const state = loadState(p, key);
  const maxEntries = opts.maxEntries ?? 10_000;
  return new FileVault(p, key, state, maxEntries);
}

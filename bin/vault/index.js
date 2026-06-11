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
import { mkdirSync, readFileSync, writeFileSync, renameSync, existsSync, unlinkSync, rmSync, chmodSync, } from "node:fs";
import { join, dirname } from "node:path";
import { createHash, randomBytes } from "node:crypto";
import { encrypt, decrypt, generateKey, KEY_LEN } from "./crypto.js";
import { formatToken, parseTokens } from "../tokens.js";
function paths(repoRoot) {
    const dir = join(repoRoot, ".scrim", "vault");
    return { dir, keyPath: join(dir, "key"), vaultPath: join(dir, "session.bin") };
}
function loadOrCreateKey(p) {
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
function loadState(p, key) {
    if (!existsSync(p.vaultPath)) {
        return { createdAt: new Date().toISOString(), entries: new Map(), byHash: new Map() };
    }
    const packed = readFileSync(p.vaultPath);
    let json;
    try {
        json = decrypt(key, packed);
    }
    catch (err) {
        // Fail-closed: a corrupt or mis-keyed vault must not silently reset to
        // empty, because that would let a write hook pass tokens through unmasked.
        throw new Error(`scrim: vault at ${p.vaultPath} could not be decrypted (key mismatch or corruption)`, { cause: err });
    }
    const parsed = JSON.parse(json);
    if (!parsed.entries || !parsed.byHash) {
        throw new Error("scrim: vault payload is missing required fields");
    }
    return {
        createdAt: parsed.createdAt,
        entries: new Map(Object.entries(parsed.entries)),
        byHash: new Map(Object.entries(parsed.byHash)),
    };
}
function writeFileAtomic(path, data, mode) {
    mkdirSync(dirname(path), { recursive: true });
    const tmp = `${path}.tmp.${process.pid}.${randomBytes(4).toString("hex")}`;
    writeFileSync(tmp, data, { mode });
    try {
        chmodSync(tmp, mode);
    }
    catch {
        // Best-effort; some filesystems ignore mode bits.
    }
    renameSync(tmp, path);
}
function sha256Hex(value) {
    return createHash("sha256").update(value, "utf8").digest("hex");
}
function newId() {
    // 6 bytes → 12 hex chars; birthday-bound 50% collision at ~20M mints —
    // comfortably above the default LRU cap of 10k.
    return randomBytes(6).toString("hex");
}
class FileVault {
    p;
    key;
    state;
    maxEntries;
    // Tokens evicted by LRU since the last drainEvicted() call. Held in-process
    // so the MCP server (which owns the long-lived vault handle) can audit them
    // immediately after the mint that caused the eviction.
    evicted = [];
    constructor(p, key, state, maxEntries) {
        this.p = p;
        this.key = key;
        this.state = state;
        this.maxEntries = maxEntries;
    }
    tokenize(value, klass, ruleId = klass) {
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
        while (this.state.entries.has(formatToken(klass, id)))
            id = newId();
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
    resolve(token) {
        const entry = this.state.entries.get(token);
        if (!entry)
            return null;
        // Bump to MRU on resolve too — a token actively used by the agent should
        // not be a candidate for eviction.
        this.state.entries.delete(token);
        this.state.entries.set(token, entry);
        return entry.value;
    }
    resolveAll(text) {
        const tokens = parseTokens(text);
        if (tokens.length === 0)
            return { output: text, missing: [] };
        const missing = [];
        let out = "";
        let cursor = 0;
        for (const t of tokens) {
            out += text.slice(cursor, t.start);
            const v = this.resolve(t.raw);
            if (v == null) {
                missing.push(t.raw);
                out += t.raw;
            }
            else {
                out += v;
            }
            cursor = t.end;
        }
        out += text.slice(cursor);
        return { output: out, missing };
    }
    updateValue(token, newValue) {
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
    size() {
        return this.state.entries.size;
    }
    stats() {
        return { size: this.size(), createdAt: this.state.createdAt };
    }
    wipe() {
        this.state = { createdAt: new Date().toISOString(), entries: new Map(), byHash: new Map() };
        this.evicted = [];
        for (const path of [this.p.vaultPath, this.p.keyPath]) {
            try {
                if (existsSync(path))
                    unlinkSync(path);
            }
            catch {
                // best-effort
            }
        }
        try {
            rmSync(this.p.dir, { recursive: true, force: true });
        }
        catch {
            // best-effort
        }
    }
    drainEvicted() {
        const out = this.evicted;
        this.evicted = [];
        return out;
    }
    // Remove LRU entries until size <= maxEntries. Records each evicted token
    // for the caller to audit. maxEntries === 0 disables the cap.
    enforceCap() {
        if (this.maxEntries <= 0)
            return;
        while (this.state.entries.size > this.maxEntries) {
            const lru = this.state.entries.keys().next();
            if (lru.done)
                break;
            const token = lru.value;
            const entry = this.state.entries.get(token);
            this.state.entries.delete(token);
            if (entry)
                this.state.byHash.delete(entry.valueHash);
            this.evicted.push(token);
        }
    }
    persist() {
        const persisted = {
            createdAt: this.state.createdAt,
            entries: Object.fromEntries(this.state.entries),
            byHash: Object.fromEntries(this.state.byHash),
        };
        const json = JSON.stringify(persisted);
        const packed = encrypt(this.key, json);
        writeFileAtomic(this.p.vaultPath, packed, 0o600);
    }
}
export function openVault(repoRoot, opts = {}) {
    const p = paths(repoRoot);
    const key = loadOrCreateKey(p);
    const state = loadState(p, key);
    const maxEntries = opts.maxEntries ?? 10_000;
    return new FileVault(p, key, state, maxEntries);
}

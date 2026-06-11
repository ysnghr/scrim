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
        return { createdAt: new Date().toISOString(), entries: {}, byHash: {} };
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
    return parsed;
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
    // 4 bytes → 8 hex chars; per-session id space of 2^32 is plenty.
    return randomBytes(4).toString("hex");
}
class FileVault {
    p;
    key;
    state;
    constructor(p, key, state) {
        this.p = p;
        this.key = key;
        this.state = state;
    }
    tokenize(value, klass, ruleId = klass) {
        if (value.length === 0) {
            throw new Error("scrim: refusing to tokenize empty value");
        }
        const valueHash = sha256Hex(value);
        const existing = this.state.byHash[valueHash];
        if (existing)
            return existing;
        let id = newId();
        // Vanishingly unlikely id collision; loop just in case.
        while (this.state.entries[formatToken(klass, id)])
            id = newId();
        const token = formatToken(klass, id);
        this.state.entries[token] = {
            klass,
            value,
            valueHash,
            ruleId,
            createdAt: new Date().toISOString(),
        };
        this.state.byHash[valueHash] = token;
        this.persist();
        return token;
    }
    resolve(token) {
        const entry = this.state.entries[token];
        return entry ? entry.value : null;
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
    size() {
        return Object.keys(this.state.entries).length;
    }
    stats() {
        return { size: this.size(), createdAt: this.state.createdAt };
    }
    wipe() {
        this.state = { createdAt: new Date().toISOString(), entries: {}, byHash: {} };
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
    persist() {
        const json = JSON.stringify(this.state);
        const packed = encrypt(this.key, json);
        writeFileAtomic(this.p.vaultPath, packed, 0o600);
    }
}
export function openVault(repoRoot) {
    const p = paths(repoRoot);
    const key = loadOrCreateKey(p);
    const state = loadState(p, key);
    return new FileVault(p, key, state);
}

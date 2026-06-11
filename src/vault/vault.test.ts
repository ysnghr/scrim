// Vault smoke tests. Cover the cross-process and fail-closed paths in
// particular — those are the contracts the hooks depend on.

import { test } from "node:test";
import { strict as assert } from "node:assert";
import { mkdtempSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { openVault } from "./index.js";
import { parseTokens, formatToken, replaceTokens } from "../tokens.js";

function freshRepo(): string {
  return mkdtempSync(join(tmpdir(), "scrim-vault-"));
}

test("tokenize round-trips through resolve", () => {
  const root = freshRepo();
  const v = openVault(root);
  const token = v.tokenize("hunter2-supersecret", "db_password");
  assert.match(token, /^⟦scrim:db_password:[a-f0-9]{8}⟧$/);
  assert.equal(v.resolve(token), "hunter2-supersecret");
});

test("same value yields the same token within a session", () => {
  const root = freshRepo();
  const v = openVault(root);
  const t1 = v.tokenize("AKIAIOSFODNN7EXAMPL2", "aws-access-key-id");
  const t2 = v.tokenize("AKIAIOSFODNN7EXAMPL2", "aws-access-key-id");
  assert.equal(t1, t2);
  assert.equal(v.size(), 1);
});

test("different values yield different tokens", () => {
  const root = freshRepo();
  const v = openVault(root);
  const t1 = v.tokenize("alpha", "secrets");
  const t2 = v.tokenize("beta", "secrets");
  assert.notEqual(t1, t2);
  assert.equal(v.size(), 2);
});

test("resolveAll rewrites tokens and reports missing ones", () => {
  const root = freshRepo();
  const v = openVault(root);
  const tok = v.tokenize("realpw", "secrets");
  const text = `db: { password: ${tok}, also: ⟦scrim:unknown:deadbeef⟧ }`;
  const { output, missing } = v.resolveAll(text);
  assert.equal(output, `db: { password: realpw, also: ⟦scrim:unknown:deadbeef⟧ }`);
  assert.deepEqual(missing, ["⟦scrim:unknown:deadbeef⟧"]);
});

test("cross-process: a second vault instance on the same dir resolves tokens minted by the first", () => {
  // This simulates the MCP server minting a token, then the detokenize hook
  // (a separate Node process) opening the vault and restoring real bytes.
  const root = freshRepo();
  const mcp = openVault(root);
  const token = mcp.tokenize("hunter2", "db_password");

  const hook = openVault(root);
  assert.equal(hook.resolve(token), "hunter2");
});

test("fail-closed: corrupt vault file throws on open", () => {
  const root = freshRepo();
  const v = openVault(root);
  v.tokenize("hunter2", "secrets");

  // Corrupt the encrypted body.
  const vaultPath = join(root, ".scrim", "vault", "session.bin");
  const buf = readFileSync(vaultPath);
  buf[buf.length - 1] = (buf[buf.length - 1]! ^ 0xff) & 0xff;
  writeFileSync(vaultPath, buf);

  assert.throws(() => openVault(root), /could not be decrypted/);
});

test("fail-closed: mismatched key throws on open", () => {
  const root = freshRepo();
  const v = openVault(root);
  v.tokenize("hunter2", "secrets");

  // Rotate the key without rewriting the vault — emulates a partial session reset.
  const keyPath = join(root, ".scrim", "vault", "key");
  writeFileSync(keyPath, Buffer.alloc(32, 0xaa));

  assert.throws(() => openVault(root), /could not be decrypted/);
});

test("wipe removes vault and key files", () => {
  const root = freshRepo();
  const v = openVault(root);
  v.tokenize("hunter2", "secrets");
  const keyPath = join(root, ".scrim", "vault", "key");
  const vaultPath = join(root, ".scrim", "vault", "session.bin");
  assert.ok(existsSync(keyPath));
  assert.ok(existsSync(vaultPath));
  v.wipe();
  assert.ok(!existsSync(keyPath));
  assert.ok(!existsSync(vaultPath));
  assert.equal(v.size(), 0);
});

test("refuses to tokenize empty value", () => {
  const root = freshRepo();
  const v = openVault(root);
  assert.throws(() => v.tokenize("", "secrets"), /empty value/);
});

test("token format helpers parse and emit correctly", () => {
  const t = formatToken("aws-access-key-id", "deadbeef");
  assert.equal(t, "⟦scrim:aws-access-key-id:deadbeef⟧");
  const parsed = parseTokens(`prefix ${t} suffix ⟦scrim:email:ab12⟧ end`);
  assert.equal(parsed.length, 2);
  assert.equal(parsed[0]!.class, "aws-access-key-id");
  assert.equal(parsed[0]!.id, "deadbeef");
  assert.equal(parsed[1]!.class, "email");

  const { output, missing } = replaceTokens(`x=${t}`, (raw) => (raw === t ? "VALUE" : null));
  assert.equal(output, "x=VALUE");
  assert.deepEqual(missing, []);
});

test("formatToken rejects invalid class or id", () => {
  assert.throws(() => formatToken("bad class", "abc"), /invalid token class/);
  assert.throws(() => formatToken("ok", "bad-id"), /invalid token id/);
});

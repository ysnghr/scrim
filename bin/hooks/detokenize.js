// Pure logic for the Write|Edit|MultiEdit detokenize hook.
//
// Walks every string leaf of `tool_input`, replaces ⟦scrim:...⟧ tokens with the
// real values from the vault, and returns a hook output object the runner
// writes to stdout. Fail-closed: if ANY token cannot be resolved the hook
// denies the tool call rather than letting a half-restored payload reach disk.
//
// This module is deliberately pure: it takes a vault-like dependency and the
// hook input, and returns the output. The thin entrypoint at
// src/scrim-detokenize.ts handles stdin/stdout and process exit codes.
import { parseTokens } from "../tokens.js";
// Walk `value` recursively. Anywhere we hit a string, rewrite every Scrim token
// in it using `vault.resolve`. Records replacements made and tokens that could
// not be resolved. Returns a new value (does not mutate the input).
export function rewriteStrings(value, vault, stats) {
    if (typeof value === "string") {
        const tokens = parseTokens(value);
        if (tokens.length === 0)
            return value;
        let out = "";
        let cursor = 0;
        for (const t of tokens) {
            out += value.slice(cursor, t.start);
            const v = vault.resolve(t.raw);
            if (v == null) {
                stats.missing.push(t.raw);
                out += t.raw;
            }
            else {
                stats.replaced++;
                out += v;
            }
            cursor = t.end;
        }
        out += value.slice(cursor);
        return out;
    }
    if (Array.isArray(value)) {
        return value.map((v) => rewriteStrings(v, vault, stats));
    }
    if (value && typeof value === "object") {
        const out = {};
        for (const [k, v] of Object.entries(value)) {
            out[k] = rewriteStrings(v, vault, stats);
        }
        return out;
    }
    return value;
}
export function detokenize(input, vault) {
    const stats = { replaced: 0, missing: [] };
    const updated = rewriteStrings(input.tool_input, vault, stats);
    if (stats.missing.length > 0) {
        // Fail-closed: deny rather than let half-restored content reach disk.
        const sample = stats.missing.slice(0, 3).join(", ");
        return {
            output: {
                hookSpecificOutput: {
                    hookEventName: "PreToolUse",
                    permissionDecision: "deny",
                    permissionDecisionReason: `scrim: refusing write — ${stats.missing.length} token(s) could not be resolved` +
                        ` (sample: ${sample}). Re-run safe_read so the vault sees the originals,` +
                        ` or remove the unknown token from your edit.`,
                },
            },
            stats,
        };
    }
    if (stats.replaced === 0) {
        // No tokens at all — pass through silently.
        return {
            output: { hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "allow" } },
            stats,
        };
    }
    return {
        output: {
            hookSpecificOutput: {
                hookEventName: "PreToolUse",
                permissionDecision: "allow",
                permissionDecisionReason: `scrim: restored ${stats.replaced} token(s) before write`,
                updatedInput: updated,
            },
        },
        stats,
    };
}

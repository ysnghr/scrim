// The redaction pipeline shared by safe_read, safe_grep, and safe_shell.
//
// detect(text) -> spans
//   for each span:
//     action = policy.actions[span.class] (default: redact)
//     redact  -> tokenize value via vault, splice token into output, audit "redact"
//     alert   -> leave value in output, audit "alert"
//     block   -> throw BlockedError so the tool call is rejected, audit "block"
//     allow   -> leave value in output, no audit
//
// Spans are produced sorted-by-start with no overlap (see mergeSpans), so we
// can walk them in order and build the masked output in a single pass.
import { detect } from "../engine/index.js";
import { append as auditAppend, hashValue } from "../audit/index.js";
import { actionFor } from "../policy/index.js";
export class BlockedError extends Error {
    ruleId;
    klass;
    constructor(ruleId, klass) {
        super(`scrim: policy blocks ${klass} (rule: ${ruleId})`);
        this.ruleId = ruleId;
        this.klass = klass;
        this.name = "BlockedError";
    }
}
export function processText(text, tool, ctx) {
    if (text.length === 0)
        return { output: "", detections: [] };
    const spans = detect(text, ctx.engine);
    if (spans.length === 0)
        return { output: text, detections: [] };
    let out = "";
    let cursor = 0;
    const detections = [];
    for (const span of spans) {
        out += text.slice(cursor, span.start);
        const value = text.slice(span.start, span.end);
        const action = actionFor(ctx.policy, span.class);
        const valueHash = hashValue(ctx.repoRoot, value);
        if (action === "redact") {
            // The visible token slug is the rule id (e.g. "aws-access-key-id") because
            // that is what is informative to the agent reading the masked content.
            // The policy class (e.g. "secrets") is what drove the action lookup above.
            const tokenRef = ctx.vault.tokenize(value, span.ruleId, span.ruleId);
            out += tokenRef;
            auditAppend(ctx.repoRoot, {
                ruleId: span.ruleId, tool, action: "redact", tokenRef, valueHash,
            });
            // Drain any LRU evictions that the mint above triggered. Each one gets
            // its own audit line so /scrim:audit shows them. A later Write that
            // references an evicted token will fail-closed at the detokenize hook.
            for (const evicted of ctx.vault.drainEvicted()) {
                auditAppend(ctx.repoRoot, {
                    ruleId: "vault-evict", tool, action: "evict", tokenRef: evicted,
                    context: { reason: "lru-cap" },
                });
            }
            detections.push({ ruleId: span.ruleId, klass: span.class, action, tokenRef });
        }
        else if (action === "alert") {
            out += value;
            auditAppend(ctx.repoRoot, { ruleId: span.ruleId, tool, action: "alert", valueHash });
            detections.push({ ruleId: span.ruleId, klass: span.class, action });
        }
        else if (action === "block") {
            auditAppend(ctx.repoRoot, { ruleId: span.ruleId, tool, action: "block", valueHash });
            throw new BlockedError(span.ruleId, span.class);
        }
        else {
            // "allow" — pass through silently
            out += value;
        }
        cursor = span.end;
    }
    out += text.slice(cursor);
    return { output: out, detections };
}

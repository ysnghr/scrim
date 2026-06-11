// Secret detection: runs Gitleaks-style rules and emits spans pointing at the
// secret VALUE (not its surrounding key=) so the tokenizer replaces only the
// sensitive bytes. Drops matches whose value is in the allowlist or fails the
// rule's entropy threshold.
import { SECRET_RULES, shannonEntropy } from "./rules/secrets-rules.js";
import { IMPORTED_SECRET_RULES } from "./rules/gitleaks-imported-rules.js";
// Core rules first, then imported. Within the "secrets" class, merge picks the
// earlier+longer span on overlap (see spans.ts), so order = precedence. Each
// rule's regex is compiled once at module load and re-used across calls;
// `lastIndex` is reset explicitly at the start of every scan. Safe because
// Node runs scan() synchronously to completion.
const ALL_SECRET_RULES = [...SECRET_RULES, ...IMPORTED_SECRET_RULES].map((rule) => ({
    ...rule,
    re: new RegExp(rule.pattern.source, rule.pattern.flags),
}));
export function detectSecrets(text, allowlist) {
    const out = [];
    for (const rule of ALL_SECRET_RULES) {
        const re = rule.re;
        re.lastIndex = 0;
        let m;
        while ((m = re.exec(text)) !== null) {
            const value = m[1] ?? m[0];
            if (!value) {
                if (m.index === re.lastIndex)
                    re.lastIndex++;
                continue;
            }
            if (allowlist.has(value))
                continue;
            if (rule.entropy !== undefined && shannonEntropy(value) < rule.entropy)
                continue;
            // Locate the captured group (group 1) within the full match so we tokenize
            // only the value, not the leading key/quote.
            const fullStart = m.index;
            const valueStart = m[1] !== undefined ? text.indexOf(value, fullStart) : fullStart;
            if (valueStart < 0)
                continue;
            out.push({
                start: valueStart,
                end: valueStart + value.length,
                class: rule.class,
                ruleId: rule.id,
            });
            if (m.index === re.lastIndex)
                re.lastIndex++;
        }
    }
    return out;
}

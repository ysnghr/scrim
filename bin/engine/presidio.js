// Optional Microsoft Presidio bridge.
//
// Disabled by default in policy. When enabled, shells out to a local Presidio
// analyzer (`scrim-presidio` on PATH, or whatever policy.detection.presidio_command
// points to) over stdin/stdout and returns spans. Falls back to an empty list —
// never throws — because PII tiering is additive: missing Presidio just means
// coarser coverage, not a security failure. The fail-closed guarantee is
// enforced one level up, when the secrets/PII engines themselves error.
//
// Trust boundary: Presidio is an external Python process potentially fetched
// from PyPI. Scrim consumes only its span shape ({start, end, entity_type}) —
// the original text never leaves this process via Presidio output, only via
// Presidio input. A compromised sidecar can under-detect (return [] to leak
// PII) but cannot inject content into the agent's context because we throw
// away anything but well-formed numeric spans.
import { spawnSync } from "node:child_process";
const DEFAULT_TIMEOUT_MS = 5_000;
export function detectPresidio(text, opts) {
    if (!opts.enabled)
        return [];
    if (!text)
        return [];
    const cmd = opts.command ?? "scrim-presidio";
    const res = spawnSync(cmd, ["--stdin-json"], {
        input: JSON.stringify({ text }),
        timeout: opts.timeoutMs ?? DEFAULT_TIMEOUT_MS,
        encoding: "utf8",
        // Cap the output the sidecar is allowed to emit. We never read more than
        // a span list for the text we sent in; multiple MB of output here is a
        // sign the sidecar is misbehaving.
        maxBuffer: 4 * 1024 * 1024,
    });
    if (res.error || res.status !== 0 || !res.stdout)
        return [];
    let parsed;
    try {
        parsed = JSON.parse(res.stdout);
    }
    catch {
        return [];
    }
    if (!Array.isArray(parsed))
        return [];
    return parsed
        .filter((p) => Number.isFinite(p.start) && Number.isFinite(p.end) && p.end > p.start)
        .map((p) => ({
        start: p.start,
        end: p.end,
        class: mapEntityToClass(p.entity_type),
        ruleId: `presidio:${p.entity_type}`,
    }));
}
function mapEntityToClass(entity) {
    switch (entity) {
        case "PERSON":
        case "LOCATION":
        case "PHONE_NUMBER":
        case "EMAIL_ADDRESS":
        case "US_SSN":
        case "CREDIT_CARD":
            return "pii_customer";
        case "IP_ADDRESS":
        case "URL":
            return "pii_internal";
        default:
            return "pii_customer";
    }
}

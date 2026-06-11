// Detection engine entrypoint.
//
// Composes the enabled detection sources into a single `detect(text)` call.
// Output is a non-overlapping, sorted list of DetectionSpans the caller can
// hand to the vault for tokenization.
//
// Fail-closed: detectors that throw are caught and re-thrown here. The caller
// (MCP server) translates that into a rejected tool call rather than returning
// raw content. Presidio is the exception — it is opt-in and additive and only
// degrades coverage on failure (see presidio.ts).
import { detectSecrets } from "./secrets.js";
import { detectFastPii } from "./pii.js";
import { detectTuned, parseEnvKeys, globToHostRegex } from "./tuned.js";
import { detectPresidio } from "./presidio.js";
import { mergeSpans } from "./spans.js";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
// Build an EngineConfig from a parsed policy and the repo root.
// Reads .env.example-style files referenced by `tune.envKeysFrom`. Files that
// don't exist are skipped silently — they're hints, not requirements.
export function buildEngineConfig(input, repoRoot) {
    const envKeys = new Set();
    for (const rel of input.tune.envKeysFrom) {
        try {
            const content = readFileSync(resolve(repoRoot, rel), "utf8");
            for (const k of parseEnvKeys(content))
                envKeys.add(k);
        }
        catch {
            // missing file — ignore
        }
    }
    const internalDomainPatterns = input.tune.internalDomains.map(globToHostRegex);
    const customPatterns = input.tune.customPatterns.map((cp) => ({
        name: cp.name,
        regex: new RegExp(cp.regex, "g"),
        class: cp.class,
    }));
    return {
        gitleaks: input.detection.gitleaks,
        fastPiiRegex: input.detection.fastPiiRegex,
        presidio: input.detection.presidio,
        presidioCommand: input.presidioCommand,
        tuned: { envKeys, internalDomainPatterns, customPatterns },
        allowlist: new Set(input.allow),
    };
}
export function detect(text, cfg) {
    const spans = [];
    if (cfg.gitleaks)
        spans.push(...detectSecrets(text, cfg.allowlist));
    if (cfg.fastPiiRegex)
        spans.push(...detectFastPii(text, cfg.allowlist));
    spans.push(...detectTuned(text, cfg.tuned, cfg.allowlist));
    if (cfg.presidio) {
        spans.push(...detectPresidio(text, { enabled: true, command: cfg.presidioCommand }));
    }
    return mergeSpans(spans);
}

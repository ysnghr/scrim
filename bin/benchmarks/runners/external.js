// Adapters for external scanners (gitleaks, trufflehog, presidio).
//
// Each adapter:
//   1. Probes for the tool via `which`. If absent, returns
//      { available: false, detections: [], ... } and a one-line note.
//   2. Invokes the tool against the corpus directory.
//   3. Parses native output and translates it into our normalized Detection
//      schema (file relative to corpusDir; class normalized to the benchmark
//      taxonomy).
//
// Output translation is intentionally generous — we never want a competitor to
// score poorly just because we miscategorized its results. Where a tool emits
// vendor-specific class names (e.g. gitleaks "rule.id = stripe-access-token"),
// we collapse the family into "secrets" / "pii_*" and preserve the original id
// in `ruleId` for debugging.
import { spawnSync } from "node:child_process";
import { readFileSync, statSync } from "node:fs";
import { join, relative, isAbsolute } from "node:path";
function isInstalled(cmd) {
    const r = spawnSync("which", [cmd], { encoding: "utf8" });
    return r.status === 0 && r.stdout.trim().length > 0;
}
function totalBytes(files) {
    let n = 0;
    for (const f of files)
        n += statSync(f.absPath).size;
    return n;
}
function rel(corpusDir, p) {
    if (!p)
        return p;
    if (isAbsolute(p))
        return relative(corpusDir, p);
    // gitleaks reports paths relative to its scan root, which we set to corpusDir
    return p;
}
export function runGitleaks(opts) {
    if (!isInstalled("gitleaks")) {
        return { runner: "gitleaks", available: false, detections: [], durationMs: 0, bytesScanned: 0,
            notes: ["gitleaks not installed — skipped. install via `brew install gitleaks` or see https://github.com/gitleaks/gitleaks"] };
    }
    const reportPath = join(opts.corpusDir, ".gitleaks-report.json");
    const start = process.hrtime.bigint();
    const r = spawnSync("gitleaks", [
        "detect",
        "--source", opts.corpusDir,
        "--no-git",
        "--no-banner",
        "--report-format", "json",
        "--report-path", reportPath,
        "--exit-code", "0",
    ], { encoding: "utf8" });
    const end = process.hrtime.bigint();
    const detections = [];
    const notes = [];
    if (r.status !== 0 && r.status !== null) {
        notes.push(`gitleaks exited ${r.status}: ${r.stderr?.slice(0, 200) ?? ""}`);
    }
    try {
        const raw = readFileSync(reportPath, "utf8");
        const arr = JSON.parse(raw);
        for (const f of arr) {
            const file = rel(opts.corpusDir, f.File ?? "");
            const needle = f.Secret ?? f.Match;
            if (!needle || !file)
                continue;
            const text = safeRead(join(opts.corpusDir, file));
            if (text == null)
                continue;
            const idx = text.indexOf(needle);
            if (idx < 0)
                continue;
            detections.push({
                file, start: idx, end: idx + needle.length,
                class: normalizeGitleaksClass(f.RuleID ?? ""),
                ruleId: f.RuleID ?? "gitleaks-unknown",
                runner: "gitleaks",
            });
        }
    }
    catch (e) {
        notes.push(`failed to parse gitleaks report: ${e.message}`);
    }
    return {
        runner: "gitleaks",
        available: true,
        detections,
        durationMs: Number(end - start) / 1e6,
        bytesScanned: totalBytes(opts.files),
        notes,
    };
}
function normalizeGitleaksClass(ruleId) {
    // Gitleaks' rule IDs are dasherized provider names. Almost all are secrets.
    // It occasionally has PII rules (email, slack-webhook) — leave email as
    // pii_email; everything else falls under secrets.
    if (ruleId === "email" || ruleId === "generic-email")
        return "pii_email";
    return "secrets";
}
export function runTrufflehog(opts) {
    if (!isInstalled("trufflehog")) {
        return { runner: "trufflehog", available: false, detections: [], durationMs: 0, bytesScanned: 0,
            notes: ["trufflehog not installed — skipped. install via `brew install trufflehog`"] };
    }
    const start = process.hrtime.bigint();
    const r = spawnSync("trufflehog", [
        "filesystem", opts.corpusDir,
        "--json",
        "--no-verification",
    ], { encoding: "utf8", maxBuffer: 32 * 1024 * 1024 });
    const end = process.hrtime.bigint();
    const detections = [];
    const notes = [];
    for (const line of (r.stdout ?? "").split("\n")) {
        if (!line.trim())
            continue;
        let obj;
        try {
            obj = JSON.parse(line);
        }
        catch {
            continue;
        }
        const file = rel(opts.corpusDir, obj?.SourceMetadata?.Data?.Filesystem?.file ?? "");
        const raw = obj?.Raw;
        if (!file || !raw)
            continue;
        const text = safeRead(join(opts.corpusDir, file));
        if (text == null)
            continue;
        const idx = text.indexOf(raw);
        if (idx < 0)
            continue;
        detections.push({
            file, start: idx, end: idx + raw.length,
            class: "secrets",
            ruleId: obj?.DetectorName ?? "trufflehog-unknown",
            runner: "trufflehog",
        });
    }
    return {
        runner: "trufflehog",
        available: true,
        detections,
        durationMs: Number(end - start) / 1e6,
        bytesScanned: totalBytes(opts.files),
        notes,
    };
}
export function runPresidio(opts) {
    const cmd = opts.command ?? "presidio-analyze";
    if (!isInstalled(cmd.split(/\s+/)[0])) {
        return { runner: "presidio", available: false, detections: [], durationMs: 0, bytesScanned: 0,
            notes: [`${cmd} not installed — skipped. provide a wrapper that emits {file,start,end,entity_type,score} JSONL`] };
    }
    const detections = [];
    const notes = [];
    const start = process.hrtime.bigint();
    for (const f of opts.files) {
        const r = spawnSync(cmd, [f.absPath], { encoding: "utf8", maxBuffer: 8 * 1024 * 1024 });
        for (const line of (r.stdout ?? "").split("\n")) {
            if (!line.trim())
                continue;
            let obj;
            try {
                obj = JSON.parse(line);
            }
            catch {
                continue;
            }
            const s = Number(obj.start), e = Number(obj.end);
            if (!Number.isFinite(s) || !Number.isFinite(e))
                continue;
            detections.push({
                file: f.relPath,
                start: s, end: e,
                class: normalizePresidioEntity(String(obj.entity_type ?? "")),
                ruleId: `presidio-${obj.entity_type}`,
                runner: "presidio",
            });
        }
    }
    const end = process.hrtime.bigint();
    return {
        runner: "presidio",
        available: true,
        detections,
        durationMs: Number(end - start) / 1e6,
        bytesScanned: totalBytes(opts.files),
        notes,
    };
}
function normalizePresidioEntity(entity) {
    switch (entity) {
        case "EMAIL_ADDRESS": return "pii_email";
        case "US_SSN": return "pii_ssn";
        case "CREDIT_CARD": return "pii_card";
        case "PHONE_NUMBER": return "pii_phone";
        default: return "pii_customer";
    }
}
function safeRead(p) {
    try {
        return readFileSync(p, "utf8");
    }
    catch {
        return null;
    }
}

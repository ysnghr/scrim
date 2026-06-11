// Render benchmark results as benchmarks/summary.md.
//
// Sections:
//   1. Detection quality (P/R/F1) — per class, per runner
//   2. Lookalike FP rate, exact vs partial match
//   3. Performance: throughput MB/s, end-to-end ms
//   4. Notes (unavailable runners, parse warnings)
//
// Keep this dumb and stable so diffs across releases are readable.
function pct(x) {
    if (!Number.isFinite(x))
        return "—";
    return (x * 100).toFixed(1) + "%";
}
function num(x, digits = 1) {
    if (!Number.isFinite(x))
        return "—";
    return x.toFixed(digits);
}
function pad(s, n) {
    return s.length >= n ? s : s + " ".repeat(n - s.length);
}
function tableHeader(cols) {
    return "| " + cols.join(" | ") + " |\n| " + cols.map(() => "---").join(" | ") + " |";
}
function classRow(s) {
    return [
        String(s.klass),
        String(s.tp), String(s.fp), String(s.fn),
        pct(s.precision), pct(s.recall), pct(s.f1),
    ];
}
export function renderSummary(input) {
    const parts = [];
    parts.push(`# Scrim benchmark report`);
    parts.push("");
    parts.push(`Generated: ${input.generatedAt}`);
    parts.push(`Corpus: ${input.corpusFiles} files, ${input.corpusBytes} bytes, ` +
        `${input.labelsReal} real labels + ${input.labelsBenign} benign (placeholder/lookalike)`);
    parts.push("");
    parts.push(`## 1. Detection quality`);
    parts.push("");
    parts.push(tableHeader(["runner", "class", "TP", "FP", "FN", "precision", "recall", "F1"]));
    for (const s of input.scores) {
        if (!s.byClass.length)
            continue;
        for (const c of s.byClass) {
            parts.push("| " + [s.runner, ...classRow(c)].join(" | ") + " |");
        }
    }
    parts.push("");
    parts.push(`## 2. Span quality + lookalike resistance`);
    parts.push("");
    parts.push(tableHeader(["runner", "exact match", "partial match", "lookalike FP rate", "throughput MB/s"]));
    for (const s of input.scores) {
        parts.push("| " + [
            s.runner,
            pct(s.exactMatchRate),
            pct(s.partialMatchRate),
            pct(s.lookalikeFpRate),
            num(s.throughputMBs, 2),
        ].join(" | ") + " |");
    }
    parts.push("");
    if (input.perf) {
        parts.push(`## 3. Scrim performance`);
        parts.push("");
        parts.push(`- Throughput (detection-only): **${num(input.perf.throughputMBs, 2)} MB/s** on ${input.perf.totalBytes} bytes`);
        parts.push(`- Per-file latency: p50 **${num(input.perf.latencyP50Ms, 2)} ms**, p95 **${num(input.perf.latencyP95Ms, 2)} ms**, p99 **${num(input.perf.latencyP99Ms, 2)} ms** (${input.perf.runs} samples)`);
        parts.push(`- Vault tokenize() scaling: ${input.perf.vault.map(v => `${v.size} entries → ${num(v.avgUs, 1)} µs/op`).join(", ")}`);
        parts.push(`- Detokenize hook latency on a typical Write payload: **${num(input.perf.hookLatencyMs, 2)} ms**`);
        parts.push(`- Memory RSS for 10 MB scan: **${num(input.perf.rssMb10mb, 1)} MB**`);
        parts.push("");
    }
    if (input.survivability) {
        parts.push(`## 4. Agent-task survivability`);
        parts.push("");
        parts.push(`For each scenario we replay the read→edit→write loop under four configurations and check three properties:`);
        parts.push(`(a) task completed, (b) final file is byte-correct, (c) the agent's "context" never saw a raw secret.`);
        parts.push("");
        parts.push(tableHeader(["scenario", "config", "completed", "byte-correct", "no leak"]));
        for (const row of input.survivability.rows) {
            parts.push("| " + [
                row.scenario, row.config,
                row.completed ? "✓" : "✗",
                row.byteCorrect ? "✓" : "✗",
                row.noLeak ? "✓" : "✗",
            ].join(" | ") + " |");
        }
        parts.push("");
        parts.push(`Summary by config:`);
        for (const c of input.survivability.byConfig) {
            parts.push(`- **${c.config}**: ${c.allThree}/${c.total} scenarios pass all three properties`);
        }
        parts.push("");
    }
    parts.push(`## 5. Notes`);
    parts.push("");
    let anyNote = false;
    for (const s of input.scores) {
        for (const n of s.notes ?? []) {
            parts.push(`- _${s.runner}_: ${n}`);
            anyNote = true;
        }
    }
    if (!anyNote)
        parts.push("(none)");
    parts.push("");
    return parts.join("\n");
}

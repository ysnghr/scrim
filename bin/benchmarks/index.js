// Top-level benchmark driver.
//
// Usage:
//   node bin/benchmarks/index.js
//
// What it does:
//   1. Generates (or reuses) the labeled corpus under benchmarks/corpus/
//   2. Runs Scrim's detection engine + every available competitor against it
//   3. Scores each runner against the labels (precision/recall/F1, lookalike FP, span quality)
//   4. Runs Scrim performance microbenchmarks
//   5. Runs the agent-task survivability framework
//   6. Writes benchmarks/summary.md plus benchmarks/detections-<runner>.jsonl
//      so each result is reproducible and inspectable.
//
// Knobs (env vars):
//   SCRIM_BENCH_OUT       output dir (default: benchmarks)
//   SCRIM_BENCH_SEED      corpus seed (default: stable)
//   SCRIM_BENCH_SKIP_PERF=1     skip the perf section
//   SCRIM_BENCH_SKIP_SURVIV=1   skip the survivability section
//   SCRIM_BENCH_RUNNERS         comma list: scrim,gitleaks,trufflehog,presidio,naive
import { mkdirSync, writeFileSync } from "node:fs";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { generateCorpus } from "./corpus.js";
import { runScrim } from "./runners/scrim-runner.js";
import { runNaive } from "./runners/naive-runner.js";
import { runGitleaks, runTrufflehog, runPresidio } from "./runners/external.js";
import { scoreRunner } from "./score/score.js";
import { renderSummary } from "./score/summary.js";
import { runPerf } from "./perf.js";
import { runSurvivability } from "./survivability.js";
const __dirname = dirname(fileURLToPath(import.meta.url));
function repoRoot() {
    // bin/benchmarks/index.js → repo root is two levels up
    return resolve(__dirname, "..", "..");
}
export function runBench(opts = {}) {
    const root = repoRoot();
    const outDir = opts.outDir ?? join(root, "benchmarks");
    const corpusDir = join(outDir, "corpus");
    mkdirSync(outDir, { recursive: true });
    // 1. Corpus
    const corpus = generateCorpus({
        outDir: corpusDir,
        seed: opts.seed ?? 0xC0DECAFE,
        clean: true,
    });
    // 2. Runners
    const allRunnerNames = ["scrim", "gitleaks", "trufflehog", "presidio", "naive-regex"];
    const enabled = new Set(opts.runners?.length ? opts.runners : allRunnerNames);
    const files = corpus.files.map((f) => ({ relPath: f.relPath, absPath: f.absPath, bytes: f.bytes }));
    const results = [];
    if (enabled.has("scrim"))
        results.push(runScrim({ corpusDir, files }));
    if (enabled.has("gitleaks"))
        results.push(runGitleaks({ corpusDir, files }));
    if (enabled.has("trufflehog"))
        results.push(runTrufflehog({ corpusDir, files }));
    if (enabled.has("presidio"))
        results.push(runPresidio({ corpusDir, files }));
    if (enabled.has("naive-regex"))
        results.push(runNaive({ files }));
    for (const r of results) {
        writeDetections(outDir, r.runner, r.detections);
    }
    // 3. Score
    const scores = [];
    for (const r of results) {
        if (!r.available) {
            scores.push({
                runner: r.runner, byClass: [], lookalikeFpRate: 0, exactMatchRate: 0,
                partialMatchRate: 0, throughputMBs: 0, notes: r.notes ?? [`${r.runner} skipped (unavailable)`],
            });
            continue;
        }
        scores.push(scoreRunner(r, corpus.labels));
    }
    // 4. Perf (Scrim-only)
    const perf = opts.skipPerf ? undefined : runPerf({ corpusDir, files });
    // 5. Survivability
    const survivability = opts.skipSurvivability ? undefined : runSurvivability();
    // 6. Write summary
    const realLabels = corpus.labels.filter((l) => l.variant === "real").length;
    const benignLabels = corpus.labels.length - realLabels;
    const md = renderSummary({
        generatedAt: new Date().toISOString(),
        corpusFiles: corpus.files.length,
        corpusBytes: corpus.totalBytes,
        labelsReal: realLabels,
        labelsBenign: benignLabels,
        scores,
        perf,
        survivability,
    });
    const summaryPath = join(outDir, "summary.md");
    writeFileSync(summaryPath, md);
    return { summaryPath, scores, outDir };
}
function writeDetections(outDir, runner, dets) {
    const p = join(outDir, `detections-${runner}.jsonl`);
    writeFileSync(p, dets.map((d) => JSON.stringify(d)).join("\n") + (dets.length ? "\n" : ""));
}
// CLI entrypoint
if (import.meta.url === `file://${process.argv[1]}`) {
    const runners = process.env["SCRIM_BENCH_RUNNERS"]?.split(",").map((s) => s.trim()).filter(Boolean);
    const out = runBench({
        outDir: process.env["SCRIM_BENCH_OUT"],
        seed: process.env["SCRIM_BENCH_SEED"] ? Number(process.env["SCRIM_BENCH_SEED"]) : undefined,
        runners,
        skipPerf: process.env["SCRIM_BENCH_SKIP_PERF"] === "1",
        skipSurvivability: process.env["SCRIM_BENCH_SKIP_SURVIV"] === "1",
    });
    console.log(`benchmarks written to ${out.outDir}`);
    console.log(`summary: ${out.summaryPath}`);
    for (const s of out.scores) {
        const overall = s.byClass.find((c) => c.klass === "overall");
        const recall = overall ? (overall.recall * 100).toFixed(1) + "%" : "—";
        const prec = overall ? (overall.precision * 100).toFixed(1) + "%" : "—";
        console.log(`  ${s.runner.padEnd(14)} P=${prec.padStart(6)}  R=${recall.padStart(6)}  ` +
            `lookalikeFP=${(s.lookalikeFpRate * 100).toFixed(1)}%  ` +
            `MB/s=${s.throughputMBs.toFixed(2)}`);
    }
}

// Performance measurements for Scrim's hot paths.
//
// - throughput: how many MB/s the detector handles on the corpus
// - per-file latency: warmup, then N samples → p50/p95/p99
// - memory: scan a synthetic 10 MB blob and report process.memoryUsage().rss
// - vault tokenize() scaling: time per call as the vault grows
// - detokenize hook latency: pure-logic call on a typical Write payload

import { readFileSync, mkdtempSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { detect, buildEngineConfig } from "../engine/index.js";
import { defaultPolicy, toEngineInput } from "../policy/index.js";
import { openVault } from "../vault/index.js";
import { detokenize } from "../hooks/detokenize.js";

export interface PerfResult {
  totalBytes: number;
  throughputMBs: number;
  runs: number;
  latencyP50Ms: number;
  latencyP95Ms: number;
  latencyP99Ms: number;
  rssMb10mb: number;
  vault: { size: number; avgUs: number }[];
  hookLatencyMs: number;
}

function percentile(sorted: number[], p: number): number {
  if (sorted.length === 0) return 0;
  const idx = Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length));
  return sorted[idx]!;
}

export interface PerfOptions {
  corpusDir: string;
  files: { relPath: string; absPath: string; bytes: number }[];
  runs?: number;       // per-file repetitions (default 50)
}

export function runPerf(opts: PerfOptions): PerfResult {
  const engine = buildEngineConfig(toEngineInput(defaultPolicy()), opts.corpusDir);
  const runs = opts.runs ?? 50;

  // Pre-read into memory so we measure detect(), not the fs.
  const buffers = opts.files.map((f) => ({ ...f, text: readFileSync(f.absPath, "utf8") }));
  let totalBytes = 0;
  for (const b of buffers) totalBytes += Buffer.byteLength(b.text, "utf8");

  // Warmup pass — JIT and inline caches settle after a few hits.
  for (const b of buffers) detect(b.text, engine);

  // Throughput: one pass over the whole corpus, measured wall-clock.
  const tpStart = process.hrtime.bigint();
  for (const b of buffers) detect(b.text, engine);
  const tpEnd = process.hrtime.bigint();
  const tpSec = Number(tpEnd - tpStart) / 1e9;
  const throughputMBs = (totalBytes / (1024 * 1024)) / tpSec;

  // Per-file latency distribution.
  const samples: number[] = [];
  for (const b of buffers) {
    for (let i = 0; i < runs; i++) {
      const s = process.hrtime.bigint();
      detect(b.text, engine);
      const e = process.hrtime.bigint();
      samples.push(Number(e - s) / 1e6);
    }
  }
  samples.sort((a, b) => a - b);

  // Memory: build a synthetic 10 MB blob salted with a few real-shape secrets.
  const big = generateBlob(10 * 1024 * 1024);
  const baseRss = process.memoryUsage().rss;
  detect(big, engine);
  const peakRss = process.memoryUsage().rss;
  // Report the delta over baseline so a noisy parent process doesn't dominate.
  const rssMb10mb = Math.max(0, (peakRss - baseRss) / (1024 * 1024));

  // Vault scaling: spin up a vault and tokenize until size = N, measuring the
  // average µs/op over the last 100 inserts at each checkpoint.
  const vaultRoot = mkdtempSync(join(tmpdir(), "scrim-bench-vault-"));
  mkdirSync(join(vaultRoot, ".scrim", "vault"), { recursive: true });
  const v = openVault(vaultRoot, { maxEntries: 50_000 });
  const checkpoints = [100, 1_000, 10_000];
  const vault: PerfResult["vault"] = [];
  let n = 0;
  for (const target of checkpoints) {
    // grow to (target - 100), then measure the last 100 inserts.
    while (n < target - 100) {
      v.tokenize(`secret-value-${n}`, "secrets", "bench-rule");
      n++;
    }
    const start = process.hrtime.bigint();
    for (let i = 0; i < 100; i++) {
      v.tokenize(`secret-value-${n}`, "secrets", "bench-rule");
      n++;
    }
    const end = process.hrtime.bigint();
    vault.push({ size: target, avgUs: (Number(end - start) / 1e3) / 100 });
  }

  // Detokenize hook latency: a "typical" Write payload — 200 lines, 6 tokens.
  // We use the SAME vault we just populated so resolve() hits cache like
  // production.
  const tokens: string[] = [];
  for (let i = 0; i < 6; i++) tokens.push(v.tokenize(`hook-bench-${i}`, "secrets", "bench-rule"));
  const lines: string[] = [];
  for (let i = 0; i < 200; i++) {
    if (i % 33 === 0 && tokens.length > 0) {
      lines.push(`secret_${i} = "${tokens[i % tokens.length]}"`);
    } else {
      lines.push(`# config line ${i} placeholder`);
    }
  }
  const hookInput = {
    hook_event_name: "PreToolUse",
    tool_name: "Write",
    tool_input: { file_path: "/tmp/example", content: lines.join("\n") },
  };
  // Warm the hook path.
  for (let i = 0; i < 5; i++) detokenize(hookInput, v);
  const hookSamples: number[] = [];
  for (let i = 0; i < 100; i++) {
    const s = process.hrtime.bigint();
    detokenize(hookInput, v);
    const e = process.hrtime.bigint();
    hookSamples.push(Number(e - s) / 1e6);
  }
  hookSamples.sort((a, b) => a - b);
  const hookLatencyMs = percentile(hookSamples, 50);

  return {
    totalBytes,
    throughputMBs,
    runs: samples.length,
    latencyP50Ms: percentile(samples, 50),
    latencyP95Ms: percentile(samples, 95),
    latencyP99Ms: percentile(samples, 99),
    rssMb10mb,
    vault,
    hookLatencyMs,
  };
}

function generateBlob(targetBytes: number): string {
  const noise = "# noise line " + "x".repeat(96) + "\n";
  const buf: string[] = [];
  let n = 0;
  while (n < targetBytes) {
    buf.push(noise);
    n += noise.length;
    // sprinkle realistic-shape secrets every ~8 KB
    if (n % 8192 < noise.length) {
      buf.push("AWS_KEY=AKIA" + "ABCDEFGHIJKLMNOP".slice(0, 16) + "\n");
      buf.push("GH=ghp_" + "z".repeat(36) + "\n");
      n += 80;
    }
  }
  return buf.join("");
}

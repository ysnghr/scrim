// "Naive" baseline: a single high-entropy-ish regex with no entropy filter and
// no semantic awareness. Useful as a precision-floor competitor — if a tool
// can't beat this on precision, it isn't earning the complexity.

import { readFileSync } from "node:fs";
import type { Detection, RunnerResult } from "../types.js";

const NAIVE = /[A-Za-z0-9_\-+/=]{32,}/g;

export interface NaiveOptions {
  files: { relPath: string; absPath: string }[];
}

export function runNaive(opts: NaiveOptions): RunnerResult {
  const detections: Detection[] = [];
  let bytesScanned = 0;
  const start = process.hrtime.bigint();

  for (const f of opts.files) {
    const text = readFileSync(f.absPath, "utf8");
    bytesScanned += Buffer.byteLength(text, "utf8");
    NAIVE.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = NAIVE.exec(text)) !== null) {
      detections.push({
        file: f.relPath,
        start: m.index,
        end: m.index + m[0].length,
        class: "secrets",
        ruleId: "naive-32plus",
        runner: "naive-regex",
      });
    }
  }

  const end = process.hrtime.bigint();
  return {
    runner: "naive-regex",
    available: true,
    detections,
    durationMs: Number(end - start) / 1e6,
    bytesScanned,
  };
}

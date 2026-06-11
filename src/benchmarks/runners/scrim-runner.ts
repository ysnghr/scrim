// Run Scrim's detection engine over the corpus and emit normalized Detections.
//
// We deliberately call `detect()` from src/engine, not the full MCP pipeline.
// The MCP pipeline adds policy actions, vault, and audit — those don't affect
// detection quality, and skipping them lets us isolate the detector's
// precision/recall from policy/runtime concerns. Performance numbers from the
// detection-only path are also closer to apples-to-apples with the other
// tools, which are themselves pure detectors.

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { detect, buildEngineConfig, type EngineConfig } from "../../engine/index.js";
import { defaultPolicy, toEngineInput } from "../../policy/index.js";
import type { Detection, RunnerResult, CorpusClass } from "../types.js";

// Map Scrim's policy classes to the normalized benchmark classes. Scrim
// reports class="secrets" for all secret rules; we sharpen pii_customer into
// the per-type buckets by ruleId so the scorer can break PII metrics down.
const PII_RULE_TO_CLASS: Record<string, CorpusClass> = {
  "pii-email": "pii_email",
  "pii-ssn":   "pii_ssn",
  "pii-card":  "pii_card",
  "pii-phone": "pii_phone",
};

function normalizeClass(klass: string, ruleId: string): CorpusClass | string {
  if (klass === "secrets") return "secrets";
  if (klass === "internal_hostnames") return "internal_hostnames";
  if (klass === "pii_customer" || klass === "pii_internal") {
    return PII_RULE_TO_CLASS[ruleId] ?? "pii_customer";
  }
  return klass;
}

export interface ScrimRunOptions {
  corpusDir: string;
  files: { relPath: string; absPath: string }[];
  engine?: EngineConfig;
}

export function runScrim(opts: ScrimRunOptions): RunnerResult {
  const engine = opts.engine ?? buildEngineConfig(toEngineInput(defaultPolicy()), opts.corpusDir);
  const detections: Detection[] = [];
  let bytesScanned = 0;
  const start = process.hrtime.bigint();

  for (const f of opts.files) {
    const text = readFileSync(f.absPath, "utf8");
    bytesScanned += Buffer.byteLength(text, "utf8");
    const spans = detect(text, engine);
    for (const s of spans) {
      detections.push({
        file: f.relPath,
        start: s.start,
        end: s.end,
        class: normalizeClass(s.class, s.ruleId),
        ruleId: s.ruleId,
        runner: "scrim",
      });
    }
  }

  const end = process.hrtime.bigint();
  return {
    runner: "scrim",
    available: true,
    detections,
    durationMs: Number(end - start) / 1e6,
    bytesScanned,
  };
}

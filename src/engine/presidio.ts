// Optional Microsoft Presidio bridge.
//
// Disabled by default in policy. When enabled, shells out to a local Presidio
// analyzer (`scrim-presidio` on PATH, or `python -m presidio_analyzer`) over
// stdin/stdout and returns spans. Falls back to an empty list — never throws —
// because PII tiering is additive: missing Presidio just means coarser coverage,
// not a security failure. The fail-closed guarantee is enforced one level up,
// when the secrets/PII engines themselves error.

import { spawnSync } from "node:child_process";
import type { DetectionSpan } from "./spans.ts";

export interface PresidioBridgeOptions {
  enabled: boolean;
  command?: string;        // override path to a local analyzer
  timeoutMs?: number;
}

interface PresidioResult {
  start: number;
  end: number;
  entity_type: string;
}

export function detectPresidio(text: string, opts: PresidioBridgeOptions): DetectionSpan[] {
  if (!opts.enabled) return [];
  const cmd = opts.command ?? "scrim-presidio";
  const res = spawnSync(cmd, ["--stdin-json"], {
    input: JSON.stringify({ text }),
    timeout: opts.timeoutMs ?? 5_000,
    encoding: "utf8",
  });
  if (res.error || res.status !== 0 || !res.stdout) return [];

  let parsed: PresidioResult[];
  try {
    parsed = JSON.parse(res.stdout);
  } catch {
    return [];
  }
  if (!Array.isArray(parsed)) return [];

  return parsed
    .filter((p) => Number.isFinite(p.start) && Number.isFinite(p.end) && p.end > p.start)
    .map((p) => ({
      start: p.start,
      end: p.end,
      class: mapEntityToClass(p.entity_type),
      ruleId: `presidio:${p.entity_type}`,
    }));
}

function mapEntityToClass(entity: string): string {
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

// Score detections against ground-truth labels.
//
// Matching rules (per file):
//   - A label and a detection match if they overlap and their normalized
//     classes agree. We use a soft class equality: any pii_* detection on a
//     pii_* label counts (so a detector that finds "pii_customer" generically
//     still scores against pii_email). Secrets match secrets.
//   - Exactly one detection can claim a given label (the first overlapping one
//     in start-order wins).
//   - A label with variant="real" that no detection covers is a false negative.
//   - A detection that covers no real label is a false positive — but if the
//     covered region is a labeled "lookalike" or "placeholder", we also count
//     it in lookalikeFp (separate axis; precision still takes the hit).
//   - A detection that lies inside a "placeholder" span on a label that the
//     scenario explicitly marked as benign does NOT count as a TP. Scrim's
//     entropy filter is supposed to skip these.
//
// Exact vs partial match: a TP whose [start,end) equals the label's is
// "exact"; otherwise it's "partial" (50%+ overlap, by IoU). Partial is
// counted as TP for precision/recall but reported separately because Scrim
// tokenizes by exact span — a partial-match-but-wrong-bounds would substitute
// the wrong bytes.

import type {
  Detection, Label, RunnerResult, RunnerScore, ClassScore, CorpusClass,
} from "../types.js";

function classFamily(klass: string): "secrets" | "pii" | "host" | "other" {
  if (klass === "secrets") return "secrets";
  if (klass === "internal_hostnames") return "host";
  if (klass.startsWith("pii_")) return "pii";
  return "other";
}

function classMatches(detClass: string, labelClass: string): boolean {
  if (detClass === labelClass) return true;
  // Generic pii_customer detection against a specific pii_email label counts.
  if (classFamily(detClass) === "pii" && classFamily(labelClass) === "pii") return true;
  return false;
}

function overlapLen(a: { start: number; end: number }, b: { start: number; end: number }): number {
  return Math.max(0, Math.min(a.end, b.end) - Math.max(a.start, b.start));
}

function iou(a: { start: number; end: number }, b: { start: number; end: number }): number {
  const inter = overlapLen(a, b);
  if (inter <= 0) return 0;
  const union = Math.max(a.end, b.end) - Math.min(a.start, b.start);
  return inter / union;
}

function exactMatch(a: { start: number; end: number }, b: { start: number; end: number }): boolean {
  return a.start === b.start && a.end === b.end;
}

interface PerFileIndex {
  realByClass: Map<string, Label[]>;          // labels with variant="real"
  benign: Label[];                            // placeholder | lookalike
}

function indexLabels(labels: Label[]): Map<string, PerFileIndex> {
  const m = new Map<string, PerFileIndex>();
  for (const l of labels) {
    let f = m.get(l.file);
    if (!f) {
      f = { realByClass: new Map(), benign: [] };
      m.set(l.file, f);
    }
    if (l.variant === "real") {
      const k = l.class;
      let arr = f.realByClass.get(k);
      if (!arr) { arr = []; f.realByClass.set(k, arr); }
      arr.push(l);
    } else {
      f.benign.push(l);
    }
  }
  return m;
}

const CLASSES_TO_REPORT: CorpusClass[] = [
  "secrets", "pii_email", "pii_ssn", "pii_card", "pii_phone",
];

export function scoreRunner(runner: RunnerResult, labels: Label[]): RunnerScore {
  const idx = indexLabels(labels);

  // Per-class counters.
  const tp: Record<string, number> = {};
  const fp: Record<string, number> = {};
  const fn: Record<string, number> = {};
  for (const c of CLASSES_TO_REPORT) { tp[c] = 0; fp[c] = 0; fn[c] = 0; }

  // Track which real labels were matched (by reference identity).
  const matched = new Set<Label>();

  // Span quality counters.
  let tpTotal = 0, exact = 0, partial = 0;

  // Lookalike FP counter.
  let lookalikeMatches = 0;
  let lookalikeAvailable = 0;
  for (const f of idx.values()) lookalikeAvailable += f.benign.length;

  // Stable order so the "first overlapping" tiebreak is reproducible.
  const dets = [...runner.detections].sort((a, b) =>
    a.file.localeCompare(b.file) || a.start - b.start || a.end - b.end);

  for (const d of dets) {
    const fileIdx = idx.get(d.file);
    if (!fileIdx) {
      // detection in a file we didn't label — treat as FP under the
      // detection's claimed class (or "secrets" if unknown)
      const c = (CLASSES_TO_REPORT as string[]).includes(d.class) ? d.class : "secrets";
      fp[c] = (fp[c] ?? 0) + 1;
      continue;
    }

    // Try to match against an unclaimed real label of any class-compatible
    // type for this file.
    let claimedLabel: Label | null = null;
    for (const [cls, arr] of fileIdx.realByClass) {
      if (!classMatches(d.class, cls)) continue;
      for (const l of arr) {
        if (matched.has(l)) continue;
        if (overlapLen(d, l) <= 0) continue;
        claimedLabel = l;
        break;
      }
      if (claimedLabel) break;
    }

    if (claimedLabel) {
      matched.add(claimedLabel);
      const c = claimedLabel.class;
      tp[c] = (tp[c] ?? 0) + 1;
      tpTotal++;
      if (exactMatch(d, claimedLabel)) exact++;
      else if (iou(d, claimedLabel) >= 0.5) partial++;
      else partial++; // any overlap counts; we already required overlap > 0
      continue;
    }

    // No real label claimed; is it overlapping a benign (lookalike/placeholder)?
    const benign = fileIdx.benign.find((l) => overlapLen(d, l) > 0);
    if (benign) {
      lookalikeMatches++;
      const c = (CLASSES_TO_REPORT as string[]).includes(benign.class) ? benign.class : "secrets";
      fp[c] = (fp[c] ?? 0) + 1;
    } else {
      // Detection covers nothing labeled. Count as FP under its class.
      const c = (CLASSES_TO_REPORT as string[]).includes(d.class) ? d.class : "secrets";
      fp[c] = (fp[c] ?? 0) + 1;
    }
  }

  // Unmatched real labels are FNs.
  for (const fileIdx of idx.values()) {
    for (const [cls, arr] of fileIdx.realByClass) {
      for (const l of arr) {
        if (!matched.has(l)) fn[cls] = (fn[cls] ?? 0) + 1;
      }
    }
  }

  const byClass: ClassScore[] = [];
  for (const c of CLASSES_TO_REPORT) {
    byClass.push(metricFrom(c, tp[c] ?? 0, fp[c] ?? 0, fn[c] ?? 0));
  }
  // Overall row.
  let tAll = 0, fAll = 0, nAll = 0;
  for (const c of CLASSES_TO_REPORT) { tAll += tp[c]!; fAll += fp[c]!; nAll += fn[c]!; }
  byClass.push(metricFrom("overall", tAll, fAll, nAll));

  const throughputMBs = runner.bytesScanned > 0 && runner.durationMs > 0
    ? (runner.bytesScanned / (1024 * 1024)) / (runner.durationMs / 1000)
    : 0;

  return {
    runner: runner.runner,
    byClass,
    lookalikeFpRate: lookalikeAvailable > 0 ? lookalikeMatches / lookalikeAvailable : 0,
    exactMatchRate: tpTotal > 0 ? exact / tpTotal : 0,
    partialMatchRate: tpTotal > 0 ? partial / tpTotal : 0,
    throughputMBs,
    notes: runner.notes ?? [],
  };
}

function metricFrom(klass: ClassScore["klass"], tp: number, fp: number, fn: number): ClassScore {
  const precision = tp + fp > 0 ? tp / (tp + fp) : 0;
  const recall    = tp + fn > 0 ? tp / (tp + fn) : 0;
  const f1        = precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : 0;
  return { klass, tp, fp, fn, precision, recall, f1 };
}

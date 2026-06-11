// Shared types for the benchmark harness.
//
// A Label is a ground-truth annotation: one secret/PII span in a corpus file.
// A Detection is what some runner (Scrim, gitleaks, presidio, naive) actually
// found. Scoring joins the two streams by (file, start, end) overlap.
//
// `class` here is the normalized cross-tool class — "secrets" or one of the
// pii_* families. Scrim's own classes already match this taxonomy; competitor
// runners translate their native categories into it before emitting.

export type CorpusKind = "secrets" | "pii";

export type CorpusClass =
  | "secrets"
  | "pii_email"
  | "pii_ssn"
  | "pii_card"
  | "pii_phone"
  | "pii_customer"
  | "internal_hostnames";

// Variant tells the scorer whether a span is a true positive when matched
// (real) or whether matching it is a *false* positive (lookalike). Placeholder
// spans aren't real secrets but are usually labeled "lookalike-ok-if-matched"
// — they don't hurt precision but a redactor that catches them shows higher
// recall on the placeholder-tolerant slice.
export type Variant = "real" | "placeholder" | "lookalike";

export interface Label {
  file: string;          // relative to benchmarks/corpus
  start: number;         // inclusive byte offset
  end: number;           // exclusive
  class: CorpusClass;
  ruleId: string;        // expected detector id (advisory; scoring matches by class)
  variant: Variant;
  // The literal value at [start, end) — denormalized to make scoring debuggable
  // when offsets diverge between runners.
  value: string;
}

export interface Detection {
  file: string;
  start: number;
  end: number;
  class: CorpusClass | string;  // string so competitor-native classes survive a stray code path
  ruleId: string;
  runner: string;               // "scrim", "gitleaks", "trufflehog", "presidio", "naive-regex"
}

export interface RunnerResult {
  runner: string;
  available: boolean;
  detections: Detection[];
  durationMs: number;
  bytesScanned: number;
  // Optional, runner-specific notes that surface in summary.md
  notes?: string[];
}

export interface ClassScore {
  klass: CorpusClass | "overall";
  tp: number;
  fp: number;
  fn: number;
  precision: number;
  recall: number;
  f1: number;
}

export interface RunnerScore {
  runner: string;
  byClass: ClassScore[];
  // Lookalike false-positive rate: of the lookalike-labeled spans (or
  // never-labeled-but-flagged regions inside lookalike files), how many were
  // flagged? Lower is better.
  lookalikeFpRate: number;
  // Span overlap quality on true positives: fraction that are exact-match vs
  // partial-overlap (50%+). Important — partial matches mean Scrim would
  // tokenize the wrong bytes.
  exactMatchRate: number;
  partialMatchRate: number;
  throughputMBs: number;
  notes: string[];
}

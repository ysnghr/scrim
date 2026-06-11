// Shared types for the benchmark harness.
//
// A Label is a ground-truth annotation: one secret/PII span in a corpus file.
// A Detection is what some runner (Scrim, gitleaks, presidio, naive) actually
// found. Scoring joins the two streams by (file, start, end) overlap.
//
// `class` here is the normalized cross-tool class — "secrets" or one of the
// pii_* families. Scrim's own classes already match this taxonomy; competitor
// runners translate their native categories into it before emitting.
export {};

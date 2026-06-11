// Detection spans and merging.
//
// Each detector returns spans pointing into the original text. The orchestrator
// merges them so the tokenizer sees a non-overlapping list. When spans overlap,
// the higher-class-priority one wins (secrets > internal_hostnames > pii_*).
// Within the same class, an earlier span wins, and at the same start, the
// longer span wins. The class priority matters because PII regexes are loose
// by design — e.g. an email regex will happily match "password@host" inside a
// URL — and we never want a secret to lose to a coincidental PII match.

export interface DetectionSpan {
  start: number;
  end: number;        // exclusive
  class: string;      // policy class, e.g. "secrets", "pii_customer"
  ruleId: string;     // detector-specific identifier, for audit
}

const CLASS_PRIORITY: Record<string, number> = {
  secrets: 100,
  internal_hostnames: 80,
  pii_customer: 50,
  pii_internal: 30,
};

function priorityOf(klass: string): number {
  return CLASS_PRIORITY[klass] ?? 0;
}

export function mergeSpans(spans: DetectionSpan[]): DetectionSpan[] {
  if (spans.length <= 1) return spans.slice();
  // First pass: sort by start, then class priority desc, then length desc, and
  // sweep. But because higher-priority spans can be SHORTER and start LATER
  // than a coincidental lower-priority span, we instead build by priority tier:
  //   1. take all secrets, sweep them
  //   2. take internal_hostnames, only keep ones that don't overlap any kept span
  //   3. take pii_customer, same rule
  //   4. take pii_internal, same rule
  // This is O(n log n + n*k) where k is small (~4 tiers).
  const tiers = [...new Set(spans.map((s) => priorityOf(s.class)))].sort((a, b) => b - a);
  const kept: DetectionSpan[] = [];
  for (const tier of tiers) {
    const tierSpans = spans
      .filter((s) => priorityOf(s.class) === tier)
      .sort((a, b) => {
        if (a.start !== b.start) return a.start - b.start;
        return (b.end - b.start) - (a.end - a.start);
      });
    for (const span of tierSpans) {
      if (kept.some((k) => overlaps(k, span))) continue;
      kept.push(span);
    }
  }
  return kept.sort((a, b) => a.start - b.start);
}

function overlaps(a: DetectionSpan, b: DetectionSpan): boolean {
  return a.start < b.end && b.start < a.end;
}

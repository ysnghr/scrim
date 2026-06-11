// Detection spans and merging.
//
// Each detector returns spans pointing into the original text. The orchestrator
// merges them so the tokenizer sees a non-overlapping list: when two detectors
// flag overlapping ranges (e.g. "password assignment" + "AWS key"), the earlier
// span wins and ties go to the longer one. That ordering is stable and good
// enough; it avoids the trap of two tokens being placed inside the same value.
export function mergeSpans(spans) {
    if (spans.length <= 1)
        return spans.slice();
    const sorted = spans.slice().sort((a, b) => {
        if (a.start !== b.start)
            return a.start - b.start;
        return (b.end - b.start) - (a.end - a.start);
    });
    const out = [];
    let lastEnd = -1;
    for (const span of sorted) {
        if (span.start >= lastEnd) {
            out.push(span);
            lastEnd = span.end;
        }
    }
    return out;
}

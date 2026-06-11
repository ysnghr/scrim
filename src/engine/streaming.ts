// Streaming detection for files that exceed the in-memory cap.
//
// Reads the file in `chunkBytes`-sized windows with `overlapBytes` of overlap
// between them, runs the existing detect() pipeline on each chunk's text, and
// stitches the per-chunk spans into a single file-global span list.
//
// Why the overlap: a secret that straddles a chunk boundary would be split
// into two halves by a naive chunked scan and neither half would match.
// `overlapBytes` is the largest single-span length the streaming path
// guarantees it can detect. Spans returned by detect() that exceed that
// length are dropped (they're likely partial matches at the boundary and we
// can't tell whether the full secret continues outside the chunk). The
// whole-buffer path in safeRead still picks them up for files <= maxBytes.
//
// UTF-8 caveat: each chunk is decoded independently. A multi-byte sequence
// straddling a chunk boundary will be replaced with U+FFFD on both sides.
// For ASCII tokens (which every shipped secret rule is) this is harmless;
// for spans containing non-ASCII bytes the offset may shift by a few bytes
// at the boundary. We accept that — the streaming path is for "is there a
// secret in this 25 MB SQL dump" use cases, not byte-exact tokenization.

import { openSync, fstatSync, readSync, closeSync } from "node:fs";
import { detect, type EngineConfig } from "./index.js";
import { mergeSpans, type DetectionSpan } from "./spans.js";

export interface StreamingOptions {
  chunkBytes?: number;
  overlapBytes?: number;
}

export interface StreamingDetection {
  span: DetectionSpan;
  value: string;
  line: number;        // 1-indexed line number in the file where the span starts
}

export interface StreamingResult {
  fileSize: number;
  detections: StreamingDetection[];
}

const DEFAULT_CHUNK_BYTES = 1_048_576;   // 1 MB
const DEFAULT_OVERLAP_BYTES = 16_384;    // 16 KB — covers PEM blocks and JWTs

export function detectStreaming(
  filePath: string,
  cfg: EngineConfig,
  opts: StreamingOptions = {},
): StreamingResult {
  const chunkBytes = opts.chunkBytes ?? DEFAULT_CHUNK_BYTES;
  const overlapBytes = opts.overlapBytes ?? DEFAULT_OVERLAP_BYTES;
  if (overlapBytes >= chunkBytes) {
    throw new Error(`scrim: overlapBytes (${overlapBytes}) must be < chunkBytes (${chunkBytes})`);
  }

  const fd = openSync(filePath, "r");
  try {
    const stat = fstatSync(fd);
    const total = stat.size;
    if (total === 0) return { fileSize: 0, detections: [] };

    const buf = Buffer.alloc(chunkBytes);
    const advance = chunkBytes - overlapBytes;
    const collected: StreamingDetection[] = [];
    const seenKeys = new Set<string>();

    // Running line counter: how many `\n` we've passed at the start of the
    // current chunk. We can't decrement, so we only ever advance.
    let lineCountUpToChunkStart = 1;
    let lastChunkStartForLineCounting = 0;

    let offset = 0;
    while (offset < total) {
      const wantBytes = Math.min(chunkBytes, total - offset);
      const got = readSync(fd, buf, 0, wantBytes, offset);
      if (got === 0) break;
      const text = buf.subarray(0, got).toString("utf8");

      // Advance lineCountUpToChunkStart from the previous chunk's start to
      // this chunk's start, counting newlines in the gap. The gap is the
      // non-overlapping portion of the previous chunk.
      if (offset > lastChunkStartForLineCounting) {
        // Re-read just the gap bytes to count newlines. This is a re-read
        // but only of `advance` bytes per non-first chunk, and only counts
        // newlines (no decode required — \n is byte 0x0A in UTF-8).
        const gapStart = lastChunkStartForLineCounting;
        const gapEnd = offset;
        const gapLen = gapEnd - gapStart;
        const gapBuf = Buffer.alloc(gapLen);
        readSync(fd, gapBuf, 0, gapLen, gapStart);
        for (let i = 0; i < gapLen; i++) {
          if (gapBuf[i] === 0x0a) lineCountUpToChunkStart++;
        }
        lastChunkStartForLineCounting = offset;
      }

      const localSpans = detect(text, cfg);

      // Newline index within this chunk for fast line lookup. We build it
      // once per chunk rather than per span.
      const newlinePrefixCount = new Int32Array(text.length + 1);
      let running = 0;
      for (let i = 0; i < text.length; i++) {
        newlinePrefixCount[i] = running;
        if (text.charCodeAt(i) === 10) running++;
      }
      newlinePrefixCount[text.length] = running;

      for (const span of localSpans) {
        const spanLen = span.end - span.start;
        if (spanLen > overlapBytes) continue; // see file header

        const absStart = offset + span.start;
        const absEnd = offset + span.end;
        const key = `${absStart}:${absEnd}:${span.ruleId}`;
        if (seenKeys.has(key)) continue;
        seenKeys.add(key);

        const value = text.slice(span.start, span.end);
        const line = lineCountUpToChunkStart + (newlinePrefixCount[span.start] ?? 0);

        collected.push({
          span: { start: absStart, end: absEnd, class: span.class, ruleId: span.ruleId },
          value,
          line,
        });
      }

      if (got < chunkBytes) break;
      offset += advance;
    }

    // Final cross-chunk merge so tier priority still applies across the file.
    // mergeSpans gives us deduped, sorted spans; we re-attach values/lines.
    const byKey = new Map<string, StreamingDetection>();
    for (const d of collected) byKey.set(`${d.span.start}:${d.span.end}:${d.span.ruleId}`, d);
    const merged = mergeSpans(collected.map((d) => d.span));
    const result: StreamingDetection[] = [];
    for (const s of merged) {
      const hit = byKey.get(`${s.start}:${s.end}:${s.ruleId}`);
      if (hit) result.push(hit);
    }

    return { fileSize: total, detections: result };
  } finally {
    closeSync(fd);
  }
}

export { DEFAULT_CHUNK_BYTES, DEFAULT_OVERLAP_BYTES };

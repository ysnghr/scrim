// Streaming detection tests.
//
// The streaming path reads files in overlapping chunks. The boundary case —
// a secret that lands ON a chunk boundary — is the one the design is
// specifically built for, so we test it directly with synthesised offsets.
import { test } from "node:test";
import { strict as assert } from "node:assert";
import { writeFileSync, mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { detectStreaming } from "./streaming.js";
import { buildEngineConfig } from "./index.js";
function cfg() {
    return buildEngineConfig({
        detection: { gitleaks: true, fastPiiRegex: true, presidio: false },
        tune: { envKeysFrom: [], internalDomains: [], customPatterns: [] },
        allow: [],
    }, "/tmp/nonexistent");
}
function freshFile(content) {
    const dir = mkdtempSync(join(tmpdir(), "scrim-streaming-"));
    const path = join(dir, "fixture.txt");
    writeFileSync(path, content);
    return { path, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}
test("streaming: secret at file start", () => {
    const { path, cleanup } = freshFile("TOKEN=AKIAIOSFODNN7EXAMPL2\n" + "x".repeat(2_000_000));
    try {
        const { detections } = detectStreaming(path, cfg(), { chunkBytes: 524_288, overlapBytes: 4096 });
        const aws = detections.filter((d) => d.span.ruleId === "aws-access-key-id");
        assert.equal(aws.length, 1);
        assert.equal(aws[0].value, "AKIAIOSFODNN7EXAMPL2");
        assert.equal(aws[0].line, 1);
    }
    finally {
        cleanup();
    }
});
test("streaming: secret at end of file", () => {
    const { path, cleanup } = freshFile("x".repeat(2_000_000) + "\nTOKEN=AKIAIOSFODNN7EXAMPL2\n");
    try {
        const { detections } = detectStreaming(path, cfg(), { chunkBytes: 524_288, overlapBytes: 4096 });
        const aws = detections.filter((d) => d.span.ruleId === "aws-access-key-id");
        assert.equal(aws.length, 1);
        assert.equal(aws[0].value, "AKIAIOSFODNN7EXAMPL2");
        assert.equal(aws[0].line, 2); // padding is one big line ending in \n; secret is line 2
    }
    finally {
        cleanup();
    }
});
test("streaming: secret straddling a chunk boundary is still detected exactly once", () => {
    // Place the AWS key so its bytes straddle position 524_288 — the first
    // chunk boundary when chunkBytes=524_288. The 20-byte key starts 10 bytes
    // before the boundary so 10 bytes are in chunk 0 and 10 are in chunk 1's
    // non-overlap region.
    const chunkSize = 524_288;
    const key = "AKIAIOSFODNN7EXAMPL2";
    const headSize = chunkSize - 10;
    const head = "a".repeat(headSize);
    const tail = "z".repeat(50_000);
    const { path, cleanup } = freshFile(head + key + tail);
    try {
        const { detections } = detectStreaming(path, cfg(), { chunkBytes: chunkSize, overlapBytes: 4096 });
        const aws = detections.filter((d) => d.span.ruleId === "aws-access-key-id");
        assert.equal(aws.length, 1, "boundary-straddling secret must be detected exactly once");
        assert.equal(aws[0].value, key);
        assert.equal(aws[0].span.start, headSize);
        assert.equal(aws[0].span.end, headSize + key.length);
    }
    finally {
        cleanup();
    }
});
test("streaming: a secret in the overlap region is not duplicated", () => {
    // Position the key inside the overlap window so both chunks see it.
    // After dedup we should still get a single detection.
    const chunkSize = 524_288;
    const overlap = 16_384;
    const key = "AKIAIOSFODNN7EXAMPL2";
    // Place the key 4 KB before the boundary — well inside the overlap region.
    const before = chunkSize - 4096;
    const head = "a".repeat(before);
    const tail = "z".repeat(chunkSize); // ensure two chunks are read
    const { path, cleanup } = freshFile(head + key + tail);
    try {
        const { detections } = detectStreaming(path, cfg(), { chunkBytes: chunkSize, overlapBytes: overlap });
        const aws = detections.filter((d) => d.span.ruleId === "aws-access-key-id");
        assert.equal(aws.length, 1, "overlap-region secret must be deduped");
    }
    finally {
        cleanup();
    }
});
test("streaming: line numbers reflect file position", () => {
    // 5 lines of padding then the secret, then more padding.
    const lines = [];
    for (let i = 0; i < 5; i++)
        lines.push(`# line ${i + 1}`);
    lines.push("TOKEN=AKIAIOSFODNN7EXAMPL2");
    for (let i = 0; i < 5; i++)
        lines.push(`# trailing ${i}`);
    const content = lines.join("\n") + "\n";
    // Pad to force the streaming path
    const padded = content + "x".repeat(2_000_000);
    const { path, cleanup } = freshFile(padded);
    try {
        const { detections } = detectStreaming(path, cfg(), { chunkBytes: 524_288, overlapBytes: 4096 });
        const aws = detections.filter((d) => d.span.ruleId === "aws-access-key-id");
        assert.equal(aws.length, 1);
        assert.equal(aws[0].line, 6);
    }
    finally {
        cleanup();
    }
});
test("streaming: rejects overlap >= chunkBytes", () => {
    const { path, cleanup } = freshFile("hello");
    try {
        assert.throws(() => detectStreaming(path, cfg(), { chunkBytes: 1024, overlapBytes: 1024 }), /overlapBytes.*chunkBytes/);
    }
    finally {
        cleanup();
    }
});
test("streaming: empty file yields zero detections", () => {
    const { path, cleanup } = freshFile("");
    try {
        const { fileSize, detections } = detectStreaming(path, cfg());
        assert.equal(fileSize, 0);
        assert.equal(detections.length, 0);
    }
    finally {
        cleanup();
    }
});

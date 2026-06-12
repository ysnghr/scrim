// Presidio bridge tests against a mock sidecar binary.
//
// The real `scrim-presidio` is a Python process behind a bash shim. The
// contract Scrim depends on is its stdin/stdout JSON shape and its argv
// (--stdin-json). These tests use a tiny bash script as a stand-in so the
// contract is exercised end-to-end without a Python install.
import { test } from "node:test";
import { strict as assert } from "node:assert";
import { mkdtempSync, writeFileSync, chmodSync, rmSync, readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { detectPresidio } from "./presidio.js";
function tempMock(body) {
    const dir = mkdtempSync(join(tmpdir(), "scrim-presidio-mock-"));
    const path = join(dir, "scrim-presidio-mock");
    writeFileSync(path, body);
    chmodSync(path, 0o755);
    return { path, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}
test("presidio: returns [] when disabled (never spawns)", () => {
    const { path, cleanup } = tempMock(`#!/usr/bin/env bash\necho "SHOULD NOT EXECUTE" >&2; exit 1\n`);
    try {
        const spans = detectPresidio("alice@example.com", { enabled: false, command: path });
        assert.deepEqual(spans, []);
    }
    finally {
        cleanup();
    }
});
test("presidio: returns [] for empty text without spawning", () => {
    const { path, cleanup } = tempMock(`#!/usr/bin/env bash\ntouch "$1.spawned"; exit 0\n`);
    try {
        detectPresidio("", { enabled: true, command: path });
        // The mock would touch `<path>.spawned` if it were invoked. Empty text
        // is the short-circuit case — should not spawn.
        assert.equal(existsSync(`${path}.spawned`), false);
    }
    finally {
        cleanup();
    }
});
test("presidio: parses spans from a well-formed mock", () => {
    const canned = JSON.stringify([
        { start: 0, end: 5, entity_type: "PERSON" },
        { start: 10, end: 27, entity_type: "EMAIL_ADDRESS" },
    ]);
    // Mock echoes the canned JSON regardless of input. The text in the call
    // doesn't have to match the span offsets — we're testing the parsing
    // contract, not Presidio's own behaviour.
    const { path, cleanup } = tempMock(`#!/usr/bin/env bash\ncat >/dev/null; echo '${canned}'\n`);
    try {
        const spans = detectPresidio("Alice alice@example.com", { enabled: true, command: path });
        assert.equal(spans.length, 2);
        assert.equal(spans[0].ruleId, "presidio:PERSON");
        assert.equal(spans[0].class, "pii_customer");
        assert.equal(spans[1].ruleId, "presidio:EMAIL_ADDRESS");
        assert.equal(spans[1].start, 10);
        assert.equal(spans[1].end, 27);
    }
    finally {
        cleanup();
    }
});
test("presidio: passes --stdin-json as argv and full text on stdin", () => {
    // Mock writes argv + stdin to a side file, then emits an empty span list.
    const { path, cleanup } = tempMock(`#!/usr/bin/env bash\nset -e\n` +
        `echo "argv:$@" > "$0.audit"\n` +
        `cat >> "$0.audit"\n` +
        `echo "[]"\n`);
    try {
        detectPresidio("Bob bob@example.org", { enabled: true, command: path });
        const audit = readFileSync(`${path}.audit`, "utf8");
        assert.match(audit, /^argv:--stdin-json$/m, "expected --stdin-json on argv");
        assert.match(audit, /Bob bob@example\.org/, "expected text echoed on stdin");
    }
    finally {
        cleanup();
    }
});
test("presidio: returns [] on non-zero exit (fail-soft)", () => {
    const { path, cleanup } = tempMock(`#!/usr/bin/env bash\necho "[]"; exit 7\n`);
    try {
        const spans = detectPresidio("anything", { enabled: true, command: path });
        assert.deepEqual(spans, []);
    }
    finally {
        cleanup();
    }
});
test("presidio: returns [] on malformed JSON (fail-soft)", () => {
    const { path, cleanup } = tempMock(`#!/usr/bin/env bash\ncat >/dev/null; echo 'not json {{{'\n`);
    try {
        const spans = detectPresidio("anything", { enabled: true, command: path });
        assert.deepEqual(spans, []);
    }
    finally {
        cleanup();
    }
});
test("presidio: returns [] on non-array JSON (fail-soft)", () => {
    const { path, cleanup } = tempMock(`#!/usr/bin/env bash\ncat >/dev/null; echo '{"oops": true}'\n`);
    try {
        const spans = detectPresidio("anything", { enabled: true, command: path });
        assert.deepEqual(spans, []);
    }
    finally {
        cleanup();
    }
});
test("presidio: drops malformed span entries but keeps valid neighbours", () => {
    const mixed = JSON.stringify([
        { start: "no", end: 5, entity_type: "PERSON" }, // start NaN
        { start: 10, end: 5, entity_type: "PERSON" }, // end <= start
        { start: 20, end: 30, entity_type: "EMAIL_ADDRESS" }, // valid
    ]);
    const { path, cleanup } = tempMock(`#!/usr/bin/env bash\ncat >/dev/null; echo '${mixed}'\n`);
    try {
        const spans = detectPresidio("hello", { enabled: true, command: path });
        assert.equal(spans.length, 1);
        assert.equal(spans[0].ruleId, "presidio:EMAIL_ADDRESS");
    }
    finally {
        cleanup();
    }
});
test("presidio: times out cleanly when sidecar hangs (fail-soft)", () => {
    // Mock sleeps longer than the timeout. detectPresidio should kill it
    // and return [], not throw.
    const { path, cleanup } = tempMock(`#!/usr/bin/env bash\nsleep 5; echo '[]'\n`);
    try {
        const spans = detectPresidio("anything", { enabled: true, command: path, timeoutMs: 200 });
        assert.deepEqual(spans, []);
    }
    finally {
        cleanup();
    }
});
test("presidio: maps IP_ADDRESS / URL to pii_internal, others to pii_customer", () => {
    const mixed = JSON.stringify([
        { start: 0, end: 4, entity_type: "PERSON" },
        { start: 5, end: 14, entity_type: "IP_ADDRESS" },
        { start: 15, end: 25, entity_type: "URL" },
        { start: 26, end: 36, entity_type: "PHONE_NUMBER" },
        { start: 37, end: 50, entity_type: "EMAIL_ADDRESS" },
        { start: 51, end: 60, entity_type: "US_SSN" },
        { start: 61, end: 70, entity_type: "CREDIT_CARD" },
        { start: 71, end: 80, entity_type: "MADE_UP_ENTITY" },
    ]);
    const { path, cleanup } = tempMock(`#!/usr/bin/env bash\ncat >/dev/null; echo '${mixed}'\n`);
    try {
        const spans = detectPresidio("x".repeat(80), { enabled: true, command: path });
        const internal = spans.filter((s) => s.class === "pii_internal").map((s) => s.ruleId);
        const customer = spans.filter((s) => s.class === "pii_customer").map((s) => s.ruleId);
        assert.deepEqual(internal.sort(), ["presidio:IP_ADDRESS", "presidio:URL"].sort());
        // Unknown entities default to pii_customer per mapEntityToClass.
        assert.ok(customer.includes("presidio:MADE_UP_ENTITY"));
        assert.equal(spans.length, 8);
    }
    finally {
        cleanup();
    }
});

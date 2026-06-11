// Append-only audit log at .scrim/audit/detections.jsonl.
// Records: timestamp, rule id, tool name, action (redact|block|alert), token reference/hash.
// Never the raw value. Value-free by design.
export function append(_root, _entry) {
    throw new Error("audit.append: not implemented yet");
}
export function tail(_root, _n) {
    throw new Error("audit.tail: not implemented yet");
}

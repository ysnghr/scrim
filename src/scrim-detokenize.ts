// PreToolUse hook for Write|Edit|MultiEdit.
// Reads the hook payload from stdin, replaces ⟦scrim:class:id⟧ tokens in tool_input
// with real values from the session vault, and writes the rewritten payload back.
// Fail-closed: if any token cannot be resolved, exit with a non-zero status so the write is blocked.

throw new Error("scrim-detokenize: not implemented yet");

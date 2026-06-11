// PreToolUse hook for Bash.
// Inspects the command; if it matches a risky pattern (env, printenv, kubectl get secret,
// docker inspect, git remote -v, anything that emits connection strings), either:
//   - rewrite tool_input to route through safe_shell, or
//   - reject with a hint to use safe_shell.
// Otherwise pass through.

throw new Error("scrim-bash-guard: not implemented yet");

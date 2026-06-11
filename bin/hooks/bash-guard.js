// Pure logic for the PreToolUse Bash hook.
//
// Looks at the command string and either:
//   - allows it (most commands)
//   - denies it with a hint to use safe_shell (when the command's output is
//     known to dump credentials or PII)
//
// We don't try to be clever about rewriting input into a safe_shell invocation
// because the agent talks to safe_shell via MCP, not via Bash — there is no
// in-place rewrite that would still go through Scrim's redaction. A clear
// denial with an actionable reason is the right UX.
// Anchored where the dangerous fragment actually appears in the command line.
// We test against the *whole* command including pipes/chains, since a risky
// sub-command is still risky.
const RISKY = [
    {
        id: "env-dump",
        re: /(?:^|[\s;&|`(])env(?:\s|$|\||;|&|`|\))/,
        why: "`env` dumps every environment variable, which routinely includes credentials",
    },
    {
        id: "printenv",
        re: /(?:^|[\s;&|`(])printenv\b/,
        why: "`printenv` prints environment variables, which routinely include credentials",
    },
    {
        id: "kubectl-secret",
        re: /kubectl\s+(?:get|describe|edit|view)\s+secret/i,
        why: "kubectl can return decoded secrets in stdout",
    },
    {
        id: "docker-inspect",
        re: /docker\s+inspect\b/i,
        why: "`docker inspect` includes environment variables and bind mounts",
    },
    {
        id: "docker-compose-config",
        re: /docker[- ]compose\s+config\b/i,
        why: "`docker compose config` prints the resolved environment, including secrets",
    },
    {
        id: "git-remote-v",
        re: /git\s+remote\s+(?:-v|--verbose|show)\b/i,
        why: "remote URLs can contain embedded credentials (https://user:token@host)",
    },
    {
        id: "aws-configure",
        re: /aws\s+configure\b/i,
        why: "`aws configure` reads/writes credentials at ~/.aws/credentials",
    },
    {
        id: "gcloud-print-token",
        re: /gcloud\s+auth\s+(?:print-access-token|print-identity-token)/i,
        why: "this command prints a bearer token directly to stdout",
    },
];
export function decideBash(input) {
    const command = input.tool_input?.command ?? "";
    if (!command) {
        return {
            output: { hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "allow" } },
        };
    }
    for (const rule of RISKY) {
        if (rule.re.test(command)) {
            return {
                output: {
                    hookSpecificOutput: {
                        hookEventName: "PreToolUse",
                        permissionDecision: "deny",
                        permissionDecisionReason: `scrim: ${rule.why}. Use scrim's safe_shell tool instead — it runs the same` +
                            ` command but redacts secrets and PII from the output before the model sees it.`,
                    },
                },
                matched: { id: rule.id, why: rule.why },
            };
        }
    }
    return {
        output: { hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "allow" } },
    };
}

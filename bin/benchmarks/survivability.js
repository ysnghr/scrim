// Agent-task survivability — the unique-to-Scrim axis.
//
// For each scenario we have:
//   - an original file containing one or more real secrets
//   - a deterministic, scripted "edit" the agent would perform (e.g. "add a
//     port field", "change the region")
//   - an oracle final file we expect on disk after the edit
//
// We simulate the agent under FOUR redactor configs:
//
//   scrim:           ingress tokenizes secret → agent reads token → agent
//                    performs scripted edit on TOKENIZED text → detokenize
//                    hook restores tokens → bytes written.
//   redact-only:     ingress replaces secret with the literal "[REDACTED]" →
//                    agent edits the redacted text → bytes written. (Common
//                    naive approach: file gets corrupted because [REDACTED]
//                    overwrites the real secret on save.)
//   no-redactor:     agent reads raw file → edits → writes. File stays
//                    correct, BUT the secret entered "context" (we flag it).
//   permission-only: read is denied → agent can't perform the task. The file
//                    stays correct but the task FAILS.
//
// "Agent saw a secret" means: did the text the agent operated on contain the
// raw secret value? Tokens like ⟦scrim:aws:abc⟧ and "[REDACTED]" both count
// as "didn't see". This is what defines the unique axis.
import { mkdtempSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { detect, buildEngineConfig } from "../engine/index.js";
import { defaultPolicy, toEngineInput } from "../policy/index.js";
import { openVault } from "../vault/index.js";
import { detokenize } from "../hooks/detokenize.js";
import { processText } from "../mcp/process.js";
import { loadPolicy } from "../policy/index.js";
// --- scenarios ---
//
// Each one is a realistic "edit the config" task. The edit() function is
// deliberately written so it ALSO works on a tokenized file (it doesn't touch
// the line carrying the secret) — that's the whole point of Scrim. The naive
// "redact-only" config will corrupt the file because [REDACTED] replaces the
// real secret and is then written back verbatim.
const SCENARIOS = [
    (() => {
        const original = `# production config
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7AAAAAAA
GITHUB_TOKEN=ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
AWS_REGION=us-east-1
LOG_LEVEL=info
`;
        const expected = `# production config
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7AAAAAAA
GITHUB_TOKEN=ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
AWS_REGION=us-east-1
LOG_LEVEL=info
PORT=8080
`;
        return {
            name: "add port field to .env",
            originalContent: original,
            // Both AKIA and ghp_ are caught by specific scrim rules, so they're
            // the right secrets to test "did the agent see them" against.
            edit: (text) => text.endsWith("\n") ? text + "PORT=8080\n" : text + "\nPORT=8080\n",
            expectedAfterEdit: expected,
            rawSecrets: ["AKIAIOSFODNN7AAAAAAA", "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
        };
    })(),
    (() => {
        const original = `environment    = "production"
aws_access_key = "AKIAQQQQQQQQQQQQQQQQ"
aws_region     = "us-east-1"
`;
        const expected = `environment    = "production"
aws_access_key = "AKIAQQQQQQQQQQQQQQQQ"
aws_region     = "eu-west-1"
`;
        return {
            name: "change region in tfvars",
            originalContent: original,
            edit: (text) => text.replace('aws_region     = "us-east-1"', 'aws_region     = "eu-west-1"'),
            expectedAfterEdit: expected,
            rawSecrets: ["AKIAQQQQQQQQQQQQQQQQ"],
        };
    })(),
    (() => {
        // A refactor task that does not touch the secret-carrying line. The edit
        // is a regex rename that's safe to apply over tokenized text.
        const original = `function getConnection() {
  const conn = "postgres://app:supersecretpw99@db.prod/app";
  return conn;
}
getConnection();
`;
        const expected = `function openConnection() {
  const conn = "postgres://app:supersecretpw99@db.prod/app";
  return conn;
}
openConnection();
`;
        return {
            name: "refactor function name",
            originalContent: original,
            edit: (text) => text.replace(/getConnection/g, "openConnection"),
            expectedAfterEdit: expected,
            rawSecrets: ["supersecretpw99"],
        };
    })(),
];
// --- runner ---
function freshRepo() {
    const dir = mkdtempSync(join(tmpdir(), "scrim-surviv-"));
    mkdirSync(join(dir, ".scrim"), { recursive: true });
    return dir;
}
function containsAny(text, needles) {
    for (const n of needles)
        if (n && text.includes(n))
            return true;
    return false;
}
function runOne(scenario, config) {
    const repo = freshRepo();
    const filePath = join(repo, "target.txt");
    writeFileSync(filePath, scenario.originalContent);
    const row = { scenario: scenario.name, config, completed: false, byteCorrect: false, noLeak: false };
    try {
        if (config === "permission-only") {
            // Read is denied. Agent has nothing to edit; task fails.
            row.completed = false;
            row.byteCorrect = readFileSync(filePath, "utf8") === scenario.originalContent;
            row.noLeak = true;
            row.reason = "read denied";
            return row;
        }
        if (config === "no-redactor") {
            const text = readFileSync(filePath, "utf8");
            row.noLeak = !containsAny(text, scenario.rawSecrets);
            const edited = scenario.edit(text);
            writeFileSync(filePath, edited);
            row.completed = true;
            row.byteCorrect = readFileSync(filePath, "utf8") === scenario.expectedAfterEdit;
            return row;
        }
        if (config === "redact-only") {
            // Replace every detected secret with the literal "[REDACTED]". The agent
            // edits THAT, then writes — secret bytes are lost.
            const engine = buildEngineConfig(toEngineInput(defaultPolicy()), repo);
            const raw = readFileSync(filePath, "utf8");
            const spans = detect(raw, engine).sort((a, b) => b.start - a.start);
            let masked = raw;
            for (const s of spans) {
                masked = masked.slice(0, s.start) + "[REDACTED]" + masked.slice(s.end);
            }
            row.noLeak = !containsAny(masked, scenario.rawSecrets);
            const edited = scenario.edit(masked);
            writeFileSync(filePath, edited);
            row.completed = true;
            row.byteCorrect = readFileSync(filePath, "utf8") === scenario.expectedAfterEdit;
            return row;
        }
        // config === "scrim"
        // Build the same context the MCP server would, run the file through
        // processText, edit the tokenized text, then run the detokenize hook
        // (with a Write payload) and check what hits disk.
        writeFileSync(join(repo, ".scrim", "policy.yml"), "version: 1\n");
        const ctx = {
            repoRoot: repo,
            policy: loadPolicy(repo),
            engine: buildEngineConfig(toEngineInput(defaultPolicy()), repo),
            vault: openVault(repo, { maxEntries: 1000 }),
        };
        const raw = readFileSync(filePath, "utf8");
        const { output: tokenized } = processText(raw, "safe_read", ctx);
        row.noLeak = !containsAny(tokenized, scenario.rawSecrets);
        const edited = scenario.edit(tokenized);
        // The detokenize hook sees the Write tool_input and resolves tokens.
        const { output: hookOut } = detokenize({
            hook_event_name: "PreToolUse",
            tool_name: "Write",
            tool_input: { file_path: filePath, content: edited },
        }, ctx.vault);
        const decision = hookOut.hookSpecificOutput.permissionDecision;
        if (decision === "deny") {
            row.completed = false;
            row.reason = hookOut.hookSpecificOutput.permissionDecisionReason ?? "hook denied";
            return row;
        }
        // Allow path. If updatedInput was supplied, use that — otherwise the
        // edited text passed through with no tokens.
        const finalText = (hookOut.hookSpecificOutput.updatedInput?.content ?? edited);
        writeFileSync(filePath, finalText);
        row.completed = true;
        row.byteCorrect = readFileSync(filePath, "utf8") === scenario.expectedAfterEdit;
        return row;
    }
    catch (e) {
        row.reason = e.message;
        return row;
    }
}
export function runSurvivability() {
    const rows = [];
    const configs = ["scrim", "redact-only", "no-redactor", "permission-only"];
    for (const s of SCENARIOS) {
        for (const c of configs)
            rows.push(runOne(s, c));
    }
    const byConfig = configs.map((c) => {
        const subset = rows.filter((r) => r.config === c);
        const allThree = subset.filter((r) => r.completed && r.byteCorrect && r.noLeak).length;
        return { config: c, total: subset.length, allThree };
    });
    return { rows, byConfig };
}

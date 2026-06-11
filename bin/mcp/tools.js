// MCP tool handlers for the Scrim server.
//
// Each ingress tool reads from disk or executes a command, then runs the result
// through processText() before returning. The hooks (Write/Edit detokenize and
// Bash guard) are NOT registered here — they live as separate executables under
// bin/ because Claude Code spawns hook commands as standalone processes.
import { readFileSync, statSync, readdirSync, existsSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { join, relative, resolve, isAbsolute } from "node:path";
import { processText, BlockedError } from "./process.js";
import { summary as auditSummary, tail as auditTail } from "../audit/index.js";
// Heuristic binary check: presence of a null byte in the first 8 KiB.
function looksBinary(buf) {
    const slice = buf.subarray(0, Math.min(buf.length, 8192));
    for (let i = 0; i < slice.length; i++)
        if (slice[i] === 0)
            return true;
    return false;
}
function resolveAgainst(root, p) {
    return isAbsolute(p) ? p : resolve(root, p);
}
export function safeRead(args, ctx) {
    const target = resolveAgainst(ctx.repoRoot, args.path);
    const maxBytes = args.maxBytes ?? 2_000_000;
    const stat = statSync(target);
    if (stat.size > maxBytes) {
        throw new Error(`scrim: ${args.path} exceeds maxBytes (${stat.size} > ${maxBytes})`);
    }
    const buf = readFileSync(target);
    if (looksBinary(buf)) {
        throw new Error(`scrim: ${args.path} appears to be binary; refusing to redact`);
    }
    const text = buf.toString("utf8");
    try {
        const { output, detections } = processText(text, "safe_read", ctx);
        return {
            path: relative(ctx.repoRoot, target) || args.path,
            bytes: buf.length,
            detections: detections.length,
            content: output,
        };
    }
    catch (err) {
        if (err instanceof BlockedError) {
            return {
                path: relative(ctx.repoRoot, target) || args.path,
                bytes: buf.length,
                detections: 0,
                content: "",
                blocked: { ruleId: err.ruleId, class: err.klass },
            };
        }
        throw err;
    }
}
// Skip these directories during recursive search — they're never interesting
// and tend to be huge.
const GREP_SKIP = new Set([".git", "node_modules", ".scrim", "dist", "build", "bin"]);
function walkFiles(root, out) {
    let entries;
    try {
        entries = readdirSync(root, { withFileTypes: true });
    }
    catch {
        return;
    }
    for (const e of entries) {
        if (e.name.startsWith(".") && GREP_SKIP.has(e.name))
            continue;
        if (GREP_SKIP.has(e.name))
            continue;
        const p = join(root, e.name);
        if (e.isDirectory())
            walkFiles(p, out);
        else if (e.isFile())
            out.push(p);
    }
}
export function safeGrep(args, ctx) {
    const re = new RegExp(args.pattern, (args.flags ?? "") + (args.flags?.includes("g") ? "" : "g"));
    const start = resolveAgainst(ctx.repoRoot, args.path ?? ".");
    const maxMatches = args.maxMatches ?? 200;
    const stat = statSync(start);
    const files = [];
    if (stat.isDirectory())
        walkFiles(start, files);
    else
        files.push(start);
    const matches = [];
    let truncated = false;
    for (const file of files) {
        let buf;
        try {
            buf = readFileSync(file);
        }
        catch {
            continue;
        }
        if (looksBinary(buf))
            continue;
        const lines = buf.toString("utf8").split(/\r?\n/);
        for (let i = 0; i < lines.length; i++) {
            const line = lines[i] ?? "";
            if (!re.test(line)) {
                re.lastIndex = 0;
                continue;
            }
            re.lastIndex = 0;
            try {
                const { output } = processText(line, "safe_grep", ctx);
                matches.push({ path: relative(ctx.repoRoot, file) || file, line: i + 1, text: output });
            }
            catch (err) {
                if (err instanceof BlockedError) {
                    matches.push({
                        path: relative(ctx.repoRoot, file) || file,
                        line: i + 1,
                        text: `[scrim: blocked by ${err.ruleId}]`,
                    });
                }
                else {
                    throw err;
                }
            }
            if (matches.length >= maxMatches) {
                truncated = true;
                return { matches, truncated };
            }
        }
    }
    return { matches, truncated };
}
export function safeShell(args, ctx) {
    const cwd = args.cwd ? resolveAgainst(ctx.repoRoot, args.cwd) : ctx.repoRoot;
    const res = spawnSync(args.command, {
        shell: true,
        cwd,
        timeout: args.timeoutMs ?? 30_000,
        encoding: "utf8",
        maxBuffer: 8 * 1024 * 1024,
    });
    const rawStdout = res.stdout ?? "";
    const rawStderr = res.stderr ?? "";
    try {
        const out = processText(rawStdout, "safe_shell", ctx);
        const err = processText(rawStderr, "safe_shell", ctx);
        return {
            stdout: out.output,
            stderr: err.output,
            exitCode: res.status,
            signal: res.signal ? String(res.signal) : null,
            detections: out.detections.length + err.detections.length,
        };
    }
    catch (e) {
        if (e instanceof BlockedError) {
            return {
                stdout: "", stderr: "",
                exitCode: res.status, signal: res.signal ? String(res.signal) : null,
                detections: 0,
                blocked: { ruleId: e.ruleId, class: e.klass },
            };
        }
        throw e;
    }
}
export function scrimStatus(ctx) {
    const sum = auditSummary(ctx.repoRoot);
    const recent = auditTail(ctx.repoRoot, 5);
    const pluginRoot = process.env["SCRIM_PLUGIN_ROOT"] ?? "";
    const detokenizePath = pluginRoot ? join(pluginRoot, "bin", "scrim-detokenize.js") : "";
    const bashGuardPath = pluginRoot ? join(pluginRoot, "bin", "scrim-bash-guard.js") : "";
    return {
        policy: {
            version: ctx.policy.version,
            failClosed: ctx.policy.failClosed,
            detection: ctx.policy.detection,
            actions: ctx.policy.actions,
            repoTuning: {
                envKeys: ctx.engine.tuned.envKeys.size,
                internalDomains: ctx.engine.tuned.internalDomainPatterns.length,
                customPatterns: ctx.engine.tuned.customPatterns.length,
            },
        },
        vault: ctx.vault.stats(),
        audit: { total: sum.total, byAction: sum.byAction, recent },
        hooks: {
            detokenize: { expectedPath: detokenizePath, present: detokenizePath ? existsSync(detokenizePath) : false },
            bashGuard: { expectedPath: bashGuardPath, present: bashGuardPath ? existsSync(bashGuardPath) : false },
        },
    };
}

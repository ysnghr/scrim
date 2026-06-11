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
import { append as auditAppend, hashValue, summary as auditSummary, tail as auditTail } from "../audit/index.js";
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
export function safeWriteToken(args, ctx) {
    const { previousValueHash: priorFullHash } = ctx.vault.updateValue(args.token, args.newValue);
    // Compress the full hex hash from the vault (raw sha256) down to the salted
    // 12-char audit hash for consistency with the rest of the log.
    const auditedPriorHash = priorFullHash.slice(0, 12);
    auditAppend(ctx.repoRoot, {
        ruleId: "safe-write-token",
        tool: "safe_write_token",
        action: "rewrite",
        tokenRef: args.token,
        valueHash: hashValue(ctx.repoRoot, args.newValue),
        context: { previousValueHash: auditedPriorHash },
    });
    return { token: args.token, previousValueHash: auditedPriorHash };
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
// ---------------- scrim_doctor ----------------
// The deny-list a project's .claude/settings.json should carry so the agent is
// actually routed through Scrim's safe_* tools. Each entry is matched verbatim
// against the user's permissions.deny[] array. Keep in sync with
// scripts/install-deny-rules.sh.
export const REQUIRED_DENY_RULES = [
    "Read(./.env*)",
    "Read(**/*.pem)",
    "Read(**/secrets/**)",
    "Bash(env)",
    "Bash(printenv*)",
    "Bash(*kubectl get secret*)",
];
function readDenyList(repoRoot) {
    const p = join(repoRoot, ".claude", "settings.json");
    if (!existsSync(p))
        return { source: p, deny: null };
    try {
        const raw = readFileSync(p, "utf8");
        const parsed = JSON.parse(raw);
        const deny = parsed.permissions?.deny;
        if (!Array.isArray(deny))
            return { source: p, deny: [] };
        return { source: p, deny: deny.filter((x) => typeof x === "string") };
    }
    catch {
        return { source: p, deny: null };
    }
}
function checkDenyRules(repoRoot) {
    const { source, deny } = readDenyList(repoRoot);
    if (deny === null) {
        return {
            name: "deny-rules-present",
            status: "fail",
            detail: `${source} missing or unparseable. Run scripts/install-deny-rules.sh to add Scrim's recommended deny list — without it, the agent may use native Read/Bash on sensitive paths and bypass Scrim.`,
        };
    }
    const missing = REQUIRED_DENY_RULES.filter((r) => !deny.includes(r));
    if (missing.length === 0) {
        return {
            name: "deny-rules-present",
            status: "pass",
            detail: `${REQUIRED_DENY_RULES.length}/${REQUIRED_DENY_RULES.length} recommended deny rules present in ${source}`,
        };
    }
    return {
        name: "deny-rules-present",
        status: "fail",
        detail: `${missing.length} of ${REQUIRED_DENY_RULES.length} recommended deny rules missing from ${source}: ${missing.join(", ")}. Run scripts/install-deny-rules.sh to add them.`,
    };
}
function checkPolicy(ctx) {
    // Context was built with a parsed policy already; if we got here, it loaded.
    return {
        name: "policy-loadable",
        status: "pass",
        detail: `policy v${ctx.policy.version} loaded; failClosed=${ctx.policy.failClosed}`,
    };
}
function checkVault(ctx) {
    const cap = ctx.policy.vault.maxEntries;
    const size = ctx.vault.size();
    if (cap > 0 && size >= cap * 0.9) {
        return {
            name: "vault-healthy",
            status: "warn",
            detail: `vault at ${size}/${cap} entries (>=90% of cap). LRU eviction will start dropping entries; in-flight Writes referencing evicted tokens will be denied.`,
        };
    }
    return {
        name: "vault-healthy",
        status: "pass",
        detail: cap > 0 ? `${size}/${cap} entries` : `${size} entries (cap disabled)`,
    };
}
function checkHooks() {
    const pluginRoot = process.env["SCRIM_PLUGIN_ROOT"] ?? "";
    if (!pluginRoot) {
        return {
            name: "hooks-registered",
            status: "warn",
            detail: "SCRIM_PLUGIN_ROOT env var not set; cannot verify hook binaries (status check from a non-MCP context).",
        };
    }
    const bins = ["scrim-detokenize.js", "scrim-bash-guard.js", "scrim-stop.js"];
    const missing = bins.filter((b) => !existsSync(join(pluginRoot, "bin", b)));
    if (missing.length > 0) {
        return {
            name: "hooks-registered",
            status: "fail",
            detail: `missing hook binaries in ${pluginRoot}/bin: ${missing.join(", ")}. Run npm run build.`,
        };
    }
    return { name: "hooks-registered", status: "pass", detail: `${bins.length} hook binaries present in ${pluginRoot}/bin` };
}
function checkPresidio(ctx) {
    if (!ctx.policy.detection.presidio)
        return null;
    const cmd = ctx.policy.detection.presidioCommand ?? "scrim-presidio";
    const which = spawnSync("which", [cmd], { encoding: "utf8" });
    if (which.status !== 0) {
        return {
            name: "presidio-binary",
            status: "warn",
            detail: `policy enables Presidio but '${cmd}' is not on PATH. Presidio detection will silently return no spans.`,
        };
    }
    return { name: "presidio-binary", status: "pass", detail: `${cmd} resolved on PATH` };
}
export function scrimDoctor(ctx) {
    const checks = [
        checkDenyRules(ctx.repoRoot),
        checkPolicy(ctx),
        checkVault(ctx),
        checkHooks(),
    ];
    const presidio = checkPresidio(ctx);
    if (presidio)
        checks.push(presidio);
    const ok = checks.every((c) => c.status !== "fail");
    return { ok, checks };
}

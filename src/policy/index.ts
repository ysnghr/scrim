// Loads and validates .scrim/policy.yml; merges with the shipped default policy.
// Exposes a typed Policy that the engine, MCP server, and hooks consume.
//
// The on-disk format uses snake_case (yaml convention); the in-memory type
// uses camelCase. Field translation happens once here so the rest of the
// codebase never sees the snake_case form.

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { parse as parseYaml } from "yaml";
import type { EngineBuildInput } from "../engine/index.js";

export type Action = "redact" | "block" | "alert" | "allow";

export interface Policy {
  version: 1;
  // class → action, e.g. { secrets: "redact", pii_customer: "redact" }
  actions: Record<string, Action>;
  detection: {
    gitleaks: boolean;
    presidio: boolean;
    fastPiiRegex: boolean;
    presidioCommand?: string;
    // Largest file (in bytes) safe_read will pull fully into memory. Files
    // above this are scanned via the streaming chunked path and return a
    // summary instead of redacted content.
    maxBytes: number;
    // Streaming-scan chunk parameters. overlap caps the longest single-rule
    // match the streaming path can reliably catch.
    chunkBytes: number;
    chunkOverlap: number;
    // Tunable Shannon-entropy threshold(s). Only the generic-credential
    // catchall is exposed today; vendor-specific rules carry their own
    // (static) thresholds inside their rule definitions.
    entropy: { genericCredential: number };
  };
  tune: {
    envKeysFrom: string[];
    internalDomains: string[];
    customPatterns: { name: string; regex: string; class: string }[];
  };
  failClosed: boolean;
  allow: string[];
  vault: {
    maxEntries: number;     // LRU cap; 0 disables eviction
    wipeOnStop: boolean;    // wipe vault files on session end (Stop hook)
  };
}

// The built-in default. Mirrors policy/default-policy.yml. Hardcoding it here
// (rather than reading the file at runtime) means the plugin works even if a
// user deletes or moves the bundled policy file.
export function defaultPolicy(): Policy {
  return {
    version: 1,
    actions: {
      secrets: "redact",
      pii_customer: "redact",
      pii_internal: "alert",
      internal_hostnames: "redact",
    },
    detection: {
      gitleaks: true,
      presidio: false,
      fastPiiRegex: true,
      maxBytes: 10_000_000,
      chunkBytes: 1_048_576,
      chunkOverlap: 16_384,
      entropy: { genericCredential: 2.7 },
    },
    tune: { envKeysFrom: [".env.example"], internalDomains: [], customPatterns: [] },
    failClosed: true,
    allow: ["AKIAIOSFODNN7EXAMPLE"],
    vault: { maxEntries: 10_000, wipeOnStop: true },
  };
}

// Source-tagged error so callers can show users where the bad field lives.
export class PolicyError extends Error {
  constructor(
    message: string,
    public readonly path: string,
    public readonly source: string,
  ) {
    super(`${source}: ${path}: ${message}`);
    this.name = "PolicyError";
  }
}

function isAction(v: unknown): v is Action {
  return v === "redact" || v === "block" || v === "alert" || v === "allow";
}

function requireBool(obj: Record<string, unknown>, key: string, path: string, source: string): boolean | undefined {
  const v = obj[key];
  if (v === undefined) return undefined;
  if (typeof v !== "boolean") throw new PolicyError(`expected boolean, got ${typeof v}`, `${path}.${key}`, source);
  return v;
}

function requireStringArray(obj: Record<string, unknown>, key: string, path: string, source: string): string[] | undefined {
  const v = obj[key];
  if (v === undefined) return undefined;
  if (!Array.isArray(v)) throw new PolicyError("expected array of strings", `${path}.${key}`, source);
  for (let i = 0; i < v.length; i++) {
    if (typeof v[i] !== "string") {
      throw new PolicyError(`expected string at index ${i}`, `${path}.${key}`, source);
    }
  }
  return v as string[];
}

function requireString(obj: Record<string, unknown>, key: string, path: string, source: string): string | undefined {
  const v = obj[key];
  if (v === undefined) return undefined;
  if (typeof v !== "string") throw new PolicyError(`expected string, got ${typeof v}`, `${path}.${key}`, source);
  return v;
}

function requireNonNegInt(obj: Record<string, unknown>, key: string, path: string, source: string): number | undefined {
  const v = obj[key];
  if (v === undefined) return undefined;
  if (typeof v !== "number" || !Number.isInteger(v) || v < 0) {
    throw new PolicyError(`expected non-negative integer, got ${JSON.stringify(v)}`, `${path}.${key}`, source);
  }
  return v;
}

function requirePosInt(obj: Record<string, unknown>, key: string, path: string, source: string): number | undefined {
  const v = obj[key];
  if (v === undefined) return undefined;
  if (typeof v !== "number" || !Number.isInteger(v) || v <= 0) {
    throw new PolicyError(`expected positive integer, got ${JSON.stringify(v)}`, `${path}.${key}`, source);
  }
  return v;
}

function validate(raw: unknown, source: string, base: Policy): Policy {
  if (raw === null || raw === undefined) return base;
  if (typeof raw !== "object" || Array.isArray(raw)) {
    throw new PolicyError("expected an object at the document root", "policy", source);
  }
  const r = raw as Record<string, unknown>;

  // version
  let version: 1 = base.version;
  if (r["version"] !== undefined) {
    if (r["version"] !== 1) throw new PolicyError("only version 1 is supported", "policy.version", source);
    version = 1;
  }

  // actions
  let actions = { ...base.actions };
  if (r["actions"] !== undefined) {
    if (typeof r["actions"] !== "object" || r["actions"] === null || Array.isArray(r["actions"])) {
      throw new PolicyError("expected an object", "policy.actions", source);
    }
    for (const [klass, action] of Object.entries(r["actions"] as Record<string, unknown>)) {
      if (!isAction(action)) {
        throw new PolicyError(
          `expected one of "redact" | "block" | "alert" | "allow", got ${JSON.stringify(action)}`,
          `policy.actions.${klass}`,
          source,
        );
      }
      actions[klass] = action;
    }
  }

  // detection (snake_case → camelCase)
  const detection = { ...base.detection };
  if (r["detection"] !== undefined) {
    if (typeof r["detection"] !== "object" || r["detection"] === null || Array.isArray(r["detection"])) {
      throw new PolicyError("expected an object", "policy.detection", source);
    }
    const d = r["detection"] as Record<string, unknown>;
    const g = requireBool(d, "gitleaks", "policy.detection", source);
    if (g !== undefined) detection.gitleaks = g;
    const p = requireBool(d, "presidio", "policy.detection", source);
    if (p !== undefined) detection.presidio = p;
    const f = requireBool(d, "fast_pii_regex", "policy.detection", source);
    if (f !== undefined) detection.fastPiiRegex = f;
    const cmd = requireString(d, "presidio_command", "policy.detection", source);
    if (cmd !== undefined) detection.presidioCommand = cmd;
    const mb = requirePosInt(d, "max_bytes", "policy.detection", source);
    if (mb !== undefined) detection.maxBytes = mb;
    const cb = requirePosInt(d, "chunk_bytes", "policy.detection", source);
    if (cb !== undefined) detection.chunkBytes = cb;
    const co = requirePosInt(d, "chunk_overlap", "policy.detection", source);
    if (co !== undefined) detection.chunkOverlap = co;
    if (detection.chunkOverlap >= detection.chunkBytes) {
      throw new PolicyError(
        `chunk_overlap (${detection.chunkOverlap}) must be smaller than chunk_bytes (${detection.chunkBytes})`,
        "policy.detection.chunk_overlap",
        source,
      );
    }
    if (d["entropy"] !== undefined) {
      if (typeof d["entropy"] !== "object" || d["entropy"] === null || Array.isArray(d["entropy"])) {
        throw new PolicyError("expected an object", "policy.detection.entropy", source);
      }
      const e = d["entropy"] as Record<string, unknown>;
      if (e["generic_credential"] !== undefined) {
        const v = e["generic_credential"];
        if (typeof v !== "number" || !Number.isFinite(v) || v < 0) {
          throw new PolicyError(
            `expected non-negative number, got ${JSON.stringify(v)}`,
            "policy.detection.entropy.generic_credential",
            source,
          );
        }
        detection.entropy = { genericCredential: v };
      }
    }
  }

  // tune
  const tune = {
    envKeysFrom: [...base.tune.envKeysFrom],
    internalDomains: [...base.tune.internalDomains],
    customPatterns: [...base.tune.customPatterns],
  };
  if (r["tune"] !== undefined) {
    if (typeof r["tune"] !== "object" || r["tune"] === null || Array.isArray(r["tune"])) {
      throw new PolicyError("expected an object", "policy.tune", source);
    }
    const t = r["tune"] as Record<string, unknown>;
    const ekf = requireStringArray(t, "env_keys_from", "policy.tune", source);
    if (ekf !== undefined) tune.envKeysFrom = ekf;
    const idoms = requireStringArray(t, "internal_domains", "policy.tune", source);
    if (idoms !== undefined) tune.internalDomains = idoms;
    if (t["custom_patterns"] !== undefined) {
      if (!Array.isArray(t["custom_patterns"])) {
        throw new PolicyError("expected an array", "policy.tune.custom_patterns", source);
      }
      const cps: Policy["tune"]["customPatterns"] = [];
      (t["custom_patterns"] as unknown[]).forEach((cp, i) => {
        if (typeof cp !== "object" || cp === null || Array.isArray(cp)) {
          throw new PolicyError(`expected an object`, `policy.tune.custom_patterns[${i}]`, source);
        }
        const o = cp as Record<string, unknown>;
        const name = requireString(o, "name", `policy.tune.custom_patterns[${i}]`, source);
        const regex = requireString(o, "regex", `policy.tune.custom_patterns[${i}]`, source);
        const klass = requireString(o, "class", `policy.tune.custom_patterns[${i}]`, source);
        if (!name || !regex || !klass) {
          throw new PolicyError(
            "name, regex, and class are required",
            `policy.tune.custom_patterns[${i}]`,
            source,
          );
        }
        try {
          new RegExp(regex);
        } catch (err) {
          throw new PolicyError(
            `invalid regex: ${(err as Error).message}`,
            `policy.tune.custom_patterns[${i}].regex`,
            source,
          );
        }
        cps.push({ name, regex, class: klass });
      });
      tune.customPatterns = cps;
    }
  }

  // fail_closed
  let failClosed = base.failClosed;
  const fc = requireBool(r, "fail_closed", "policy", source);
  if (fc !== undefined) failClosed = fc;

  // allow
  let allow = [...base.allow];
  const al = requireStringArray(r, "allow", "policy", source);
  if (al !== undefined) allow = al;

  // vault
  const vault = { ...base.vault };
  if (r["vault"] !== undefined) {
    if (typeof r["vault"] !== "object" || r["vault"] === null || Array.isArray(r["vault"])) {
      throw new PolicyError("expected an object", "policy.vault", source);
    }
    const vv = r["vault"] as Record<string, unknown>;
    const m = requireNonNegInt(vv, "max_entries", "policy.vault", source);
    if (m !== undefined) vault.maxEntries = m;
    const w = requireBool(vv, "wipe_on_stop", "policy.vault", source);
    if (w !== undefined) vault.wipeOnStop = w;
  }

  return { version, actions, detection, tune, failClosed, allow, vault };
}

export function loadPolicyFromString(yamlText: string, source = "<inline>"): Policy {
  const parsed: unknown = yamlText.trim() === "" ? {} : parseYaml(yamlText);
  return validate(parsed, source, defaultPolicy());
}

// Load a policy from `<repoRoot>/.scrim/policy.yml`. If the file does not exist,
// returns the default policy. If it exists but is malformed, throws PolicyError.
export function loadPolicy(repoRoot: string): Policy {
  const path = join(repoRoot, ".scrim", "policy.yml");
  if (!existsSync(path)) return defaultPolicy();
  const text = readFileSync(path, "utf8");
  return loadPolicyFromString(text, path);
}

// Translate a Policy into the shape `buildEngineConfig` consumes. Keeps the
// engine ignorant of policy concerns (actions, fail-closed semantics).
export function toEngineInput(policy: Policy): EngineBuildInput {
  return {
    detection: {
      gitleaks: policy.detection.gitleaks,
      presidio: policy.detection.presidio,
      fastPiiRegex: policy.detection.fastPiiRegex,
      entropy: { genericCredential: policy.detection.entropy.genericCredential },
    },
    tune: {
      envKeysFrom: policy.tune.envKeysFrom,
      internalDomains: policy.tune.internalDomains,
      customPatterns: policy.tune.customPatterns,
    },
    allow: policy.allow,
    presidioCommand: policy.detection.presidioCommand,
  };
}

// Convenience for the MCP server / hooks: given a detection class, what action
// did the user configure? Defaults to "redact" — the safer choice.
export function actionFor(policy: Policy, klass: string): Action {
  return policy.actions[klass] ?? "redact";
}

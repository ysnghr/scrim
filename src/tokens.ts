// Canonical Scrim token format and parsing helpers.
//
// Token shape: ⟦scrim:<class>:<id>⟧
//   class — taxonomy/rule slug (e.g. db_password, aws-access-key-id, email)
//   id    — short stable hex identifier within the session vault
//
// The opening and closing brackets are U+27E6 / U+27E7 (MATHEMATICAL DOUBLE
// SQUARE BRACKETS). They were chosen because:
//   - Models tokenize them as a single distinct unit, so the agent can copy
//     them through edits without accidental whitespace mutation.
//   - They never appear in normal source code, config, or prose, so a match
//     unambiguously identifies a Scrim token.
//   - They are valid UTF-8 and survive shells, JSON, and YAML transport.

export const TOKEN_OPEN = "⟦scrim:";
export const TOKEN_CLOSE = "⟧";

// Class portion accepts letters, digits, underscore, and hyphen so we can use
// rule ids like "aws-access-key-id" as the class slug directly.
const TOKEN_RE = /⟦scrim:([A-Za-z0-9_\-]+):([A-Za-z0-9]+)⟧/g;

export interface ParsedToken {
  raw: string;       // the full token including brackets
  class: string;
  id: string;
  start: number;
  end: number;
}

export function isToken(s: string): boolean {
  return new RegExp(TOKEN_RE.source).test(s);
}

export function formatToken(klass: string, id: string): string {
  if (!/^[A-Za-z0-9_\-]+$/.test(klass)) {
    throw new Error(`scrim: invalid token class slug: ${klass}`);
  }
  if (!/^[A-Za-z0-9]+$/.test(id)) {
    throw new Error(`scrim: invalid token id: ${id}`);
  }
  return `${TOKEN_OPEN}${klass}:${id}${TOKEN_CLOSE}`;
}

export function parseTokens(text: string): ParsedToken[] {
  const out: ParsedToken[] = [];
  const re = new RegExp(TOKEN_RE.source, "g");
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    out.push({
      raw: m[0],
      class: m[1] ?? "",
      id: m[2] ?? "",
      start: m.index,
      end: m.index + m[0].length,
    });
  }
  return out;
}

// Replace every token in `text` with the result of `lookup(token)`. If lookup
// returns null/undefined, the caller decides whether to throw or leave it in
// place; this function leaves it in place and reports which tokens were missing.
export function replaceTokens(
  text: string,
  lookup: (raw: string) => string | null,
): { output: string; missing: string[] } {
  const tokens = parseTokens(text);
  if (tokens.length === 0) return { output: text, missing: [] };
  const missing: string[] = [];
  let out = "";
  let cursor = 0;
  for (const t of tokens) {
    out += text.slice(cursor, t.start);
    const resolved = lookup(t.raw);
    if (resolved == null) {
      missing.push(t.raw);
      out += t.raw;
    } else {
      out += resolved;
    }
    cursor = t.end;
  }
  out += text.slice(cursor);
  return { output: out, missing };
}

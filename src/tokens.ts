// Canonical Scrim token format and parsing helpers.
// Token shape: ⟦scrim:<class>:<id>⟧
//   class — taxonomy bucket (e.g. db_password, aws_access_key, email, customer_id)
//   id    — short stable identifier within the session vault (base32, ~6 chars)
// The token is opaque to the model but stable across reads within a session,
// so the agent can copy it through edits and the egress hook can restore it.

export const TOKEN_OPEN = "⟦scrim:";
export const TOKEN_CLOSE = "⟧";

export interface ParsedToken {
  class: string;
  id: string;
  raw: string;
}

export function parseTokens(_text: string): ParsedToken[] {
  throw new Error("parseTokens: not implemented yet");
}

export function formatToken(_klass: string, _id: string): string {
  throw new Error("formatToken: not implemented yet");
}

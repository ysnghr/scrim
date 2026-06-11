// Gitleaks-compatible secret rules.
//
// Each rule has a regex with a single capturing group that points at the secret
// value (so callers can tokenize just the value, not the surrounding context).
// Where a rule needs the full match to be the secret, group 1 covers the whole match.
//
// `entropy` (optional) is the minimum Shannon entropy of the captured value.
// Used to suppress matches on placeholders like "password=changeme".
function re(src, flags = "g") {
    return new RegExp(src, flags);
}
export const SECRET_RULES = [
    // --- Private key blocks (multiline) ---
    {
        id: "private-key-block",
        class: "secrets",
        pattern: re("(-----BEGIN[A-Z ]{0,30}PRIVATE KEY-----[\\s\\S]*?-----END[A-Z ]{0,30}PRIVATE KEY-----)", "g"),
    },
    // --- Cloud provider keys ---
    {
        id: "aws-access-key-id",
        class: "secrets",
        pattern: re("\\b(AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16})\\b"),
    },
    {
        id: "google-api-key",
        class: "secrets",
        pattern: re("\\b(AIza[0-9A-Za-z\\-_]{35})\\b"),
    },
    // --- Source forges ---
    {
        id: "github-token-classic",
        class: "secrets",
        pattern: re("\\b(gh[pousr]_[A-Za-z0-9]{36,255})\\b"),
    },
    {
        id: "github-token-fine-grained",
        class: "secrets",
        pattern: re("\\b(github_pat_[A-Za-z0-9_]{82,})\\b"),
    },
    {
        id: "gitlab-token",
        class: "secrets",
        pattern: re("\\b(glpat-[A-Za-z0-9\\-_]{20,})\\b"),
    },
    // --- Payments / messaging ---
    {
        id: "stripe-key",
        class: "secrets",
        pattern: re("\\b((?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{24,})\\b"),
    },
    {
        id: "slack-token",
        class: "secrets",
        pattern: re("\\b(xox[abprso]-[A-Za-z0-9-]{10,})\\b"),
    },
    {
        id: "twilio-key",
        class: "secrets",
        pattern: re("\\b((?:SK|AC)[0-9a-fA-F]{32})\\b"),
    },
    {
        id: "sendgrid-key",
        class: "secrets",
        pattern: re("\\b(SG\\.[A-Za-z0-9_\\-]{22}\\.[A-Za-z0-9_\\-]{43})\\b"),
    },
    // --- AI providers ---
    {
        id: "anthropic-api-key",
        class: "secrets",
        pattern: re("\\b(sk-ant-[A-Za-z0-9_\\-]{32,})\\b"),
    },
    {
        id: "openai-api-key",
        // Order matters: keep AFTER stripe so sk_live_/sk_test_ have already matched.
        class: "secrets",
        pattern: re("\\b(sk-(?:proj-)?[A-Za-z0-9_\\-]{20,})\\b"),
    },
    // --- Package managers ---
    {
        id: "npm-token",
        class: "secrets",
        pattern: re("\\b(npm_[A-Za-z0-9]{36})\\b"),
    },
    // --- JWTs ---
    {
        id: "jwt",
        class: "secrets",
        pattern: re("\\b(eyJ[A-Za-z0-9_=\\-]+\\.eyJ[A-Za-z0-9_=\\-]+\\.[A-Za-z0-9_=\\-]+)\\b"),
    },
    // --- Connection strings with embedded credentials ---
    // Match user:password in URLs. Capture group 1 is the password portion only.
    {
        id: "url-basic-auth",
        class: "secrets",
        pattern: re("(?:postgres|postgresql|mysql|mongodb(?:\\+srv)?|redis|amqps?|https?)://[^\\s:/@]+:([^\\s/@]+)@", "gi"),
    },
    // --- Generic password / token assignments ---
    // Catches "password=...", "API_TOKEN: ...", "secret = '...'", etc.
    // Captures the value only; requires entropy to suppress placeholders.
    {
        id: "generic-credential-assignment",
        class: "secrets",
        pattern: re("(?:password|passwd|pwd|secret|api[_\\-]?key|api[_\\-]?token|auth[_\\-]?token|access[_\\-]?token|client[_\\-]?secret)\\s*[:=]\\s*[\"']?([A-Za-z0-9_+/=.\\-]{8,})[\"']?", "gi"),
        entropy: 3.0,
    },
];
// Shannon entropy in bits per character. Higher = more random.
export function shannonEntropy(s) {
    if (s.length === 0)
        return 0;
    const counts = new Map();
    for (const ch of s)
        counts.set(ch, (counts.get(ch) ?? 0) + 1);
    let h = 0;
    for (const c of counts.values()) {
        const p = c / s.length;
        h -= p * Math.log2(p);
    }
    return h;
}

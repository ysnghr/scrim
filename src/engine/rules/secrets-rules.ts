// Gitleaks-compatible secret rules.
//
// Each rule has a regex with a single capturing group that points at the secret
// value (so callers can tokenize just the value, not the surrounding context).
// Where a rule needs the full match to be the secret, group 1 covers the whole match.
//
// `entropy` (optional) is the minimum Shannon entropy of the captured value.
// Used to suppress matches on placeholders like "password=changeme".

export interface SecretRule {
  id: string;
  class: string;
  pattern: RegExp;
  entropy?: number;
}

function re(src: string, flags = "g"): RegExp {
  return new RegExp(src, flags);
}

export const SECRET_RULES: SecretRule[] = [
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

  // --- Cloud / hosting providers ---
  {
    id: "digitalocean-token",
    class: "secrets",
    pattern: re("\\b(do[oprs]_v1_[a-f0-9]{64})\\b"),
  },
  {
    id: "hashicorp-vault-token",
    class: "secrets",
    pattern: re("\\b(hv[bs]\\.[A-Za-z0-9_\\-]{90,200})\\b"),
  },
  {
    id: "heroku-platform-token",
    class: "secrets",
    pattern: re("\\b(HRKU-[A-Za-z0-9_\\-]{30,})\\b"),
  },

  // --- Email / messaging / CRM ---
  {
    id: "sendinblue-key",
    class: "secrets",
    pattern: re("\\b(xkeysib-[a-f0-9]{64}-[A-Za-z0-9]{16})\\b"),
  },
  {
    id: "slack-webhook-url",
    class: "secrets",
    pattern: re("(https://hooks\\.slack\\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{20,})", "g"),
  },

  // --- Observability ---
  {
    // Sentry auth tokens: sntrys_ (secret), sntryu_ (user), sntryo_ (org).
    id: "sentry-token",
    class: "secrets",
    pattern: re("\\b(sntry[suo]_[A-Za-z0-9]{64})\\b"),
  },

  // --- Commerce / payments ---
  {
    id: "shopify-token",
    class: "secrets",
    pattern: re("\\b(shp(?:at|ca|ss|pa)_[a-fA-F0-9]{32})\\b"),
  },
  {
    id: "square-access-token",
    class: "secrets",
    pattern: re("\\b(EAAA[A-Za-z0-9_\\-]{60})\\b"),
  },
  {
    id: "plaid-key",
    class: "secrets",
    pattern: re("\\b(access-(?:sandbox|development|production)-[a-f0-9\\-]{36})\\b"),
  },

  // --- AI / ML platforms ---
  {
    id: "huggingface-token",
    class: "secrets",
    pattern: re("\\b(hf_[A-Za-z]{34,40})\\b"),
  },

  // --- Productivity SaaS ---
  {
    id: "linear-api-key",
    class: "secrets",
    pattern: re("\\b(lin_api_[A-Za-z0-9]{40})\\b"),
  },
  {
    id: "notion-integration-token",
    class: "secrets",
    pattern: re("\\b(secret_[A-Za-z0-9]{43})\\b"),
  },
  {
    id: "asana-pat",
    class: "secrets",
    pattern: re("\\b(1/\\d{16}:[a-f0-9]{32})\\b"),
  },
  {
    id: "atlassian-api-token",
    class: "secrets",
    pattern: re("\\b(ATATT3xFfGF0[A-Za-z0-9_\\-]{100,}=[A-F0-9]{8})\\b"),
  },

  // --- Dev tools ---
  {
    id: "postman-api-key",
    class: "secrets",
    pattern: re("\\b(PMAK-[a-f0-9]{24}-[a-f0-9]{34})\\b"),
  },
  {
    id: "sonar-token",
    class: "secrets",
    pattern: re("\\b(sq[abpu]_[a-f0-9]{40})\\b"),
  },
  {
    id: "new-relic-api-key",
    class: "secrets",
    pattern: re("\\b(NRAK-[A-Z0-9]{27})\\b"),
  },
  {
    id: "jfrog-api-key",
    class: "secrets",
    pattern: re("\\b(AKCp[A-Za-z0-9]{69})\\b"),
  },

  // --- File / object storage ---
  {
    id: "dropbox-token",
    class: "secrets",
    pattern: re("\\b(sl\\.[A-Za-z0-9_\\-]{130,})\\b"),
  },

  // --- Package managers / registries ---
  {
    id: "pypi-token",
    class: "secrets",
    pattern: re("\\b(pypi-AgEIcHlwaS5vcmcC[A-Za-z0-9_\\-]{50,})\\b"),
  },
  {
    id: "rubygems-api-key",
    class: "secrets",
    pattern: re("\\b(rubygems_[a-f0-9]{48})\\b"),
  },

  // --- Chat / bot tokens (entropy-gated; the shape is shared by lots of
  // unrelated colon-separated identifiers — without entropy this would
  // false-positive on things like "12345678:my-build-tag") ---
  {
    id: "telegram-bot-token",
    class: "secrets",
    pattern: re("\\b(\\d{8,10}:[A-Za-z0-9_\\-]{35})\\b"),
    entropy: 3.0,
  },
  {
    id: "discord-bot-token",
    class: "secrets",
    pattern: re("\\b([MN][A-Za-z\\d]{23}\\.[\\w\\-]{6}\\.[\\w\\-]{27})\\b"),
    entropy: 3.0,
  },

  // --- Generic password / token assignments ---
  // Catches "password=...", "API_TOKEN: ...", "secret = '...'", etc.
  // Captures the value only; requires entropy to suppress placeholders.
  // Lives LAST so more-specific vendor rules above win on overlap.
  {
    id: "generic-credential-assignment",
    class: "secrets",
    pattern: re("(?:password|passwd|pwd|secret|api[_\\-]?key|api[_\\-]?token|auth[_\\-]?token|access[_\\-]?token|client[_\\-]?secret)\\s*[:=]\\s*[\"']?([A-Za-z0-9_+/=.\\-]{8,})[\"']?", "gi"),
    entropy: 3.0,
  },
];

// Shannon entropy in bits per character. Higher = more random.
export function shannonEntropy(s: string): number {
  if (s.length === 0) return 0;
  const counts = new Map<string, number>();
  for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let h = 0;
  for (const c of counts.values()) {
    const p = c / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

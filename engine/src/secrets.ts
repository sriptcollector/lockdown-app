// Live-credential patterns for files outside git (shell history, configs, downloads).
// Code inside repos goes through gitleaks instead.

export interface SecretRule {
  id: string;
  name: string; // provider, plain words
  re: RegExp;
  rotate?: string; // where to replace it
}

export const SECRET_RULES: SecretRule[] = [
  { id: "aws", name: "AWS access key", re: /\b(AKIA|ASIA)[0-9A-Z]{16}\b/g, rotate: "https://console.aws.amazon.com/iam/home#/security_credentials" },
  { id: "github", name: "GitHub token", re: /\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b/g, rotate: "https://github.com/settings/tokens" },
  { id: "stripe", name: "Stripe live key", re: /\b(sk|rk)_live_[A-Za-z0-9]{20,}\b/g, rotate: "https://dashboard.stripe.com/apikeys" },
  { id: "stripe-webhook", name: "Stripe webhook secret", re: /\bwhsec_[A-Za-z0-9]{24,}\b/g, rotate: "https://dashboard.stripe.com/webhooks" },
  { id: "openai", name: "OpenAI key", re: /\bsk-(proj-|svcacct-|admin-)?[A-Za-z0-9_-]{40,}\b/g, rotate: "https://platform.openai.com/api-keys" },
  { id: "anthropic", name: "Anthropic key", re: /\bsk-ant-(api|admin)\d{2}-[A-Za-z0-9_-]{80,}\b/g, rotate: "https://console.anthropic.com/settings/keys" },
  { id: "google", name: "Google API key", re: /\bAIza[0-9A-Za-z_-]{35}\b/g, rotate: "https://console.cloud.google.com/apis/credentials" },
  { id: "slack", name: "Slack token", re: /\bxox[abposr]-[A-Za-z0-9-]{10,}\b/g, rotate: "https://api.slack.com/apps" },
  { id: "sendgrid", name: "SendGrid key", re: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g, rotate: "https://app.sendgrid.com/settings/api_keys" },
  { id: "resend", name: "Resend key", re: /\bre_[A-Za-z0-9]{8}_[A-Za-z0-9]{20,}\b/g, rotate: "https://resend.com/api-keys" },
  { id: "twilio", name: "Twilio key", re: /\bSK[0-9a-f]{32}\b/g, rotate: "https://console.twilio.com/" },
  { id: "huggingface", name: "Hugging Face token", re: /\bhf_[A-Za-z0-9]{34,}\b/g, rotate: "https://huggingface.co/settings/tokens" },
  { id: "npm", name: "npm token", re: /\bnpm_[A-Za-z0-9]{36}\b/g, rotate: "https://www.npmjs.com/settings/~/tokens" },
  { id: "supabase-service", name: "Supabase service key", re: /\bsb_secret_[A-Za-z0-9_-]{20,}\b/g, rotate: "https://supabase.com/dashboard/project/_/settings/api-keys" },
  { id: "vercel", name: "Vercel token", re: /\bvc[pkia]_[A-Za-z0-9]{24,}\b/g, rotate: "https://vercel.com/account/tokens" },
  { id: "cloudflare", name: "Cloudflare token", re: /\bcf(ut|at)_[A-Za-z0-9_-]{30,}\b/g, rotate: "https://dash.cloudflare.com/profile/api-tokens" },
  { id: "private-key", name: "Private key", re: /-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY( BLOCK)?-----/g },
  { id: "gcp-sa", name: "Google service account key", re: /"type"\s*:\s*"service_account"/g, rotate: "https://console.cloud.google.com/iam-admin/serviceaccounts" },
  { id: "db-url", name: "Database password in a URL", re: /\b(postgres(ql)?|mysql|mongodb(\+srv)?|redis|rediss):\/\/[^\s:@\/]+:[^\s@\/]{6,}@[^\s'"]+/g },
  { id: "bearer-cli", name: "Password on a command line", re: /--password[= ](?![$%{<])[^\s'"]{8,}|\bAuthorization:\s*Bearer\s+(?![$%{<])[A-Za-z0-9._-]{20,}/gi },
];

export interface SecretHit {
  rule: SecretRule;
  value: string;
  line: number;
}

export function findSecrets(text: string, maxHits = 50): SecretHit[] {
  const hits: SecretHit[] = [];
  const lineStarts: number[] = [0];
  for (let i = 0; i < text.length; i++) if (text.charCodeAt(i) === 10) lineStarts.push(i + 1);
  const lineOf = (idx: number) => {
    let lo = 0,
      hi = lineStarts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (lineStarts[mid] <= idx) lo = mid;
      else hi = mid - 1;
    }
    return lo + 1;
  };
  for (const rule of SECRET_RULES) {
    rule.re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = rule.re.exec(text)) && hits.length < maxHits) {
      const v = m[0];
      if (/example|xxxx|your[_-]?key|placeholder|<|\$\{/i.test(v)) continue;
      hits.push({ rule, value: v, line: lineOf(m.index) });
    }
  }
  return hits;
}

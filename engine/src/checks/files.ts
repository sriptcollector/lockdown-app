// Files layer: secrets in plain files, key permissions, exported passwords.
import { existsSync, readFileSync, statSync } from "node:fs";
import { basename, join } from "node:path";
import type { ScanCtx } from "../context";
import type { Finding, Severity } from "../types";
import { findSecrets } from "../secrets";
import { HOME, IS_WIN, redact, run, shortPath } from "../util";
import { mayRead, skippedFolders } from "../permissions";
import { cloudFolders, codeRoots, fileSize, inCloudFolder, walk } from "../walk";

type F = Omit<Finding, "id" | "layer">;

const HISTORY_FILES = () => [
  IS_WIN ? join(process.env.LOCKDOWN_APPDATA || process.env.APPDATA || join(HOME, "AppData", "Roaming"), "Microsoft", "Windows", "PowerShell", "PSReadLine", "ConsoleHost_history.txt") : "",
  join(HOME, ".bash_history"),
  join(HOME, ".zsh_history"),
  join(HOME, ".local", "share", "fish", "fish_history"),
  join(HOME, ".python_history"),
  join(HOME, ".node_repl_history"),
  join(HOME, ".psql_history"),
  join(HOME, ".mysql_history"),
  join(HOME, ".rediscli_history"),
].filter(Boolean);

const AI_CONFIGS = () => [
  join(HOME, ".claude.json"),
  join(HOME, ".cursor", "mcp.json"),
  join(HOME, ".codeium", "windsurf", "mcp_config.json"),
  join(HOME, ".gemini", "settings.json"),
  join(HOME, ".codex", "config.toml"),
  IS_WIN ? join(process.env.APPDATA || "", "Claude", "claude_desktop_config.json") : join(HOME, "Library", "Application Support", "Claude", "claude_desktop_config.json"),
  IS_WIN ? join(process.env.APPDATA || "", "Code", "User", "settings.json") : join(HOME, "Library", "Application Support", "Code", "User", "settings.json"),
  IS_WIN ? join(process.env.APPDATA || "", "Code", "User", "mcp.json") : join(HOME, "Library", "Application Support", "Code", "User", "mcp.json"),
];

const CRED_FILES: { path: () => string; name: string; severity: Severity; why: string; test?: (t: string) => boolean; manual: string }[] = [
  { path: () => join(HOME, ".git-credentials"), name: "Git passwords saved in plain text", severity: "high", why: "Every Git host password or token you've used is in one readable file.", test: (t) => /:\/\/[^:\s]+:[^@\s]+@/.test(t), manual: "" },
  { path: () => join(HOME, ".aws", "credentials"), name: "Long-lived AWS keys on disk", severity: "high", why: "Keys that never expire are the most common way AWS accounts get taken over.", test: (t) => /aws_access_key_id\s*=\s*AKIA/i.test(t), manual: "Switch to AWS IAM Identity Center (aws sso login) and delete the long-lived keys." },
  { path: () => join(HOME, ".docker", "config.json"), name: "Docker registry passwords in plain text", severity: "medium", why: "Your registry login is stored base64-encoded, which anyone can decode.", test: (t) => /"auth"\s*:\s*"[A-Za-z0-9+/=]{8,}"/.test(t), manual: "Use a Docker credential helper (credsStore: desktop or wincred) and run docker login again." },
  { path: () => join(HOME, ".npmrc"), name: "npm publish token in plain text", severity: "medium", why: "Someone with it can publish malware under your npm name.", test: (t) => /_authToken\s*=\s*(?!\$\{)\S{10,}/.test(t), manual: "Use granular, expiring npm tokens and keep them in an environment variable." },
  { path: () => join(HOME, ".pypirc"), name: "PyPI password in plain text", severity: "medium", why: "Someone with it can publish packages as you.", test: (t) => /password\s*=\s*\S+/.test(t), manual: "Use a PyPI API token scoped to one project, stored with keyring." },
  { path: () => join(HOME, ".netrc"), name: "Passwords in .netrc", severity: "medium", why: "Plain-text logins for servers and APIs.", test: (t) => /password\s+\S+/.test(t), manual: "Move these logins to your OS keychain." },
  { path: () => join(HOME, IS_WIN ? "_netrc" : ".netrc-unused"), name: "Passwords in _netrc", severity: "medium", why: "Plain-text logins for servers and APIs.", test: (t) => /password\s+\S+/.test(t), manual: "Move these logins to Windows Credential Manager." },
];

const PASSWORD_EXPORT = /^(.*passwords?.*\.csv|chrome passwords.*\.csv|.*logins.*\.csv|bitwarden_export.*\.(json|csv)|1password.*\.(csv|1pux)|lastpass.*\.csv|.*\bkeychain\b.*\.csv|.*seed.?phrase.*\.(txt|docx?|rtf|png|jpe?g))$/i;
const KEY_FILE = /\.(pem|p12|pfx|key|jks|keystore|ppk|ovpn)$/i;

export async function scanFiles(ctx: ScanCtx) {
  const report = (f: F) => ctx.report({ layer: "files", ...f }, "machine");

  await ctx.step("files", "files.history", "Shell and console history", async () => {
    for (const p of HISTORY_FILES()) {
      if (!existsSync(p) || fileSize(p) > 50_000_000) continue;
      const hits = findSecrets(readFileSync(p, "utf8"), 200);
      if (!hits.length) continue;
      const kinds = [...new Set(hits.map((h) => h.rule.name))];
      report({
        check: "files.history-secrets",
        severity: "high",
        title: `${hits.length} secret${hits.length > 1 ? "s" : ""} saved in your ${basename(p)} history`,
        why: "Anything you paste into a terminal is saved in plain text. Malware that steals files grabs these first.",
        where: shortPath(p),
        evidence: kinds.slice(0, 4).join(", ") + ` (e.g. ${redact(hits[0].value)})`,
        fix: { fixer: "files.scrub-lines", action: "Remove those lines from the history file", params: { path: p, lines: [...new Set(hits.map((h) => h.line))] } },
      });
    }
  });

  await ctx.step("files", "files.ssh", "SSH keys", async () => {
    const dir = join(HOME, ".ssh");
    if (!existsSync(dir)) return "no .ssh folder";
    const keys = walk(dir, { maxDepth: 1, match: (n, _f, d) => !d && !n.endsWith(".pub") && !/^(known_hosts|config|authorized_keys)/.test(n) });
    for (const k of keys) {
      let t = "";
      try {
        if (fileSize(k) > 20_000) continue;
        t = readFileSync(k, "utf8");
      } catch {
        continue;
      }
      if (!/PRIVATE KEY-----/.test(t)) continue;
      if (!keyHasPassphrase(t)) {
        report({
          check: "files.ssh-nopass",
          severity: "medium",
          title: `SSH key ${basename(k)} has no passphrase`,
          why: "If this file is ever copied off your computer, it unlocks every server and Git host that trusts it.",
          where: shortPath(k),
          fix: { fixer: "none", action: "Add a passphrase", params: {}, manual: `Run: ssh-keygen -p -f "${k}", then use ssh-agent so you only type it once per session.` },
        });
      }
      await checkPerms(k, report, "SSH private key");
    }
  });

  await ctx.step("files", "files.creds", "Saved logins and tokens", async () => {
    for (const c of CRED_FILES) {
      const p = c.path();
      if (!existsSync(p)) continue;
      let t = "";
      try {
        t = readFileSync(p, "utf8");
      } catch {
        continue;
      }
      if (c.test && !c.test(t)) continue;
      const isGitCreds = basename(p) === ".git-credentials";
      report({
        check: "files.cred-file",
        severity: c.severity,
        title: c.name,
        why: c.why,
        where: shortPath(p),
        fix: isGitCreds
          ? { fixer: "files.git-credentials", action: "Move Git logins into the system keychain", params: { path: p } }
          : { fixer: "none", action: "Store it securely", params: {}, manual: c.manual },
      });
      await checkPerms(p, report, c.name);
    }
    for (const p of AI_CONFIGS()) {
      if (!existsSync(p) || fileSize(p) > 5_000_000) continue;
      const hits = findSecrets(readFileSync(p, "utf8"));
      if (!hits.length) continue;
      report({
        check: "files.ai-config",
        severity: "medium",
        title: `API keys pasted into ${basename(p)}`,
        why: "AI tool configs are plain text, often synced or shared, and any extension or MCP server you run can read them.",
        where: shortPath(p),
        evidence: [...new Set(hits.map((h) => h.rule.name))].join(", ") + ` (e.g. ${redact(hits[0].value)})`,
        fix: { fixer: "none", action: "Reference keys from environment variables", params: {}, manual: "Put the key in an environment variable and reference it from the config (most tools accept ${VAR})." },
      });
    }
  });

  await ctx.step("files", "files.exports", "Downloaded password exports and key files", async () => {
    const dirs = ["Downloads", "Desktop", "Documents"].map((d) => join(HOME, d));
    for (const c of cloudFolders()) dirs.push(join(c, "Desktop"), join(c, "Documents"));
    const skipped = skippedFolders();
    if (skipped.length) {
      const names = skipped.map((f) => f.label).join(", ");
      report({
        check: "files.not-checked",
        severity: "info",
        title: `Lockdown didn't look in ${names}`,
        why: "Your Mac keeps apps out of these folders until you say yes, so passwords or keys left there weren't checked.",
        fix: { fixer: "mac.open", action: "Let Lockdown check these folders", params: { url: "x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension?Privacy_FilesAndFolders" }, manual: `In System Settings > Privacy & Security > Files & Folders, turn on ${names} under Lockdown.` },
      });
    }
    for (const d of [...new Set(dirs)]) {
      if (!existsSync(d) || !mayRead(d)) continue;
      const found = walk(d, { maxDepth: 3, match: (n, _f, isDir) => !isDir && (PASSWORD_EXPORT.test(n) || KEY_FILE.test(n) || /\.json$/i.test(n)), limit: 4000 });
      for (const p of found) {
        const n = basename(p);
        if (PASSWORD_EXPORT.test(n)) {
          report({
            check: "files.password-export",
            severity: "critical",
            title: `Password export sitting in ${basename(d)}`,
            why: "An exported password list is every account you have in one unencrypted file.",
            where: shortPath(p),
            fix: { fixer: "files.quarantine", action: "Lock it away in Lockdown's vault folder", params: { path: p } },
          });
        } else if (KEY_FILE.test(n) && fileSize(p) < 50_000) {
          const t = safeRead(p);
          if (t && !/PRIVATE KEY|ENCRYPTED/.test(t) && !/\.(p12|pfx|jks|keystore|ppk|ovpn)$/i.test(n)) continue;
          report({
            check: "files.loose-key",
            severity: "high",
            title: `Private key file ${n} in ${basename(d)}`,
            why: "Keys left in Downloads or Desktop get synced, emailed, and backed up to places you don't control.",
            where: shortPath(p),
            fix: { fixer: "files.quarantine", action: "Move it to Lockdown's vault folder", params: { path: p, reliance: "running-app" } },
          });
        } else if (/\.json$/i.test(n) && fileSize(p) < 20_000) {
          const t = safeRead(p);
          if (t && /"type"\s*:\s*"service_account"/.test(t) && /"private_key"/.test(t)) {
            report({
              check: "files.gcp-key",
              severity: "high",
              title: `Google Cloud service-account key in ${basename(d)}`,
              why: "These keys never expire and often have broad access to your cloud project.",
              where: shortPath(p),
              evidence: (t.match(/"client_email"\s*:\s*"([^"]+)"/)?.[1] ?? "").replace(/^(.{3}).*(@.*)$/, "$1…$2"),
              fix: { fixer: "files.quarantine", action: "Move it to Lockdown's vault folder", params: { path: p, reliance: "running-app" } },
            });
          }
        }
      }
    }
  });

  await ctx.step("files", "files.dotenv", ".env files with live keys", async () => {
    const roots = codeRoots(ctx.prefs.codeRoots).filter((r) => r !== HOME);
    let live = 0;
    let synced = 0;
    let syncedTo = "";
    const files = new Set<string>();
    for (const r of roots) {
      for (const p of walk(r, { maxDepth: 5, match: (n, _f, d) => !d && /^\.env(\..+)?$/.test(n) && !/\.(example|sample|template|dist)$/.test(n), limit: 3000 })) files.add(p);
    }
    for (const p of files) {
      if (fileSize(p) > 200_000) continue;
      const hits = findSecrets(safeRead(p) ?? "").filter((h) => h.rule.id !== "bearer-cli");
      if (!hits.length) continue;
      live++;
      const cloud = inCloudFolder(p);
      if (cloud) {
        synced++;
        syncedTo = cloud;
      }
    }
    if (synced) {
      report({
        check: "files.env-synced",
        severity: "medium",
        title: `${synced} .env file${synced > 1 ? "s" : ""} with live keys sync to ${syncedTo}`,
        why: `Your project folders sync to ${syncedTo}, so your production keys live in that cloud account too. If it's ever breached or shared, so are they.`,
        evidence: `${live} .env files with live keys found, ${synced} inside ${syncedTo}`,
        fix: { fixer: "none", action: "Keep code outside synced folders", params: {}, manual: `Move your code folder out of ${syncedTo} (e.g. to ${join(HOME, "code")}) and push to GitHub instead of syncing.` },
      });
    }
  });
}

function safeRead(p: string): string | null {
  try {
    return readFileSync(p, "utf8");
  } catch {
    return null;
  }
}

export function keyHasPassphrase(t: string): boolean {
  if (/ENCRYPTED/.test(t)) return true;
  const m = t.match(/-----BEGIN OPENSSH PRIVATE KEY-----([\s\S]+?)-----END/);
  if (!m) return false;
  try {
    const buf = Buffer.from(m[1].replace(/\s+/g, ""), "base64");
    // "openssh-key-v1\0" + string ciphername + string kdfname
    let o = 15;
    const len = buf.readUInt32BE(o);
    const cipher = buf.subarray(o + 4, o + 4 + len).toString();
    return cipher !== "none";
  } catch {
    return false;
  }
}

async function checkPerms(p: string, report: (f: F) => void, what: string) {
  if (IS_WIN) {
    const r = await run("icacls", [p], { timeoutMs: 10_000 });
    const broad = r.stdout.split(/\r?\n/).filter((l) => /\b(Everyone|BUILTIN\\Users|Authenticated Users|NT AUTHORITY\\Authenticated Users)\b:.*\((F|M|RX|R|W)/i.test(l));
    if (broad.length) {
      report({ check: "files.perms", severity: "medium", title: `${what} can be read by other accounts`, why: "Other users and some services on this PC can read it.", where: shortPath(p), evidence: broad[0].trim().replace(/^.*?(\S+:\S+)$/, "$1"), fix: { fixer: "files.restrict", action: "Make it readable only by you", params: { path: p } } });
    }
  } else {
    try {
      const mode = statSync(p).mode & 0o777;
      if (mode & 0o077) {
        report({ check: "files.perms", severity: "medium", title: `${what} can be read by other accounts`, why: "Other users and processes on this computer can read it.", where: shortPath(p), evidence: `mode ${mode.toString(8)}`, fix: { fixer: "files.restrict", action: "Make it readable only by you", params: { path: p } } });
      }
    } catch {}
  }
}

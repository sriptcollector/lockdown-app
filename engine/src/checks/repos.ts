// Code layer: leaked secrets (gitleaks), vulnerable dependencies (OSV-Scanner), insecure code
// (Opengrep with Lockdown's rules), and how easy the app is to reverse-engineer.
import { existsSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { basename, join, relative } from "node:path";
import type { ScanCtx } from "../context";
import type { Finding, Severity } from "../types";
import { gh, parseGithubRemote, repoInfo } from "../gh";
import { ensureTool } from "../scanners/tools";
import { findSecrets, SECRET_RULES } from "../secrets";
import { dataDir, hash, redact, run, shortPath } from "../util";
import { codeRoots, fileSize, findRepos, walk } from "../walk";
import rulesYml from "../rules/lockdown.yml" with { type: "text" };

type F = Omit<Finding, "id" | "layer">;

export interface RepoMeta {
  path: string;
  name: string;
  remote?: string;
  gh?: { owner: string; repo: string; private: boolean; fork: boolean; stars: number; pages: boolean; defaultBranch: string } | null;
}

async function pool<T>(items: T[], n: number, fn: (x: T, i: number) => Promise<void>) {
  let i = 0;
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, async () => { while (i < items.length) { const k = i++; await fn(items[k], k); } }));
}

export async function discoverRepos(ctx: ScanCtx): Promise<RepoMeta[]> {
  const paths = process.env.LOCKDOWN_REPOS ? process.env.LOCKDOWN_REPOS.split(";") : findRepos(codeRoots(ctx.prefs.codeRoots));
  const metas: RepoMeta[] = [];
  await pool(paths, 8, async (p) => {
    const r = await run("git", ["-C", p, "remote", "get-url", "origin"], { timeoutMs: 10_000 });
    const remote = r.code === 0 ? r.stdout.trim() : undefined;
    const gr = remote ? parseGithubRemote(remote) : null;
    let gh: RepoMeta["gh"] = null;
    if (gr) {
      const info = await repoInfo(gr.owner, gr.repo);
      if (info) gh = { owner: info.owner.login, repo: info.name, private: info.private, fork: info.fork, stars: info.stargazers_count, pages: info.has_pages, defaultBranch: info.default_branch };
    }
    metas.push({ path: p, name: gh ? `${gh.owner}/${gh.repo}` : basename(p), remote, gh });
  });
  metas.sort((a, b) => a.name.localeCompare(b.name));
  for (const m of metas) ctx.target({ kind: "repo", id: `repo:${m.path}`, name: m.name, layer: "code" });
  return metas;
}

export async function scanRepos(ctx: ScanCtx, all: RepoMeta[]) {
  if (!all.length) return;
  // Projects the last scan ran out of time for go first this time, so "Check again" picks up where it stopped.
  const lateFile = join(dataDir(), "code-late.json");
  const lastLate = new Set<string>(existsSync(lateFile) ? JSON.parse(readFileSync(lateFile, "utf8")) : []);
  const repos = [...all.filter((r) => lastLate.has(r.path)), ...all.filter((r) => !lastLate.has(r.path))];
  const tid = (r: RepoMeta) => `repo:${r.path}`;

  // A first check shouldn't take a quarter of an hour on a laptop full of projects: deep checks stop at
  // the time limit, and whatever didn't fit is named in the results instead of silently missing.
  const deadline = Date.now() + CODE_BUDGET_MS;
  const late = new Map<string, string>();
  const inTime = (r: RepoMeta, fn: () => Promise<void | string>) => () => {
    if (Date.now() > deadline) {
      late.set(r.path, r.name);
      return Promise.resolve("time limit for this check");
    }
    return fn();
  };
  const n = repos.length;
  const label = (what: string, r: RepoMeta, i: number) => `${what} in ${r.name} (project ${i + 1} of ${n})`;

  // Secrets in code and history, one repo at a time (gitleaks needs a repo per run).
  await pool(repos, 4, async (r, i) => {
    await ctx.step("code", "code.secrets", label("Leaked keys", r, i), inTime(r, () => gitleaksRepo(ctx, r)), tid(r));
  });

  // Dependencies are looked up once across every repo.
  await ctx.step("code", "code.deps", "Known-vulnerable packages", () => osvAll(ctx, repos));

  // Code patterns per repo, so progress is real and one huge project can't stall the rest.
  await pool(repos, 2, async (r, i) => {
    await ctx.step("code", "code.patterns", label("Unsafe code", r, i), inTime(r, () => opengrepRepo(ctx, r)), tid(r));
  });

  await pool(repos, 6, async (r, i) => {
    await ctx.step("code", "code.reverse", label("Reverse-engineering exposure", r, i), async () => reverseChecks(ctx, r), tid(r));
    await ctx.step("code", "code.config", label("Config and workflows", r, i), async () => configChecks(ctx, r), tid(r));
  });

  writeFileSync(lateFile, JSON.stringify([...late.keys()]));
  if (late.size) {
    const names = [...new Set(late.values())];
    ctx.report({
      layer: "code",
      check: "code.not-checked",
      severity: "info",
      title: `${names.length === 1 ? "1 project wasn't" : `${names.length} projects weren't`} fully checked for leaked keys and unsafe code`,
      why: "Deep code checks stop after a few minutes so you get results quickly. Press Check again and Lockdown starts with these projects.",
      evidence: names.slice(0, 8).join(", ") + (names.length > 8 ? ` and ${names.length - 8} more` : ""),
    });
  }
}

/** Deep code checks (leaked keys, unsafe code) get this long in one scan. */
const CODE_BUDGET_MS = Number(process.env.LOCKDOWN_CODE_BUDGET_MS) || 5 * 60_000;

const report = (ctx: ScanCtx, r: RepoMeta, f: F) => ctx.report({ layer: "code", ...f }, `repo:${r.path}`);

async function gitleaksRepo(ctx: ScanCtx, r: RepoMeta): Promise<void | string> {
  const bin = await ensureTool("gitleaks");
  if (!bin) return "gitleaks isn't available for this computer";
  const out = join(dataDir("tmp"), `gitleaks-${hash(r.path)}.json`);
  const res = await run(bin, ["git", r.path, "--report-format", "json", "--report-path", out, "--no-banner", "--log-level", "error", "--max-target-megabytes", "5"], { timeoutMs: 240_000 });
  if (res.timedOut) return "took too long; skipped";
  let leaks: any[] = [];
  try {
    leaks = JSON.parse(readFileSync(out, "utf8"));
  } catch {
    leaks = [];
  }
  if (!leaks.length) return;
  const tracked = new Set((await run("git", ["-C", r.path, "ls-files"], { timeoutMs: 30_000 })).stdout.split(/\r?\n/));
  // Group by secret so one key committed many times is one finding.
  const bySecret = new Map<string, any[]>();
  for (const l of leaks) {
    const k = `${l.RuleID}:${hash(l.Secret ?? l.Match ?? "")}`;
    (bySecret.get(k) ?? bySecret.set(k, []).get(k)!).push(l);
  }
  const me = await myLogin();
  const theirs = r.gh && me && r.gh.owner.toLowerCase() !== me.toLowerCase();
  for (const [, group] of bySecret) {
    const l = group[0];
    const secret = String(l.Secret ?? "");
    if (/example|sample|dummy|test|fake|xxxx|placeholder|your[_-]?(api[_-]?)?key/i.test(`${secret} ${l.File}`) && !/live/i.test(secret)) continue;
    const files = [...new Set(group.map((g) => g.File as string))];
    if (looksFake(secret)) continue;
    // Test fixtures hold made-up keys; real ones in tests still show up when they live in .env files.
    if (files.every((f) => /(^|\/)(tests?|__tests__|spec|fixtures?|mocks?)\/|\.(test|spec)\.[cm]?[jt]sx?$|secret-?scan/i.test(f))) continue;
    // Docs, lockfiles and fixtures are where generic rules guess wrong most.
    if (files.every((f) => /\.(md|mdx|txt|lock|snap|svg)$|(^|\/)(docs?|fixtures?|__tests__|tests?|examples?)\//i.test(f)) && l.RuleID === "generic-api-key") continue;
    const inHead = files.filter((f) => tracked.has(f));
    const pub = r.gh && !r.gh.private;
    const rule = SECRET_RULES.find((x) => l.RuleID?.toLowerCase().includes(x.id));
    // A provider-specific match (Stripe, GitHub, AWS...) is confirmed; gitleaks' generic rule is a guess.
    const confirmed = l.RuleID !== "generic-api-key" || SECRET_RULES.some((x) => x.id !== "bearer-cli" && new RegExp(x.re.source).test(secret));
    const isEnv = files.some((f) => /(^|\/)\.env(\.|$)/.test(f));
    let sev: Severity = pub ? "critical" : inHead.length ? "high" : "medium";
    if (!confirmed) sev = pub ? "high" : "medium";
    if (theirs) sev = "low";
    report(ctx, r, {
      check: "code.secret",
      severity: sev,
      title: `${confirmed ? prettyRule(l.RuleID) : "Something that looks like a key"} ${inHead.length ? "committed in" : "in the history of"} ${r.name}`,
      why: theirs
        ? `This is ${r.gh!.owner}'s repo, cloned onto this computer. The key is theirs, but don't reuse anything from it.`
        : pub
          ? "This repo is public. Bots scrape GitHub for keys within minutes of a push, so assume this key is already in someone else's hands."
          : "Anyone who gets read access to this repo, or a copy of it, gets this key. It stays in git history even after the file changes.",
      where: `${r.name}/${files[0]}${files.length > 1 ? ` (+${files.length - 1} more)` : ""}`,
      evidence: `${redact(secret)} · ${group.length} commit${group.length > 1 ? "s" : ""}, first ${String(l.Date ?? "").slice(0, 10)}`,
      source: "gitleaks",
      fix: theirs
        ? { fixer: "none", action: "Nothing to do unless you use this key", params: {}, manual: "If you copied this key into your own projects, replace it." }
        : isEnv && inHead.length
          ? { fixer: "git.untrack", action: `Stop tracking ${inHead.join(", ")} and ignore it`, pr: true, params: { repo: r.path, files: inHead.filter((f) => /\.env/.test(f)) }, manual: rotateText(rule) }
          : ctx.prefs.rewriteHistory
            ? { fixer: "git.purge-history", action: "Rotate the key, then remove it from git history", pr: false, params: { repo: r.path, secretHash: hash(secret) }, manual: rotateText(rule) }
            : { fixer: "none", action: "Replace this key", params: { url: rule?.rotate }, manual: rotateText(rule) },
    });
  }
}

/** Invented values: long runs of one character, counting sequences, or one chunk repeated. */
export function looksFake(secret: string): boolean {
  const body = secret.replace(/^(sk_(live|test)_|rk_live_|ghp_|gho_|github_pat_|xox[abposr]-|sk-(ant-api\d\d-|proj-)?|AKIA|AIza|eyJ)/, "");
  if (/(.){3,}/.test(body) || /0123456|abcdefg|ABCDEFG|EXAMPLE|xxxx/i.test(body) || /(.{3,6}){2,}/.test(body)) return true;
  const freq = new Map<string, number>();
  for (const ch of body) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let h = 0;
  for (const n of freq.values()) h -= (n / body.length) * Math.log2(n / body.length);
  return body.length >= 16 && h < 3;
}

let loginP: Promise<string | null> | null = null;
function myLogin() {
  return (loginP ??= gh("/user").then((r) => (r.status === 200 ? r.data.login : null)).catch(() => null));
}

function prettyRule(id: string) {
  const m: Record<string, string> = { "generic-api-key": "An API key", "private-key": "A private key", "aws-access-token": "An AWS key", "github-pat": "A GitHub token", "stripe-access-token": "A Stripe key", "gcp-api-key": "A Google API key", "openai-api-key": "An OpenAI key", "jwt": "A login token (JWT)", "slack-bot-token": "A Slack token" };
  return m[id] ?? `A ${id.replace(/-/g, " ").replace(/\b(api|aws|gcp|jwt|pat)\b/gi, (s) => s.toUpperCase())}`;
}
function rotateText(rule?: { name: string; rotate?: string }) {
  return rule?.rotate ? `Make a new ${rule.name} at ${rule.rotate}, update your app, then delete the old one.` : "Make a new key at the provider, update your app, then delete the old one.";
}

async function osvAll(ctx: ScanCtx, repos: RepoMeta[]): Promise<void | string> {
  const bin = await ensureTool("osv-scanner");
  if (!bin) return "OSV-Scanner isn't available for this computer";
  const out = join(dataDir("tmp"), `osv-${ctx.runId}.json`);
  await run(bin, ["scan", "source", "--format", "json", "--output", out, "-r", ...repos.map((r) => r.path)], { timeoutMs: 600_000 });
  let data: any;
  try {
    data = JSON.parse(readFileSync(out, "utf8"));
  } catch {
    return "couldn't read OSV results";
  }
  // One finding per repo, covering every lockfile in it.
  const byRepo = new Map<RepoMeta, { lockfiles: string[]; pkgs: Map<string, { name: string; version: string; ids: string[]; sev: number; fixed?: string }> }>();
  for (const res of data.results ?? []) {
    const src: string = norm(res.source?.path ?? "");
    const repo = repos.filter((r) => src.startsWith(norm(r.path) + "/")).sort((a, b) => b.path.length - a.path.length)[0];
    if (!repo || !(res.packages ?? []).length) continue;
    const g = byRepo.get(repo) ?? byRepo.set(repo, { lockfiles: [], pkgs: new Map() }).get(repo)!;
    g.lockfiles.push(src.slice(norm(repo.path).length + 1));
    for (const p of res.packages ?? []) {
      const maxSev = Math.max(0, ...(p.groups ?? []).map((x: any) => Number(x.max_severity) || 0));
      const fixed = (p.vulnerabilities ?? []).flatMap((v: any) => (v.affected ?? []).flatMap((a: any) => (a.ranges ?? []).flatMap((rg: any) => (rg.events ?? []).map((e: any) => e.fixed).filter(Boolean))))[0];
      const key = `${p.package?.name}@${p.package?.version}`;
      if (!g.pkgs.has(key)) g.pkgs.set(key, { name: p.package?.name, version: p.package?.version, ids: (p.groups ?? []).map((x: any) => x.aliases?.find((a: string) => a.startsWith("CVE")) ?? x.ids?.[0]).filter(Boolean), sev: maxSev, fixed });
    }
  }
  for (const [repo, g] of byRepo) {
    const pkgs = [...g.pkgs.values()].sort((a, b) => b.sev - a.sev);
    const worst = pkgs[0]?.sev ?? 0;
    const sev: Severity = worst >= 9 ? "critical" : worst >= 7 ? "high" : worst >= 4 ? "medium" : "low";
    const vulnCount = pkgs.reduce((n, p) => n + p.ids.length, 0);
    const npmLocks = g.lockfiles.filter((l) => /(^|\/)package-lock\.json$/.test(l) && !/node_modules/.test(l));
    report(ctx, repo, {
      check: "code.deps",
      severity: sev,
      title: `${pkgs.length} package${pkgs.length > 1 ? "s" : ""} with known holes in ${repo.name}`,
      why: "These versions have published attacks. Bots scan for apps running them.",
      where: `${repo.name}/${g.lockfiles[0]}${g.lockfiles.length > 1 ? ` (+${g.lockfiles.length - 1} more)` : ""}`,
      evidence: pkgs.slice(0, 3).map((p) => `${p.name}@${p.version}${p.ids[0] ? ` (${p.ids[0]})` : ""}`).join(", ") + (vulnCount > 3 ? ` +${vulnCount - 3} more` : ""),
      source: "OSV-Scanner",
      fix: npmLocks.length
        ? { fixer: "deps.npm", action: "Upgrade the affected packages", pr: true, params: { repo: repo.path, lockfile: npmLocks[0], lockfiles: npmLocks, packages: pkgs.map((p) => p.name) } }
        : { fixer: "none", action: "Upgrade the affected packages", params: {}, manual: `Upgrade ${pkgs.slice(0, 3).map((p) => `${p.name} to ${p.fixed ?? "the latest version"}`).join(", ")}.` },
    });
  }
}

async function opengrepRepo(ctx: ScanCtx, repo: RepoMeta): Promise<void | string> {
  return opengrepAll(ctx, [repo], 120_000);
}

async function opengrepAll(ctx: ScanCtx, repos: RepoMeta[], timeoutMs = 900_000): Promise<void | string> {
  const bin = await ensureTool("opengrep");
  if (!bin) return "Opengrep isn't available for this computer";
  const rules = join(dataDir("tmp"), "lockdown-rules.yml");
  writeFileSync(rules, rulesYml);
  const out = join(dataDir("tmp"), `opengrep-${ctx.runId}-${hash(repos.map((x) => x.path).join("|"))}.json`);
  const r = await run(bin, ["scan", "--config", rules, "--json", "--output", out, "--quiet", "--timeout", "10", "--max-target-bytes", "1000000", "--exclude", "*.min.js", "--exclude", "dist", "--exclude", "build", "--exclude", ".next", "--exclude", "test*", "--exclude", "*.test.*", "--exclude", "*.spec.*", ...repos.map((x) => x.path)], { timeoutMs });
  let data: any;
  try {
    data = JSON.parse(readFileSync(out, "utf8"));
    const fatal = (data.errors ?? []).find((e: any) => e.level === "error" && /config|YAML|rule/i.test(e.message ?? ""));
    if (fatal) return `Opengrep rules error: ${String(fatal.message).slice(0, 160)}`;
  } catch {
    return `couldn't read Opengrep results${r.stderr ? ": " + r.stderr.slice(0, 120) : ""}`;
  }
  // One finding per rule per repo.
  const groups = new Map<string, { repo: RepoMeta; hits: any[] }>();
  for (const h of data.results ?? []) {
    const p = norm(String(h.path));
    const repo = repos.filter((x) => p.startsWith(norm(x.path) + "/")).sort((a, b) => b.path.length - a.path.length)[0];
    if (!repo) continue;
    const rule = String(h.check_id).split(".").pop()!;
    const k = `${repo.path}|${rule}`;
    (groups.get(k) ?? groups.set(k, { repo, hits: [] }).get(k)!).hits.push(h);
  }
  for (const [k, { repo, hits }] of groups) {
    const h = hits[0];
    const meta = h.extra?.metadata ?? {};
    const rule = k.split("|")[1];
    const files = [...new Set(hits.map((x) => relative(repo.path, x.path).replace(/\\/g, "/")))];
    report(ctx, repo, {
      check: `code.${rule}`,
      severity: (meta.lockdown_severity as Severity) ?? "medium",
      title: `${meta.title ?? rule} in ${repo.name}`,
      why: String(h.extra?.message ?? ""),
      where: `${repo.name}/${files[0]}:${h.start?.line}${hits.length > 1 ? ` (+${hits.length - 1} more)` : ""}`,
      evidence: String(h.extra?.lines ?? "").trim().slice(0, 140),
      source: "Opengrep",
      fix: { fixer: "code.patch", action: "Write a fix and open a pull request", pr: true, params: { repo: repo.path, rule, files, lines: hits.slice(0, 20).map((x) => ({ file: relative(repo.path, x.path).replace(/\\/g, "/"), line: x.start?.line })) } },
    });
  }
}

const CLIENT_PREFIX = /^(NEXT_PUBLIC_|VITE_|EXPO_PUBLIC_|REACT_APP_|PUBLIC_|NUXT_PUBLIC_|GATSBY_)/;
const SERVER_SECRET = /(sk_live_|rk_live_|sk-ant-|sk-proj-|service_role|SECRET|PRIVATE|whsec_|sb_secret_)/;

function reverseChecks(ctx: ScanCtx, r: RepoMeta) {
  const ls = (d: string) => {
    try {
      return readdirSync(d);
    } catch {
      return [];
    }
  };
  const top = ls(r.path);
  const pub = r.gh && !r.gh.private;
  // Source maps in production builds
  for (const f of top.filter((n) => /^vite\.config\.(m?[jt]s)$/.test(n))) {
    const t = readFileSync(join(r.path, f), "utf8");
    if (/sourcemap\s*:\s*(true|['"]inline['"])/.test(t)) {
      report(ctx, r, { check: "code.sourcemaps", severity: "medium", title: `${r.name} ships its source code to the browser`, why: "Source maps let anyone rebuild your original code, comments and all, from the live site.", where: `${r.name}/${f}`, fix: { fixer: "code.config-edit", action: "Turn off production source maps", pr: true, params: { repo: r.path, file: f, find: "sourcemap\\s*:\\s*(true|['\"]inline['\"])", replace: "sourcemap: false" } } });
    }
  }
  for (const f of top.filter((n) => /^next\.config\.(m?[jt]s)$/.test(n))) {
    const t = readFileSync(join(r.path, f), "utf8");
    if (/productionBrowserSourceMaps\s*:\s*true/.test(t)) {
      report(ctx, r, { check: "code.sourcemaps", severity: "medium", title: `${r.name} ships its source code to the browser`, why: "Source maps let anyone rebuild your original code from the live site.", where: `${r.name}/${f}`, fix: { fixer: "code.config-edit", action: "Turn off production source maps", pr: true, params: { repo: r.path, file: f, find: "productionBrowserSourceMaps\\s*:\\s*true", replace: "productionBrowserSourceMaps: false" } } });
    }
  }
  // Server secrets in browser-exposed env vars
  for (const f of top.filter((n) => /^\.env(\.|$)/.test(n) && !/example|sample|template/.test(n))) {
    if (fileSize(join(r.path, f)) > 100_000) continue;
    for (const line of readFileSync(join(r.path, f), "utf8").split(/\r?\n/)) {
      const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*["']?([^"'\s#]+)/);
      if (!m || !CLIENT_PREFIX.test(m[1])) continue;
      const jwtRole = m[2].split(".").length === 3 ? safeJwtRole(m[2]) : null;
      if (SERVER_SECRET.test(m[1].replace(CLIENT_PREFIX, "")) || SERVER_SECRET.test(m[2]) || jwtRole === "service_role") {
        report(ctx, r, {
          check: "code.client-secret",
          severity: "critical",
          title: `A server secret is built into ${r.name}'s website code`,
          why: `${m[1]} starts with a prefix that copies it into the JavaScript every visitor downloads. Anyone can open the browser tools and take it.`,
          where: `${r.name}/${f}`,
          evidence: `${m[1]}=${redact(m[2])}`,
          fix: { fixer: "none", action: "Move it to the server", params: {}, manual: `Rename ${m[1]} without the public prefix, use it only in server code, and make a new key since the old one has been public.` },
        });
      }
    }
  }
  // Map files committed into public folders
  const maps = walk(r.path, { maxDepth: 3, match: (n, _f, d) => !d && /\.js\.map$/.test(n), limit: 50, skipDirs: new Set(["node_modules", ".git", ".next", "target"]) });
  if (maps.length) {
    report(ctx, r, { check: "code.map-files", severity: pub ? "medium" : "low", title: `${maps.length} source map file${maps.length > 1 ? "s" : ""} sitting in ${r.name}`, why: "If these get deployed, anyone can rebuild your original source from them.", where: shortPath(maps[0]), fix: { fixer: "none", action: "Delete them and stop generating them for production", params: {}, manual: "Delete the .map files and turn off source maps in your production build." } });
  }
  // Electron apps shipped without asar
  const pkg = safeJson(join(r.path, "package.json"));
  if (pkg?.build && pkg.build.asar === false) {
    report(ctx, r, { check: "code.electron-asar", severity: "medium", title: `${r.name} ships its desktop app code as loose files`, why: "Anyone who installs the app can read and change all of its code.", where: `${r.name}/package.json`, fix: { fixer: "none", action: "Package the app with asar", params: {}, manual: "Remove \"asar\": false from the build settings." } });
  }
}

function configChecks(ctx: ScanCtx, r: RepoMeta) {
  // .env present but not ignored
  const envs = readdirSafe(r.path).filter((n) => /^\.env(\.local|\.production|\.development)?$/.test(n));
  const gi = existsSync(join(r.path, ".gitignore")) ? readFileSync(join(r.path, ".gitignore"), "utf8") : "";
  if (envs.length && !/^\s*\/?\.env(\*|\.\*|\.local)?\s*$/m.test(gi) && !/^\s*\*\.env|^\s*\.env.*$/m.test(gi)) {
    report(ctx, r, { check: "code.gitignore-env", severity: "medium", title: `${r.name} doesn't ignore .env files`, why: "One 'git add .' and your keys are in the repo forever.", where: `${r.name}/.gitignore`, fix: { fixer: "git.gitignore", action: "Add .env files to .gitignore", pr: true, params: { repo: r.path, lines: [".env", ".env.*", "!.env.example"] } } });
  }
  // Firebase security rules left open
  for (const f of ["firestore.rules", "storage.rules", "database.rules.json"]) {
    const p = join(r.path, f);
    if (!existsSync(p)) continue;
    const t = readFileSync(p, "utf8");
    if (/allow\s+(read|write|read,\s*write|write,\s*read)\s*:\s*if\s+true\s*;/.test(t) || /request\.time\s*<\s*timestamp\.date\(/.test(t) || /"\.(read|write)"\s*:\s*true/.test(t)) {
      report(ctx, r, { check: "code.firebase-open", severity: "critical", title: `${r.name}'s Firebase ${f.replace(/\..*/, "")} rules let anyone in`, why: "Anyone with your project ID (it's in your website's code) can read, change or delete this data.", where: `${r.name}/${f}`, fix: { fixer: "none", action: "Require sign-in in your rules", params: {}, manual: "Change the rules to check request.auth, then deploy them with firebase deploy --only firestore:rules." } });
    }
  }
  // GitHub Actions workflows
  const wfDir = join(r.path, ".github", "workflows");
  for (const f of readdirSafe(wfDir).filter((n) => /\.ya?ml$/.test(n))) {
    const t = readFileSync(join(wfDir, f), "utf8");
    const where = `${r.name}/.github/workflows/${f}`;
    if (/pull_request_target/.test(t) && /ref:\s*\$\{\{\s*github\.event\.pull_request\.head\.(sha|ref)/.test(t)) {
      report(ctx, r, { check: "code.gha-prt", layer: "github", severity: "critical", title: `Workflow ${f} runs strangers' code with your secrets`, why: "pull_request_target plus checking out the PR's code lets anyone who opens a pull request steal your repo's secrets.", where, fix: { fixer: "none", action: "Use pull_request instead", params: {}, manual: "Switch the trigger to pull_request, or don't check out the PR's code in that job." } } as any);
    }
    const inj = t.match(/run:[^\n]*\$\{\{\s*github\.event\.(issue\.title|issue\.body|pull_request\.title|pull_request\.body|comment\.body|review\.body|head_commit\.message|pull_request\.head\.ref)[^}]*\}\}/);
    if (inj) {
      report(ctx, r, { check: "code.gha-injection", layer: "github", severity: "high", title: `Workflow ${f} can be hijacked by an issue or PR title`, why: "Text that anyone can write is pasted straight into a shell command in your workflow.", where, evidence: inj[0].slice(0, 120), fix: { fixer: "none", action: "Pass it through an environment variable", params: {}, manual: "Move ${{ github.event... }} into env: and use \"$VAR\" in the run step." } } as any);
    }
    const unpinned = [...t.matchAll(/uses:\s*([\w.-]+\/[\w.\/-]+)@([\w.-]+)/g)].filter((m) => !/^(actions|github)\//.test(m[1]) && !/^[0-9a-f]{40}$/.test(m[2]));
    if (unpinned.length) {
      report(ctx, r, { check: "code.gha-unpinned", layer: "github", severity: "low", title: `Workflow ${f} uses ${unpinned.length} third-party action${unpinned.length > 1 ? "s" : ""} by tag`, why: "If that action's owner is hacked, the tag can be moved to malicious code that runs with your secrets (this happened to tj-actions/changed-files in 2025).", where, evidence: unpinned.slice(0, 3).map((m) => `${m[1]}@${m[2]}`).join(", "), fix: { fixer: "gha.pin", action: "Pin actions to exact commits", pr: true, params: { repo: r.path, file: f } } } as any);
    }
    const secretsEcho = t.match(/(echo|print|console\.log)[^\n]*\$\{\{\s*secrets\.[A-Z0-9_]+/i);
    if (secretsEcho) {
      report(ctx, r, { check: "code.gha-echo", layer: "github", severity: "medium", title: `Workflow ${f} prints a secret`, why: "Masking misses changed or partial values; printed secrets can end up readable in logs.", where, evidence: secretsEcho[0].slice(0, 100), fix: { fixer: "none", action: "Stop printing secrets", params: {}, manual: "Remove the echo of the secret from the workflow." } } as any);
    }
  }
  // Rate limits on sign-in routes (cheap text check across the repo's server code)
  const files = walk(r.path, { maxDepth: 6, match: (n, _f, d) => !d && /\.(ts|js|mjs)$/.test(n) && !/\.(test|spec|d)\./.test(n), limit: 3000 });
  let authRoute: string | null = null;
  let hasLimiter = false;
  for (const p of files) {
    if (fileSize(p) > 300_000) continue;
    const t = readFileSync(p, "utf8");
    if (/rateLimit|rate-limit|ratelimit|limiter|slowDown|throttle|@upstash\/ratelimit|express-rate-limit/i.test(t)) hasLimiter = true;
    if (!authRoute && /(\.post\(\s*["'`][^"'`]*(login|signin|sign-in|signup|register|verify|otp|forgot|reset)|app\/api\/[^\n]*(login|signin|verify|otp|code)[^\n]*\/route\.(ts|js))/i.test(t + "\n" + p.replace(/\\/g, "/"))) authRoute = p;
  }
  if (authRoute && !hasLimiter) {
    report(ctx, r, { check: "code.no-rate-limit", severity: "medium", title: `${r.name}'s sign-in has no rate limit`, why: "Bots can try thousands of passwords or one-time codes a minute until one works.", where: shortPath(authRoute), fix: { fixer: "code.patch", action: "Add a rate limit to sign-in routes", pr: true, params: { repo: r.path, rule: "no-rate-limit", files: [relative(r.path, authRoute).replace(/\\/g, "/")] } } });
  }
}

const norm = (p: string) => p.replace(/\\/g, "/").replace(/\/+$/, "").toLowerCase();

function readdirSafe(d: string) {
  try {
    return readdirSync(d);
  } catch {
    return [];
  }
}
function safeJson(p: string): any {
  try {
    return JSON.parse(readFileSync(p, "utf8"));
  } catch {
    return null;
  }
}
function safeJwtRole(t: string): string | null {
  try {
    return JSON.parse(Buffer.from(t.split(".")[1], "base64url").toString()).role ?? null;
  } catch {
    return null;
  }
}
// Re-exported for the fixers so repo-level secret checks agree with scan-time ones.
export { findSecrets };

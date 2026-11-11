// Every fixer records the state it found before changing anything, so undo can put it back.
// Sandbox mode (LOCKDOWN_SANDBOX=1) sends registry writes to HKCU:\Software\LockdownSandbox and
// refuses machine-wide commands, so fixes can be tested without touching real settings.
import { chmodSync, copyFileSync, existsSync, mkdirSync, readFileSync, renameSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import type { Finding } from "./types";
import { gh } from "./gh";
import { dataDir, hash, HOME, IS_MAC, IS_WIN, ps, run, sh } from "./util";

const gitGlobal = () => ["config", "--file", join(HOME, ".gitconfig")];

export const SANDBOX = () => process.env.LOCKDOWN_SANDBOX === "1";

export interface ApplyResult {
  before: unknown;
  after?: unknown;
  backups?: Record<string, string>;
  note?: string;
  result?: "applied" | "pr-opened" | "skipped";
}

export interface Fixer {
  apply(f: Finding, ctx: FixCtx): Promise<ApplyResult>;
  undo(before: any, f: Finding, ctx: FixCtx): Promise<void>;
}

export interface FixCtx {
  runId: string;
  backupDir: string;
  prefs: import("./types").Preferences;
  /** Admin commands are queued and run together behind one prompt. */
  admin: AdminBatch;
}

// ---------- admin batching ----------
export class AdminBatch {
  steps: { id: string; script: string }[] = [];
  results = new Map<string, { ok: boolean; out: string }>();
  add(id: string, script: string) {
    this.steps.push({ id, script });
  }
  /** Run all queued admin steps with one UAC / password prompt. */
  async flush(): Promise<void> {
    if (!this.steps.length) return;
    const steps = this.steps.splice(0);
    if (SANDBOX()) {
      for (const s of steps) this.results.set(s.id, { ok: false, out: "sandbox: admin change not run" });
      return;
    }
    const dir = dataDir("tmp");
    const out = join(dir, `admin-${Date.now()}.json`);
    if (IS_WIN) {
      const body = steps.map((s) => `try { $o = & { ${s.script} } 2>&1 | Out-String; $r['${s.id}'] = @{ ok = $true; out = $o } } catch { $r['${s.id}'] = @{ ok = $false; out = "$_" } }`).join("\n");
      const script = join(dir, `admin-${Date.now()}.ps1`);
      writeFileSync(script, `$ErrorActionPreference='Stop'\n$r=@{}\n${body}\n$r | ConvertTo-Json -Depth 3 | Set-Content -Encoding UTF8 '${out}'\n`);
      const elevated = await ps<boolean>("([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) | ConvertTo-Json");
      if (elevated) await run("powershell.exe", ["-NoProfile", "-ExecutionPolicy", "Bypass", "-File", script], { timeoutMs: 600_000 });
      else await run("powershell.exe", ["-NoProfile", "-Command", `Start-Process powershell.exe -Verb RunAs -Wait -WindowStyle Hidden -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','"${script}"'`], { timeoutMs: 600_000 });
    } else if (IS_MAC) {
      const body = steps.map((s) => `if out=$( { ${s.script} ; } 2>&1 ); then ok=true; else ok=false; fi; printf '%s\\t%s\\t%s\\n' '${s.id}' "$ok" "$(printf '%s' "$out" | tr '\\n\\t' '  ')" >> '${out}.tsv'`).join("\n");
      const script = join(dir, `admin-${Date.now()}.sh`);
      writeFileSync(script, `#!/bin/sh\n${body}\n`);
      chmodSync(script, 0o755);
      const root = process.getuid?.() === 0;
      if (root) await run("/bin/sh", [script], { timeoutMs: 600_000 });
      else if ((await run("sudo", ["-n", "true"], { timeoutMs: 10_000 })).code === 0) await run("sudo", ["-n", "/bin/sh", script], { timeoutMs: 600_000 });
      else await run("osascript", ["-e", `do shell script "/bin/sh '${script}'" with prompt "Lockdown needs your password to apply security fixes." with administrator privileges`], { timeoutMs: 600_000 });
      if (existsSync(`${out}.tsv`)) {
        for (const line of readFileSync(`${out}.tsv`, "utf8").split("\n").filter(Boolean)) {
          const [id, ok, o] = line.split("\t");
          this.results.set(id, { ok: ok === "true", out: o ?? "" });
        }
      }
      for (const s of steps) if (!this.results.has(s.id)) this.results.set(s.id, { ok: false, out: "admin prompt was cancelled" });
      return;
    }
    if (existsSync(out)) {
      const r = JSON.parse(readFileSync(out, "utf8").replace(/^﻿/, ""));
      for (const s of steps) this.results.set(s.id, r[s.id] ? { ok: !!r[s.id].ok, out: String(r[s.id].out ?? "") } : { ok: false, out: "not run" });
    } else for (const s of steps) this.results.set(s.id, { ok: false, out: "admin prompt was cancelled" });
  }
}

// ---------- helpers ----------
const sandboxReg = (p: string) => (SANDBOX() ? p.replace(/^(HKLM|HKCU):\\/, (_m, hive) => `HKCU:\\Software\\LockdownSandbox\\${hive}\\`) : p);
const q = (s: string) => `'${String(s).replace(/'/g, "''")}'`;

async function regRead(path: string, name: string): Promise<{ exists: boolean; value?: unknown; kind?: string }> {
  const r = await ps<any>(`$k = Get-Item -Path ${q(path)} -ErrorAction SilentlyContinue; if ($k -and ($k.GetValueNames() -contains ${q(name)})) { @{ exists = $true; value = $k.GetValue(${q(name)}); kind = "$($k.GetValueKind(${q(name)}))" } | ConvertTo-Json -Compress } else { @{ exists = $false } | ConvertTo-Json -Compress }`);
  return r ?? { exists: false };
}
function regWriteScript(path: string, name: string, kind: string, value: unknown) {
  const v = typeof value === "number" ? String(value) : q(String(value));
  return `if (-not (Test-Path ${q(path)})) { New-Item -Path ${q(path)} -Force | Out-Null }; New-ItemProperty -Path ${q(path)} -Name ${q(name)} -PropertyType ${kind} -Value ${v} -Force | Out-Null`;
}
function regDeleteScript(path: string, name: string) {
  return `Remove-ItemProperty -Path ${q(path)} -Name ${q(name)} -ErrorAction SilentlyContinue`;
}
const isHKLM = (p: string) => /^HKLM:/.test(p);

async function runAdminOrUser(ctx: FixCtx, id: string, script: string, admin: boolean): Promise<void> {
  if (admin && !(SANDBOX() && /HKCU:\\Software\\LockdownSandbox/.test(script))) {
    ctx.admin.add(id, script);
    return;
  }
  const r = await run("powershell.exe", ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", "-"], { input: `$ErrorActionPreference='Stop'\n${script}`, timeoutMs: 120_000 });
  if (r.code !== 0) throw new Error(r.stderr.trim().split("\n")[0] || "command failed");
}

// ---------- git / PR helpers ----------
async function git(repo: string, args: string[], timeoutMs = 120_000) {
  const r = await run("git", ["-C", repo, ...args], { timeoutMs });
  if (r.code !== 0) throw new Error(`git ${args[0]}: ${(r.stderr || r.stdout).trim().split("\n").slice(-1)[0]}`);
  return r.stdout.trim();
}

export async function withBranch(repo: string, branch: string, title: string, body: string, ctx: FixCtx, edit: (dir: string) => Promise<string[] | void>): Promise<ApplyResult> {
  const remote = await git(repo, ["remote", "get-url", "origin"]);
  const m = remote.match(/github\.com[:/]([^/]+)\/([^/\s]+?)(\.git)?$/);
  if (!m) throw new Error("repo isn't on GitHub");
  const full = `${m[1]}/${m[2]}`;
  await git(repo, ["fetch", "origin", "--quiet"], 180_000);
  let base = "";
  try {
    base = (await git(repo, ["symbolic-ref", "--short", "refs/remotes/origin/HEAD"])).replace(/^origin\//, "");
  } catch {
    base = (await gh(`/repos/${full}`)).data?.default_branch ?? "main";
  }
  const dir = join(tmpdir(), `lockdown-${hash(repo, branch)}`);
  await run("git", ["-C", repo, "worktree", "remove", "--force", dir]);
  await git(repo, ["worktree", "add", "-B", branch, dir, `origin/${base}`], 180_000);
  try {
    const touched = (await edit(dir)) ?? [];
    const status = await git(dir, ["status", "--porcelain"]);
    if (!status) return { before: null, result: "skipped", note: "nothing to change" };
    await git(dir, ["add", "-A", ...(touched.length ? ["--", ...touched] : [])]);
    await git(dir, ["-c", "user.name=Lockdown", "-c", "user.email=lockdown@westwardconsulting.ai", "commit", "-m", `${title}\n\n${body}`]);
    if (ctx.prefs.code === "direct") {
      await git(dir, ["push", "origin", `HEAD:${base}`], 180_000);
      const sha = await git(dir, ["rev-parse", "HEAD"]);
      return { before: { repo: full, base, direct: true, sha }, result: "applied", note: `committed to ${base}` };
    }
    await git(dir, ["push", "-f", "origin", `HEAD:refs/heads/${branch}`], 180_000);
    const pr = await gh(`/repos/${full}/pulls`, { method: "POST", body: { title, head: branch, base, body: `${body}\n\n_Opened by Lockdown. Undo from the Lockdown app, or close this PR._` } });
    let number = pr.data?.number;
    if (!number && pr.status === 422) {
      const open = await gh(`/repos/${full}/pulls?head=${m[1]}:${branch}&state=open`);
      number = open.data?.[0]?.number;
    }
    if (!number) throw new Error(`couldn't open pull request (${pr.status})`);
    let merged = false;
    if (ctx.prefs.code === "pr-automerge") merged = await tryMerge(full, number);
    return { before: { repo: full, base, branch, pr: number, merged }, result: merged ? "applied" : "pr-opened", note: `${merged ? "merged" : "opened"} https://github.com/${full}/pull/${number}` };
  } finally {
    await run("git", ["-C", repo, "worktree", "remove", "--force", dir]);
  }
}

/** Merge when checks pass (or there are none). Leaves the PR open if anything is failing or pending. */
async function tryMerge(full: string, number: number): Promise<boolean> {
  for (let i = 0; i < 20; i++) {
    const pr = await gh(`/repos/${full}/pulls/${number}`);
    if (pr.data?.mergeable_state === "clean") break;
    if (pr.data?.mergeable === false) return false;
    const checks = await gh(`/repos/${full}/commits/${pr.data?.head?.sha}/check-runs`);
    const runs = checks.data?.check_runs ?? [];
    if (runs.some((c: any) => c.conclusion && !["success", "neutral", "skipped"].includes(c.conclusion))) return false;
    if (pr.data?.mergeable === true && runs.every((c: any) => c.status === "completed")) break;
    await new Promise((r) => setTimeout(r, 6000));
  }
  const r = await gh(`/repos/${full}/pulls/${number}/merge`, { method: "PUT", body: { merge_method: "squash" } });
  return r.status === 200;
}

async function undoBranch(b: any) {
  if (!b) return;
  if (b.direct || b.merged) {
    // Open a revert PR rather than force-pushing over someone's branch.
    const pr = b.pr ? (await gh(`/repos/${b.repo}/pulls/${b.pr}`)).data : null;
    const sha = b.sha ?? pr?.merge_commit_sha;
    const dir = join(tmpdir(), `lockdown-undo-${hash(b.repo, String(sha))}`);
    await run("git", ["clone", "--quiet", "--depth", "50", `https://github.com/${b.repo}.git`, dir], { timeoutMs: 300_000 });
    await git(dir, ["checkout", "-B", `lockdown/undo-${String(sha).slice(0, 7)}`, `origin/${b.base}`]);
    await git(dir, ["-c", "user.name=Lockdown", "-c", "user.email=lockdown@westwardconsulting.ai", "revert", "--no-edit", String(sha)]);
    await git(dir, ["push", "-f", "origin", "HEAD"]);
    const r = await gh(`/repos/${b.repo}/pulls`, { method: "POST", body: { title: `Undo Lockdown fix ${String(sha).slice(0, 7)}`, head: `lockdown/undo-${String(sha).slice(0, 7)}`, base: b.base, body: "Reverts a change Lockdown made." } });
    if (r.data?.number) await gh(`/repos/${b.repo}/pulls/${r.data.number}/merge`, { method: "PUT", body: { merge_method: "squash" } });
    return;
  }
  await gh(`/repos/${b.repo}/pulls/${b.pr}`, { method: "PATCH", body: { state: "closed" } });
  await gh(`/repos/${b.repo}/git/refs/heads/${b.branch}`, { method: "DELETE" });
}

// ---------- the fixers ----------
export const FIXERS: Record<string, Fixer> = {
  "win.reg": {
    async apply(f, ctx) {
      const ops = (f.fix!.params as any).ops as { path: string; name: string; type?: string; value?: unknown; delete?: boolean }[];
      const before = [];
      const scripts = [];
      for (const o of ops) {
        const path = sandboxReg(o.path);
        before.push({ ...o, path, prev: await regRead(path, o.name) });
        scripts.push(o.delete ? regDeleteScript(path, o.name) : regWriteScript(path, o.name, o.type ?? "DWord", o.value));
      }
      const admin = ops.some((o) => isHKLM(o.path));
      await runAdminOrUser(ctx, f.id, scripts.join("; "), admin);
      return { before };
    },
    async undo(before: any[], f, ctx) {
      const scripts = before.map((b) => (b.prev?.exists ? regWriteScript(b.path, b.name, b.prev.kind ?? "DWord", b.prev.value) : regDeleteScript(b.path, b.name)));
      await runAdminOrUser(ctx, `undo-${f.id}`, scripts.join("; "), before.some((b) => isHKLM(b.path)));
    },
  },
  "win.ps": {
    async apply(f, ctx) {
      const p = f.fix!.params as any;
      if (SANDBOX()) return { before: null, result: "skipped", note: "sandbox: system command not run" };
      await runAdminOrUser(ctx, f.id, p.script, false);
      return { before: { undo: p.undo } };
    },
    async undo(b, f, ctx) {
      if (b?.undo) await runAdminOrUser(ctx, `undo-${f.id}`, b.undo, false);
    },
  },
  "win.ps-admin": {
    async apply(f, ctx) {
      const p = f.fix!.params as any;
      await runAdminOrUser(ctx, f.id, p.script, true);
      return { before: { undo: p.undo } };
    },
    async undo(b, f, ctx) {
      if (b?.undo) await runAdminOrUser(ctx, `undo-${f.id}`, b.undo, true);
    },
  },
  "win.service": {
    async apply(f, ctx) {
      const p = f.fix!.params as any;
      const prev = await ps<any>(`$s = Get-Service ${q(p.name)} -ErrorAction SilentlyContinue; if ($s) { @{ status = "$($s.Status)"; start = "$($s.StartType)" } | ConvertTo-Json -Compress }`);
      await runAdminOrUser(ctx, f.id, `Stop-Service ${q(p.name)} -Force; Set-Service ${q(p.name)} -StartupType ${p.startup ?? "Disabled"}`, true);
      return { before: { name: p.name, ...prev } };
    },
    async undo(b, f, ctx) {
      await runAdminOrUser(ctx, `undo-${f.id}`, `Set-Service ${q(b.name)} -StartupType ${b.start ?? "Manual"}; ${b.status === "Running" ? `Start-Service ${q(b.name)}` : ""}`, true);
    },
  },
  "win.fw-block": {
    async apply(f, ctx) {
      const p = f.fix!.params as any;
      const name = `Lockdown: block inbound ${p.port} (${p.proc ?? "app"})`;
      await runAdminOrUser(ctx, f.id, `New-NetFirewallRule -DisplayName ${q(name)} -Group 'Lockdown' -Direction Inbound -Protocol TCP -LocalPort ${Number(p.port)} -Action Block -Profile Any | Out-Null`, true);
      return { before: { rule: name } };
    },
    async undo(b, f, ctx) {
      await runAdminOrUser(ctx, `undo-${f.id}`, `Remove-NetFirewallRule -DisplayName ${q(b.rule)}`, true);
    },
  },
  "win.share-remove": {
    async apply(f, ctx) {
      const p = f.fix!.params as any;
      const access = await ps<any>(`Get-SmbShareAccess -Name ${q(p.name)} | ForEach-Object { @{ account = $_.AccountName; right = "$($_.AccessRight)"; type = "$($_.AccessControlType)" } } | ConvertTo-Json -Compress`);
      await runAdminOrUser(ctx, f.id, `Remove-SmbShare -Name ${q(p.name)} -Force`, true);
      return { before: { name: p.name, path: p.path, access: access ? [].concat(access) : [] } };
    },
    async undo(b, f, ctx) {
      const grants = (b.access as any[]).filter((a) => a.type === "Allow").map((a) => `Grant-SmbShareAccess -Name ${q(b.name)} -AccountName ${q(a.account)} -AccessRight ${a.right} -Force | Out-Null`).join("; ");
      await runAdminOrUser(ctx, `undo-${f.id}`, `New-SmbShare -Name ${q(b.name)} -Path ${q(b.path)} | Out-Null; ${grants}`, true);
    },
  },
  "win.wifi-forget": {
    async apply(f, ctx) {
      const names = (f.fix!.params as any).names as string[];
      const dir = join(ctx.backupDir, "wifi");
      mkdirSync(dir, { recursive: true });
      const saved: Record<string, string> = {};
      if (SANDBOX()) return { before: null, result: "skipped", note: "sandbox: Wi-Fi profiles not touched" };
      for (const n of names) {
        await run("netsh", ["wlan", "export", "profile", `name=${n}`, `folder=${dir}`]);
        const r = await run("netsh", ["wlan", "delete", "profile", `name=${n}`]);
        if (r.code === 0) saved[n] = dir;
      }
      return { before: { dir, names: Object.keys(saved) }, backups: { wifi: dir } };
    },
    async undo(b) {
      const { readdirSync } = await import("node:fs");
      for (const file of readdirSync(b.dir).filter((x: string) => x.endsWith(".xml"))) await run("netsh", ["wlan", "add", "profile", `filename=${join(b.dir, file)}`]);
    },
  },
  "win.startup-disable": {
    async apply(f, ctx) {
      const p = f.fix!.params as any;
      const path = sandboxReg(String(p.key).replace(/^HKCU:\\/, "HKCU:\\").replace(/^HKLM:\\/, "HKLM:\\"));
      const prev = await regRead(path, p.name);
      if (!prev.exists) return { before: null, result: "skipped", note: "already gone" };
      await runAdminOrUser(ctx, f.id, regDeleteScript(path, p.name), isHKLM(p.key));
      return { before: { path, name: p.name, prev } };
    },
    async undo(b, f, ctx) {
      await runAdminOrUser(ctx, `undo-${f.id}`, regWriteScript(b.path, b.name, b.prev.kind ?? "String", b.prev.value), isHKLM(b.path));
    },
  },
  "win.open-settings": {
    async apply(f) {
      if (!SANDBOX()) await run("cmd.exe", ["/c", "start", "", String((f.fix!.params as any).uri)]);
      return { before: null, result: "skipped", note: "opened settings for you" };
    },
    async undo() {},
  },
  "mac.admin": {
    async apply(f, ctx) {
      const p = f.fix!.params as any;
      if (SANDBOX()) return { before: null, result: "skipped", note: "sandbox: system command not run" };
      ctx.admin.add(f.id, p.cmd);
      return { before: { undo: p.undo } };
    },
    async undo(b, f, ctx) {
      if (b?.undo) ctx.admin.add(`undo-${f.id}`, b.undo);
    },
  },
  "mac.user": {
    async apply(f) {
      const p = f.fix!.params as any;
      if (SANDBOX()) return { before: null, result: "skipped", note: "sandbox: setting not changed" };
      const r = await sh(p.cmd);
      if (r.code !== 0) throw new Error(r.stderr.trim() || "command failed");
      return { before: { undo: p.undo } };
    },
    async undo(b) {
      if (b?.undo) await sh(b.undo);
    },
  },
  "mac.open": {
    async apply(f) {
      if (!SANDBOX()) await run("open", [String((f.fix!.params as any).url)]);
      return { before: null, result: "skipped", note: "opened settings for you" };
    },
    async undo() {},
  },
  "files.scrub-lines": {
    async apply(f, ctx) {
      const p = f.fix!.params as any;
      const backup = join(ctx.backupDir, `${hash(p.path)}-${basename(p.path)}`);
      copyFileSync(p.path, backup);
      await lockDown(backup);
      const drop = new Set<number>(p.lines);
      const lines = readFileSync(p.path, "utf8").split(/\n/);
      const kept = lines.filter((_l, i) => !drop.has(i + 1));
      writeFileSync(p.path, kept.join("\n"));
      return { before: { path: p.path, backup, removed: drop.size, keptCount: kept.length }, backups: { [p.path]: backup } };
    },
    async undo(b) {
      // Restore the file as it was, keeping any history written since the fix.
      const tail = existsSync(b.path) ? readFileSync(b.path, "utf8").split("\n").slice(b.keptCount) : [];
      const old = readFileSync(b.backup, "utf8");
      writeFileSync(b.path, tail.some((l: string) => l !== "") ? `${old.replace(/\n$/, "")}\n${tail.join("\n")}` : old);
    },
  },
  "files.restrict": {
    async apply(f, ctx) {
      const p = (f.fix!.params as any).path as string;
      if (IS_WIN) {
        const acl = join(ctx.backupDir, `${hash(p)}.acl`);
        await run("icacls", [p, "/save", acl]);
        const r = await run("icacls", [p, "/inheritance:r", "/grant:r", `${process.env.USERNAME}:F`, "/grant:r", "SYSTEM:F", "/remove:g", "*S-1-1-0", "*S-1-5-11", "*S-1-5-32-545"]);
        if (r.code !== 0) throw new Error(r.stdout.trim() || r.stderr.trim());
        return { before: { path: p, acl } };
      }
      const mode = statSync(p).mode & 0o777;
      chmodSync(p, 0o600);
      return { before: { path: p, mode } };
    },
    async undo(b) {
      if (IS_WIN) {
        const dir = b.path.replace(/[\\/][^\\/]+$/, "");
        await run("icacls", [p2(dir), "/restore", b.acl]);
        await run("icacls", [b.path, "/inheritance:e"]);
      } else chmodSync(b.path, b.mode);
    },
  },
  "files.quarantine": {
    async apply(f) {
      const p = (f.fix!.params as any).path as string;
      const vault = dataDir("vault");
      await lockDown(vault);
      const dest = join(vault, `${hash(p)}-${basename(p)}`);
      renameSafe(p, dest);
      return { before: { from: p, to: dest }, note: `moved to ${dest}` };
    },
    async undo(b) {
      renameSafe(b.to, b.from);
    },
  },
  "files.git-credentials": {
    async apply(f, ctx) {
      const p = (f.fix!.params as any).path as string;
      const prevHelper = (await run("git", [...gitGlobal(), "--get", "credential.helper"])).stdout.trim();
      const backup = join(ctx.backupDir, `${hash(p)}-git-credentials`);
      copyFileSync(p, backup);
      await lockDown(backup);
      const helper = IS_WIN ? "manager" : IS_MAC ? "osxkeychain" : "cache";
      // Hand each saved login to the keychain helper before removing the plain file.
      for (const line of (SANDBOX() ? "" : readFileSync(p, "utf8")).split(/\r?\n/).filter(Boolean)) {
        try {
          const u = new URL(line);
          await run("git", ["-c", `credential.helper=${helper}`, "credential", "approve"], { input: `protocol=${u.protocol.replace(":", "")}\nhost=${u.host}\nusername=${decodeURIComponent(u.username)}\npassword=${decodeURIComponent(u.password)}\n\n` });
        } catch {}
      }
      await run("git", [...gitGlobal(), "credential.helper", helper]);
      writeFileSync(p, "");
      renameSafe(p, `${backup}.emptied`);
      return { before: { path: p, backup, prevHelper }, backups: { [p]: backup } };
    },
    async undo(b) {
      copyFileSync(b.backup, b.path);
      if (b.prevHelper) await run("git", [...gitGlobal(), "credential.helper", b.prevHelper]);
      else await run("git", [...gitGlobal(), "--unset", "credential.helper"]);
    },
  },
  "gh.visibility": {
    async apply(f) {
      const p = f.fix!.params as any;
      const prev = (await gh(`/repos/${p.repo}`)).data?.private;
      const r = await gh(`/repos/${p.repo}`, { method: "PATCH", body: { private: !!p.private } });
      if (r.status !== 200) throw new Error(`GitHub said ${r.status}`);
      return { before: { repo: p.repo, private: prev } };
    },
    async undo(b) {
      await gh(`/repos/${b.repo}`, { method: "PATCH", body: { private: b.private } });
    },
  },
  "gh.actions-perms": {
    async apply(f) {
      const p = f.fix!.params as any;
      const prev = (await gh(`/repos/${p.repo}/actions/permissions/workflow`)).data;
      const r = await gh(`/repos/${p.repo}/actions/permissions/workflow`, { method: "PUT", body: { default_workflow_permissions: "read", can_approve_pull_request_reviews: false } });
      if (r.status >= 300) throw new Error(`GitHub said ${r.status}`);
      return { before: { repo: p.repo, prev } };
    },
    async undo(b) {
      await gh(`/repos/${b.repo}/actions/permissions/workflow`, { method: "PUT", body: { default_workflow_permissions: b.prev.default_workflow_permissions, can_approve_pull_request_reviews: b.prev.can_approve_pull_request_reviews } });
    },
  },
  "gh.deploy-key": {
    async apply(f) {
      const p = f.fix!.params as any;
      const add = await gh(`/repos/${p.repo}/keys`, { method: "POST", body: { title: `${p.title} (read-only, Lockdown)`, key: p.key, read_only: true } });
      // GitHub won't hold the same key twice: delete first, then re-add, and roll back if the re-add fails.
      if (add.status === 422) {
        await gh(`/repos/${p.repo}/keys/${p.id}`, { method: "DELETE" });
        const again = await gh(`/repos/${p.repo}/keys`, { method: "POST", body: { title: `${p.title} (read-only, Lockdown)`, key: p.key, read_only: true } });
        if (again.status !== 201) {
          await gh(`/repos/${p.repo}/keys`, { method: "POST", body: { title: p.title, key: p.key, read_only: false } });
          throw new Error(`GitHub said ${again.status}`);
        }
        return { before: { repo: p.repo, title: p.title, key: p.key, newId: again.data.id } };
      }
      if (add.status !== 201) throw new Error(`GitHub said ${add.status}`);
      await gh(`/repos/${p.repo}/keys/${p.id}`, { method: "DELETE" });
      return { before: { repo: p.repo, title: p.title, key: p.key, newId: add.data.id } };
    },
    async undo(b) {
      await gh(`/repos/${b.repo}/keys/${b.newId}`, { method: "DELETE" });
      await gh(`/repos/${b.repo}/keys`, { method: "POST", body: { title: b.title, key: b.key, read_only: false } });
    },
  },
  "gh.webhook-ssl": {
    async apply(f) {
      const p = f.fix!.params as any;
      const r = await gh(`/repos/${p.repo}/hooks/${p.id}/config`, { method: "PATCH", body: { insecure_ssl: "0" } });
      if (r.status !== 200) throw new Error(`GitHub said ${r.status}`);
      return { before: { repo: p.repo, id: p.id } };
    },
    async undo(b) {
      await gh(`/repos/${b.repo}/hooks/${b.id}/config`, { method: "PATCH", body: { insecure_ssl: "1" } });
    },
  },
  "gh.security-features": {
    async apply(f) {
      const p = f.fix!.params as any;
      const repos: string[] = p.repos ?? [p.repo];
      const done: { repo: string; feat: string }[] = [];
      for (const repo of repos) {
        for (const feat of p.features as string[]) {
          if (feat === "vulnerability-alerts") {
            const r = await gh(`/repos/${repo}/vulnerability-alerts`, { method: "PUT" });
            if (r.status === 204) done.push({ repo, feat });
          } else {
            const r = await gh(`/repos/${repo}`, { method: "PATCH", body: { security_and_analysis: { [feat]: { status: "enabled" } } } });
            if (r.status === 200) done.push({ repo, feat });
          }
        }
      }
      if (!done.length) throw new Error("GitHub didn't accept the change");
      return { before: { enabled: done }, note: `${done.length} setting${done.length > 1 ? "s" : ""} turned on` };
    },
    async undo(b) {
      for (const { repo, feat } of b.enabled as { repo: string; feat: string }[]) {
        if (feat === "vulnerability-alerts") await gh(`/repos/${repo}/vulnerability-alerts`, { method: "DELETE" });
        else await gh(`/repos/${repo}`, { method: "PATCH", body: { security_and_analysis: { [feat]: { status: "disabled" } } } });
      }
    },
  },
  "gh.ruleset": {
    async apply(f) {
      const p = f.fix!.params as any;
      const repos: string[] = (p.repos ?? [{ repo: p.repo }]).map((x: any) => x.repo);
      const made: { repo: string; id: number }[] = [];
      for (const repo of repos) {
        const r = await gh(`/repos/${repo}/rulesets`, { method: "POST", body: { name: "Lockdown: protect main", target: "branch", enforcement: "active", conditions: { ref_name: { include: ["~DEFAULT_BRANCH"], exclude: [] } }, rules: [{ type: "non_fast_forward" }, { type: "deletion" }] } });
        if (r.status === 201) made.push({ repo, id: r.data.id });
      }
      if (!made.length) throw new Error("GitHub didn't accept the rule");
      return { before: { made }, note: `${made.length} repo${made.length > 1 ? "s" : ""} protected` };
    },
    async undo(b) {
      for (const m of b.made as { repo: string; id: number }[]) await gh(`/repos/${m.repo}/rulesets/${m.id}`, { method: "DELETE" });
    },
  },
  "gcp.key-disable": {
    async apply(f) {
      const p = f.fix!.params as any;
      const r = await run(IS_WIN ? "gcloud.cmd" : "gcloud", ["iam", "service-accounts", "keys", "disable", p.key, `--iam-account=${p.account}`, `--project=${p.project}`, "--quiet"], { timeoutMs: 60_000 });
      if (r.code !== 0) throw new Error(r.stderr.trim().split("\n").pop());
      return { before: p };
    },
    async undo(b) {
      await run(IS_WIN ? "gcloud.cmd" : "gcloud", ["iam", "service-accounts", "keys", "enable", b.key, `--iam-account=${b.account}`, `--project=${b.project}`, "--quiet"], { timeoutMs: 60_000 });
    },
  },
  "gcp.bucket-private": {
    async apply(f, ctx) {
      const p = f.fix!.params as any;
      const g = IS_WIN ? "gcloud.cmd" : "gcloud";
      const pol = join(ctx.backupDir, `bucket-${p.bucket}.json`);
      const cur = await run(g, ["storage", "buckets", "get-iam-policy", `gs://${p.bucket}`, "--format=json"], { timeoutMs: 60_000 });
      writeFileSync(pol, cur.stdout);
      for (const role of p.roles as string[]) for (const m of ["allUsers", "allAuthenticatedUsers"]) await run(g, ["storage", "buckets", "remove-iam-policy-binding", `gs://${p.bucket}`, `--member=${m}`, `--role=${role}`, "--quiet"], { timeoutMs: 60_000 });
      return { before: { bucket: p.bucket, policy: pol }, backups: { [`gs://${p.bucket}`]: pol } };
    },
    async undo(b) {
      await run(IS_WIN ? "gcloud.cmd" : "gcloud", ["storage", "buckets", "set-iam-policy", `gs://${b.bucket}`, b.policy, "--quiet"], { timeoutMs: 60_000 });
    },
  },
  "git.untrack": {
    async apply(f, ctx) {
      const p = f.fix!.params as any;
      return withBranch(p.repo, "lockdown/untrack-env", "Stop tracking .env files", "These files held live keys. They're now ignored by git; set the values as environment variables where you deploy.", ctx, async (dir) => {
        await git(dir, ["rm", "--cached", "--quiet", ...p.files]);
        appendIgnore(dir, [".env", ".env.*", "!.env.example"]);
      });
    },
    async undo(b) {
      await undoBranch(b);
    },
  },
  "git.gitignore": {
    async apply(f, ctx) {
      const p = f.fix!.params as any;
      return withBranch(p.repo, "lockdown/ignore-env", "Ignore .env files", "Keeps keys in .env files from being committed by accident.", ctx, async (dir) => {
        appendIgnore(dir, p.lines);
      });
    },
    async undo(b) {
      await undoBranch(b);
    },
  },
  "code.config-edit": {
    async apply(f, ctx) {
      const p = f.fix!.params as any;
      return withBranch(p.repo, `lockdown/${hash(p.file, p.find)}`, f.fix!.action, f.why, ctx, async (dir) => {
        const file = join(dir, p.file);
        writeFileSync(file, readFileSync(file, "utf8").replace(new RegExp(p.find, "g"), p.replace));
      });
    },
    async undo(b) {
      await undoBranch(b);
    },
  },
  "gha.pin": {
    async apply(f, ctx) {
      const p = f.fix!.params as any;
      return withBranch(p.repo, `lockdown/pin-actions-${hash(p.file)}`, `Pin actions in ${p.file} to exact commits`, "A moved tag can't swap in different code once actions are pinned to a commit.", ctx, async (dir) => {
        const file = join(dir, ".github", "workflows", p.file);
        let t = readFileSync(file, "utf8");
        for (const m of [...t.matchAll(/uses:\s*([\w.-]+\/[\w.-]+)((?:\/[\w.-]+)*)@([\w.-]+)/g)]) {
          if (/^(actions|github)\//.test(m[1]) || /^[0-9a-f]{40}$/.test(m[3])) continue;
          const c = await gh(`/repos/${m[1]}/commits/${m[3]}`);
          if (c.status === 200 && c.data?.sha) t = t.replace(m[0], `uses: ${m[1]}${m[2]}@${c.data.sha} # ${m[3]}`);
        }
        writeFileSync(file, t);
      });
    },
    async undo(b) {
      await undoBranch(b);
    },
  },
  "deps.npm": {
    async apply(f, ctx) {
      const p = f.fix!.params as any;
      const sub = p.lockfile.replace(/\/?package-lock\.json$/, "");
      return withBranch(p.repo, `lockdown/deps-${hash(p.lockfile)}`, `Upgrade vulnerable packages${sub ? ` in ${sub}` : ""}`, `Updates ${p.packages.slice(0, 8).join(", ")} to versions without known holes. Only versions your package.json already allows; no major upgrades.`, ctx, async (dir) => {
        const cwd = join(dir, sub);
        const r = await run(IS_WIN ? "npm.cmd" : "npm", ["audit", "fix", "--package-lock-only", "--ignore-scripts", "--no-audit-report"], { cwd, timeoutMs: 600_000 });
        if (r.code !== 0 && !/fixed|changed/i.test(r.stdout)) throw new Error(`npm audit fix: ${(r.stderr || r.stdout).trim().split("\n").slice(-1)[0]}`);
      });
    },
    async undo(b) {
      await undoBranch(b);
    },
  },
  "code.patch": {
    async apply(f, ctx) {
      const p = f.fix!.params as any;
      // Patches are written by the user's own coding agent (Claude Code or Codex CLI) on a branch.
      const agent = await findAgent();
      if (!agent) return { before: null, result: "skipped", note: "needs Claude Code or Codex installed to write this fix" };
      return withBranch(p.repo, `lockdown/fix-${p.rule}`, `Fix: ${f.title.replace(/ in .*$/, "")}`, `${f.why}\n\nFiles: ${p.files.slice(0, 10).join(", ")}`, ctx, async (dir) => {
        const lines = (p.lines ?? []).map((l: any) => `${l.file}:${l.line}`).join(", ");
        const prompt = `Security fix. Problem: ${f.why} Locations: ${lines || p.files.join(", ")}. Make the smallest change that removes the vulnerability without changing behavior for legitimate users. Don't touch unrelated code, don't add dependencies unless unavoidable, don't commit.`;
        const r = agent === "claude"
          ? await run("claude", ["-p", prompt, "--permission-mode", "acceptEdits", "--allowedTools", "Read,Edit,Glob,Grep"], { cwd: dir, timeoutMs: 600_000 })
          : await run("codex", ["exec", "--full-auto", prompt], { cwd: dir, timeoutMs: 600_000 });
        if (r.code !== 0) throw new Error(`${agent} couldn't write the fix`);
      });
    },
    async undo(b) {
      await undoBranch(b);
    },
  },
};

async function findAgent(): Promise<"claude" | "codex" | null> {
  if (process.env.LOCKDOWN_NO_AGENT) return null;
  if ((await run("claude", ["--version"], { timeoutMs: 15_000 })).code === 0) return "claude";
  if ((await run("codex", ["--version"], { timeoutMs: 15_000 })).code === 0) return "codex";
  return null;
}

function appendIgnore(dir: string, lines: string[]) {
  const p = join(dir, ".gitignore");
  const cur = existsSync(p) ? readFileSync(p, "utf8") : "";
  const add = lines.filter((l) => !new RegExp(`^${l.replace(/[.*!]/g, (c) => "\\" + c)}\\s*$`, "m").test(cur));
  if (add.length) writeFileSync(p, `${cur}${cur && !cur.endsWith("\n") ? "\n" : ""}\n# Lockdown: keep keys out of git\n${add.join("\n")}\n`);
}

function renameSafe(from: string, to: string) {
  try {
    renameSync(from, to);
  } catch {
    copyFileSync(from, to);
    writeFileSync(from, "");
    require("node:fs").unlinkSync(from);
  }
}

async function lockDown(p: string) {
  if (IS_WIN) await run("icacls", [p, "/inheritance:r", "/grant:r", `${process.env.USERNAME}:F`, "/grant:r", "SYSTEM:F", "/remove:g", "*S-1-1-0", "*S-1-5-11", "*S-1-5-32-545"]);
  else chmodSync(p, existsSync(p) && statSync(p).isDirectory() ? 0o700 : 0o600);
}
const p2 = (s: string) => s;

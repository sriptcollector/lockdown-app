import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync } from "node:fs";
import { homedir, platform } from "node:os";
import { join } from "node:path";

export const IS_WIN = platform() === "win32";
export const IS_MAC = platform() === "darwin";
export const HOME = process.env.LOCKDOWN_HOME_OVERRIDE || homedir();

/** Lockdown's own folder: scanners, journal, backups, prefs. */
export function dataDir(...parts: string[]): string {
  const base =
    process.env.LOCKDOWN_DATA ||
    (IS_WIN
      ? join(process.env.LOCALAPPDATA || join(homedir(), "AppData", "Local"), "Lockdown")
      : IS_MAC
        ? join(homedir(), "Library", "Application Support", "Lockdown")
        : join(homedir(), ".local", "share", "lockdown"));
  const p = join(base, ...parts);
  mkdirSync(p, { recursive: true });
  return p;
}

export interface RunResult {
  code: number;
  stdout: string;
  stderr: string;
  timedOut: boolean;
}

// Windows PowerShell 5.1 can't load PowerShell 7's modules. Launched from a pwsh terminal, Lockdown would inherit
// pwsh's PSModulePath and core cmdlets (Get-ExecutionPolicy, Get-AuthenticodeSignature) would vanish, so checks
// would quietly miss problems. Give powershell.exe its own default module path.
function winPsModulePath(): string {
  const root = process.env.SystemRoot ?? "C:\\Windows";
  const pf = process.env.ProgramFiles ?? "C:\\Program Files";
  return [join(homedir(), "Documents", "WindowsPowerShell", "Modules"), join(pf, "WindowsPowerShell", "Modules"), join(root, "System32", "WindowsPowerShell", "v1.0", "Modules")].join(";");
}

export function run(
  cmd: string,
  args: string[],
  opts: { cwd?: string; timeoutMs?: number; input?: string; env?: Record<string, string> } = {},
): Promise<RunResult> {
  return new Promise((resolve) => {
    let stdout = "";
    let stderr = "";
    let timedOut = false;
    let child;
    try {
      child = spawn(cmd, args, {
        cwd: opts.cwd,
        env: { ...process.env, GIT_TERMINAL_PROMPT: "0", GCM_INTERACTIVE: "Never", ...(/^powershell(\.exe)?$/i.test(cmd) ? { PSModulePath: winPsModulePath() } : {}), ...opts.env },
        windowsHide: true,
      });
    } catch (e) {
      resolve({ code: -1, stdout: "", stderr: String(e), timedOut: false });
      return;
    }
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill();
    }, opts.timeoutMs ?? 120_000);
    child.stdout?.on("data", (d) => (stdout += d));
    child.stderr?.on("data", (d) => (stderr += d));
    child.on("error", (e) => {
      clearTimeout(timer);
      resolve({ code: -1, stdout, stderr: stderr + String(e), timedOut });
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ code: code ?? -1, stdout, stderr, timedOut });
    });
    if (opts.input) child.stdin?.end(opts.input);
    else child.stdin?.end();
  });
}

/** Run a PowerShell script and parse its JSON output (script must end with ConvertTo-Json). */
export async function ps<T = any>(script: string, timeoutMs = 60_000): Promise<T | null> {
  const wrapped = `$ErrorActionPreference='SilentlyContinue'; $ProgressPreference='SilentlyContinue'; [Console]::OutputEncoding=[Text.Encoding]::UTF8; ${script}`;
  const r = await run("powershell.exe", ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", "-"], {
    input: wrapped,
    timeoutMs,
  });
  const out = r.stdout.trim();
  if (!out) return null;
  try {
    return JSON.parse(out) as T;
  } catch {
    return null;
  }
}

export async function sh(script: string, timeoutMs = 60_000): Promise<RunResult> {
  return run("/bin/sh", ["-c", script], { timeoutMs });
}

export function hash(...parts: string[]): string {
  return createHash("sha256").update(parts.join("\u0000")).digest("hex").slice(0, 16);
}

/** Show only enough of a secret to recognize it. */
export function redact(secret: string): string {
  const s = secret.trim();
  if (s.length <= 8) return "•".repeat(s.length);
  return `${s.slice(0, 4)}${"•".repeat(Math.min(12, s.length - 6))}${s.slice(-2)}`;
}

export function asArray<T>(v: T | T[] | null | undefined): T[] {
  if (v == null) return [];
  return Array.isArray(v) ? v : [v];
}

export function shortPath(p: string): string {
  const h = HOME.replace(/\\/g, "/").toLowerCase();
  const n = p.replace(/\\/g, "/");
  return n.toLowerCase().startsWith(h) ? "~" + n.slice(h.length) : n;
}

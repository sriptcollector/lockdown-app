// End-to-end fix test in a sandbox: planted problems in a fake home folder, a fake registry hive
// under HKCU:\Software\LockdownSandbox, and a throwaway GitHub repo. Scan → plan → fix → verify →
// undo → verify. Never touches the real machine settings or real repos.
//   bun test/e2e-sandbox.ts <sandboxDir> <owner/test-repo>
import { execSync } from "node:child_process";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const [sandbox, testRepo] = process.argv.slice(2);
if (!sandbox || !testRepo) throw new Error("usage: e2e-sandbox.ts <sandboxDir> <owner/repo>");

const token = execSync("gh auth token").toString().trim();
Object.assign(process.env, {
  LOCKDOWN_SANDBOX: "1",
  LOCKDOWN_GITHUB_TOKEN: token,
  LOCKDOWN_HOME_OVERRIDE: join(sandbox, "home"),
  LOCKDOWN_APPDATA: join(sandbox, "appdata"),
  LOCKDOWN_DATA: join(sandbox, "data"),
  LOCKDOWN_WIN_FACTS: join(sandbox, "winfacts.json"),
  LOCKDOWN_REPOS: join(sandbox, "repo"),
  LOCKDOWN_GITHUB_ONLY: testRepo,
  LOCKDOWN_NO_AGENT: process.env.LOCKDOWN_NO_AGENT ?? "1",
});

const { runScan } = await import("../src/scan");
const { makePlan, applyPlan, undo } = await import("../src/fix");
const { savePrefs } = await import("../src/prefs");
const { gh } = await import("../src/gh");
const { ps } = await import("../src/util");

const SBX = "HKCU:\\Software\\LockdownSandbox";
const runKey = `${SBX}\\HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run`;
await ps(`New-Item -Path '${runKey}' -Force | Out-Null; New-ItemProperty -Path '${runKey}' -Name LockdownSandboxItem -Value 'C:\\Users\\x\\AppData\\Roaming\\evil.exe' -Force | Out-Null; 'ok' | ConvertTo-Json`);

const prefs = savePrefs({ mode: "all-auto", code: "pr-automerge", keep: [], rewriteHistory: false, codeRoots: [join(sandbox, "repo")] });
const checks: { name: string; ok: boolean; detail?: string }[] = [];
const check = (name: string, ok: boolean, detail?: string) => {
  checks.push({ name, ok, detail });
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${detail ? `  (${detail})` : ""}`);
};

// ---- scan ----
const scan = await runScan(prefs, () => {}, ["system", "network", "apps", "files", "code", "github"]);
console.log(`scan: ${scan.findings.length} findings, score ${scan.summary.score}`);
const has = (check: string) => scan.findings.some((f) => f.check === check);
for (const c of ["files.history-secrets", "files.password-export", "files.perms", "files.cred-file", "win.firewall", "win.uac", "win.autologon", "win.rdp", "win.smb1", "win.startup", "code.secret", "code.client-secret", "code.sourcemaps", "code.deps", "gh.actions-write", "gh.deploy-key", "gh.webhook", "code.gha-injection", "code.gha-unpinned"]) check(`finds ${c}`, has(c));
check("finds insecure code (Opengrep)", scan.findings.some((f) => f.source === "Opengrep"), scan.findings.filter((f) => f.source === "Opengrep").map((f) => f.check).join(", "));

// ---- plan ----
const plan = await makePlan(scan, prefs);
const withRisk = plan.filter((p) => p.risks.length);
check("break risks detected before applying", withRisk.length > 0, withRisk.slice(0, 3).map((p) => p.risks[0].says).join(" | "));
// Same plan under safe-auto holds the risky ones, and "keep" skips them.
const { decide } = await import("../src/fix");
const rdp = plan.find((p) => p.finding.check === "win.rdp")!;
check("safe-auto holds a fix that might break remote access", decide(rdp.finding, rdp.risks, { ...prefs, mode: "safe-auto" }).decision === "hold");
check("keeping remote access skips it", decide(rdp.finding, rdp.risks, { ...prefs, keep: ["remote-access"] }).decision === "skip");

// ---- fix ----
const hist = join(sandbox, "appdata", "Microsoft", "Windows", "PowerShell", "PSReadLine", "ConsoleHost_history.txt");
const histBefore = readFileSync(hist, "utf8");
const { runId, changes } = await applyPlan(plan, prefs);
const res = (c: string) => changes.find((x) => scan.findings.find((f) => f.id === x.findingId)?.check === c);
console.log(changes.map((c) => `  ${c.result.padEnd(9)} ${c.action}${c.note ? ` — ${c.note}` : ""}`).join("\n"));

check("history secrets removed", !/ghp_|sk_live_/.test(readFileSync(hist, "utf8")));
check("password export locked away", !existsSync(join(sandbox, "home", "Downloads", "Chrome Passwords.csv")));
check("SSH key no longer readable by Everyone", !/Everyone/.test(execSync(`icacls "${join(sandbox, "home", ".ssh", "id_test")}"`).toString()));
check("git credentials moved out of plain text", readFileSync(join(sandbox, "home", ".git-credentials"), { flag: "a+" }).toString() === "" || !existsSync(join(sandbox, "home", ".git-credentials")));
const sbxVal = await ps<any>(`(Get-ItemProperty '${SBX}\\HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name EnableLUA -ErrorAction SilentlyContinue).EnableLUA | ConvertTo-Json`);
check("UAC fix written (sandbox hive)", sbxVal === 1, String(sbxVal));
const startupGone = await ps<any>(`[bool](Get-ItemProperty '${runKey}' -Name LockdownSandboxItem -ErrorAction SilentlyContinue) | ConvertTo-Json`);
check("startup item disabled (sandbox hive)", startupGone === false);
check("admin-only changes are not run in the sandbox", res("win.firewall")?.result === "skipped");
const perms = (await gh(`/repos/${testRepo}/actions/permissions/workflow`)).data;
check("workflow token now read-only", perms?.default_workflow_permissions === "read");
const keys = (await gh(`/repos/${testRepo}/keys`)).data as any[];
check("deploy key now read-only", keys.length > 0 && keys.every((k) => k.read_only));
const hooks = (await gh(`/repos/${testRepo}/hooks`)).data as any[];
check("webhook HTTPS checks on", hooks.every((h) => h.config.insecure_ssl === "0"));
const prs = changes.filter((c) => c.result === "pr-opened" || (c.note ?? "").includes("/pull/"));
check("code fixes landed as pull requests", prs.length >= 3, prs.map((c) => c.note).join(" | "));

// ---- undo ----
const undone = await undo(runId, prefs);
check("undo reversed every applied change", undone.length === changes.filter((c) => ["applied", "pr-opened"].includes(c.result) && c.before != null).length, `${undone.length} undone`);
check("history file restored", readFileSync(hist, "utf8") === histBefore);
check("password export back in place", existsSync(join(sandbox, "home", "Downloads", "Chrome Passwords.csv")));
check("SSH key permissions restored", /Everyone/.test(execSync(`icacls "${join(sandbox, "home", ".ssh", "id_test")}"`).toString()));
const sbxVal2 = await ps<any>(`(Get-ItemProperty '${SBX}\\HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name EnableLUA -ErrorAction SilentlyContinue).EnableLUA | ConvertTo-Json`);
check("UAC value restored (sandbox hive)", sbxVal2 == null, String(sbxVal2));
const startupBack = await ps<any>(`[bool](Get-ItemProperty '${runKey}' -Name LockdownSandboxItem -ErrorAction SilentlyContinue) | ConvertTo-Json`);
check("startup item restored", startupBack === true);
check("workflow token back to write", (await gh(`/repos/${testRepo}/actions/permissions/workflow`)).data?.default_workflow_permissions === "write");
const keys2 = (await gh(`/repos/${testRepo}/keys`)).data as any[];
check("deploy key back to read-write", keys2.some((k) => !k.read_only));
check("webhook setting restored", ((await gh(`/repos/${testRepo}/hooks`)).data as any[]).some((h) => h.config.insecure_ssl === "1"));

const failed = checks.filter((c) => !c.ok);
writeFileSync(join(sandbox, "e2e-result.json"), JSON.stringify({ runId, checks, changes }, null, 1));
console.log(`\n${checks.length - failed.length}/${checks.length} passed`);
process.exit(failed.length ? 1 : 0);

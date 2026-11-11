// Real fix-all and undo on a throwaway CI virtual machine (never run this on your own computer).
// Plants problems, scans, applies every fix with admin rights, re-scans, undoes, re-scans.
//   bun test/e2e-vm.ts
import { execSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { homedir, platform } from "node:os";
import { join } from "node:path";

if (!process.env.CI || !process.env.GITHUB_ACTIONS) throw new Error("e2e-vm only runs on a throwaway CI machine");
const win = platform() === "win32";
const sh = (c: string) => {
  try {
    // The runner's default shell is pwsh 7; its module path breaks Windows PowerShell's own cmdlets.
    const env = win ? { ...process.env, PSModulePath: [join(process.env.ProgramFiles!, "WindowsPowerShell", "Modules"), join(process.env.SystemRoot!, "System32", "WindowsPowerShell", "v1.0", "Modules")].join(";") } : process.env;
    return execSync(c, { stdio: "pipe", shell: win ? "powershell.exe" : "/bin/bash", env }).toString();
  } catch (e: any) {
    return String(e.stdout ?? "") + String(e.stderr ?? "");
  }
};

// ---- plant problems ----
if (win) {
  sh(`Set-NetFirewallProfile -Profile Public -Enabled False`);
  sh(`Set-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced' -Name HideFileExt -Value 1`);
  sh(`Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server' -Name fDenyTSConnections -Value 0`);
  sh(`New-Item -ItemType Directory -Force "$env:APPDATA\\Sketchy" | Out-Null; Copy-Item "$env:WINDIR\\System32\\notepad.exe" "$env:APPDATA\\Sketchy\\updater.exe"; New-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name SketchyUpdater -Value "$env:APPDATA\\Sketchy\\updater.exe" -Force | Out-Null`);
  sh(`Set-ExecutionPolicy -Scope CurrentUser Unrestricted -Force`);
  sh(`New-NetFirewallRule -DisplayName 'test allow 5432' -Direction Inbound -Protocol TCP -LocalPort 5432 -Action Allow | Out-Null`);
  sh(`Start-Process python -ArgumentList '-m','http.server','5432','--bind','0.0.0.0' -WindowStyle Hidden`);
} else {
  sh(`sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate off`);
  sh(`defaults write com.apple.sharingd DiscoverableMode -string Everyone`);
  sh(`sudo defaults write /Library/Preferences/com.apple.loginwindow GuestEnabled -bool true`);
  sh(`nohup python3 -m http.server 5432 --bind 0.0.0.0 >/dev/null 2>&1 &`);
}
mkdirSync(join(homedir(), "Downloads"), { recursive: true });
writeFileSync(join(homedir(), "Downloads", "passwords.csv"), "name,url,username,password\nx,https://x.test,me,pw\n");
await new Promise((r) => setTimeout(r, 3000));
if (win) console.log("planted check:", sh(String.raw`Get-ExecutionPolicy -List | Out-String; Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' | Out-String; (Get-AuthenticodeSignature "$env:APPDATA\Sketchy\updater.exe").Status`));

// ---- pay like a customer: an account that bought a trial on staging (fake purchase, no card) ----
const staged = process.env.LOCKDOWN_TEST_ACCOUNT;
if (!staged) throw new Error("LOCKDOWN_TEST_ACCOUNT is missing (an account.json from a staging purchase)");
process.env.LOCKDOWN_API = "https://lockdown-staging.westwardconsulting.ai";
const { dataDir } = await import("../src/util");
mkdirSync(dataDir(), { recursive: true });
writeFileSync(join(dataDir(), "account.json"), staged, { mode: 0o600 });
const lic = await import("../src/license");
const acct = await lic.account.refresh();
console.log(`account: signed in ${acct.signedIn}, plan ${acct.plan}, can fix ${lic.canFix()}`);
if (acct.plan !== "pro" || !lic.canFix()) throw new Error("the staging purchase didn't unlock fixing");

process.env.LOCKDOWN_REPOS = "";
const { runScan } = await import("../src/scan");
const { makePlan, applyPlan, undo } = await import("../src/fix");
const { savePrefs } = await import("../src/prefs");
const prefs = savePrefs({ mode: "all-auto", keep: [], codeRoots: [join(homedir(), "nothing-here")] });
const layers = ["system", "network", "apps", "files"] as any;

const scan1 = await runScan(prefs, () => {}, layers);
console.log(`before: ${scan1.findings.length} findings, score ${scan1.summary.score}`);
for (const f of scan1.findings) console.log(`  [${f.severity}] ${f.check} · ${f.title}`);

const plan = await makePlan(scan1, prefs);
const { runId, changes } = await applyPlan(plan, prefs);
console.log("\nchanges:");
for (const c of changes) console.log(`  ${c.result.padEnd(9)} ${c.fixer.padEnd(20)} ${c.action}${c.note ? ` — ${c.note.slice(0, 120)}` : ""}`);

// One-way fixes (updating virus definitions, running a scan) have nothing to undo.
const applied = changes.filter((c) => c.result === "applied" && c.before != null && !(String(c.fixer).startsWith("win.ps") && !(c.before as any).undo));
const checkOf = (id: string) => scan1.findings.find((f) => f.id === id)!.check;
const scan2 = await runScan(prefs, () => {}, layers);
console.log(`\nafter fix: ${scan2.findings.length} findings, score ${scan2.summary.score}`);
const stillThere = applied.filter((c) => scan2.findings.some((f) => f.id === c.findingId));

const undone = await undo(runId, prefs);
const scan3 = await runScan(prefs, () => {}, layers);
console.log(`after undo: ${scan3.findings.length} findings, score ${scan3.summary.score}`);
// Tamper Protection can refuse to switch real-time protection back off; that's Windows protecting itself.
const notBack = applied.filter((c) => checkOf(c.findingId) !== "win.defender-realtime" && !scan3.findings.some((f) => f.check === checkOf(c.findingId)));
const planted = ["files.password-export", ...(win ? ["win.firewall", "win.file-ext", "win.rdp", "win.startup", "win.execpolicy", "win.open-port"] : ["mac.firewall", "mac.airdrop", "mac.guest", "mac.open-port"])];
const missing = planted.filter((c) => !scan1.findings.some((f) => f.check === c));

const results = [
  { name: "every planted problem found", ok: !missing.length, detail: missing.join(", ") },
  { name: "fixes applied with admin rights", ok: applied.length >= (win ? 6 : 3), detail: `${applied.length} applied, ${changes.filter((c) => c.result === "failed").length} failed` },
  { name: "applied fixes are gone on re-scan", ok: stillThere.length === 0, detail: stillThere.map((c) => checkOf(c.findingId)).join(", ") },
  { name: "score went up", ok: scan2.summary.score > scan1.summary.score, detail: `${scan1.summary.score} → ${scan2.summary.score}` },
  { name: "undo reversed every change", ok: undone.filter((u) => applied.some((a) => a.id === u.id)).length === applied.length, detail: `${undone.length}/${applied.length}` },
  { name: "undone problems are back on re-scan", ok: notBack.length === 0, detail: notBack.map((c) => checkOf(c.findingId)).join(", ") },
];
console.log("");
for (const r of results) console.log(`${r.ok ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`);
writeFileSync("e2e-vm-result.json", JSON.stringify({ platform: platform(), results, changes, before: scan1.summary, afterFix: scan2.summary, afterUndo: scan3.summary }, null, 1));
process.exit(results.every((r) => r.ok) ? 0 : 1);

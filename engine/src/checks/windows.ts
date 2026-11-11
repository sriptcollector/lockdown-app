// Windows: system, network and apps layers. Facts are gathered read-only by win-facts.ps1,
// then judged here so the rules can be tested against saved fact files.
import { readFileSync } from "node:fs";
import type { ScanCtx } from "../context";
import type { Finding } from "../types";
import { asArray, run } from "../util";
import factsScript from "./win-facts.ps1" with { type: "text" };

export type WinFacts = Record<string, any>;

export async function gatherWinFacts(): Promise<WinFacts> {
  if (process.env.LOCKDOWN_WIN_FACTS) return JSON.parse(readFileSync(process.env.LOCKDOWN_WIN_FACTS, "utf8").replace(/^\uFEFF/, ""));
  const r = await run("powershell.exe", ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", "-"], {
    input: `[Console]::OutputEncoding=[Text.Encoding]::UTF8\n${factsScript}`,
    timeoutMs: 180_000,
  });
  const out = r.stdout.trim().replace(/^\uFEFF/, "");
  const start = out.indexOf("{");
  if (start < 0) throw new Error("couldn't read Windows settings");
  return JSON.parse(out.slice(start));
}

// Windows 11 feature updates and the day security updates stop (Home and Pro).
// Source: Microsoft lifecycle pages for Windows 11 Home and Pro.
const WIN11_EOS_HOME: Record<string, string> = {
  "21H2": "2023-10-10",
  "22H2": "2024-10-08",
  "23H2": "2025-11-11",
  "24H2": "2026-10-13",
  "25H2": "2027-10-12",
};
const WIN11_EOS_ENTERPRISE: Record<string, string> = {
  "21H2": "2024-10-08",
  "22H2": "2025-10-14",
  "23H2": "2026-11-10",
  "24H2": "2027-10-12",
  "25H2": "2028-10-10",
};
// SKUs for Enterprise/Education (they get 36 months instead of 24).
const ENTERPRISE_SKUS = new Set([4, 27, 70, 72, 84, 121, 122, 125, 126, 161, 162, 175]);

type Emit = (f: Omit<Finding, "id" | "layer"> & { layer?: Finding["layer"] }) => void;

export function judgeWindows(f: WinFacts, now = new Date()): Omit<Finding, "id">[] {
  const out: Omit<Finding, "id">[] = [];
  const add: Emit = (x) => out.push({ layer: "system", ...x } as Omit<Finding, "id">);

  // --- Updates ---
  const build = Number(f.os?.build);
  const ver = String(f.displayVersion ?? "");
  if (build && build < 22000) {
    add({
      check: "win.os-support",
      severity: "critical",
      title: "Windows 10 no longer gets security updates",
      why: "Microsoft stopped patching Windows 10 on October 14, 2025, so every new hole found in it stays open on this PC.",
      where: f.os?.caption,
      fix: { fixer: "win.open-settings", action: "Update to Windows 11", params: { uri: "ms-settings:windowsupdate" }, manual: "Upgrade to Windows 11 in Windows Update (free on supported PCs)." },
    });
  } else if (ver && !/Server/i.test(f.os?.caption ?? "")) {
    const table = ENTERPRISE_SKUS.has(Number(f.edition)) ? WIN11_EOS_ENTERPRISE : WIN11_EOS_HOME;
    const eos = table[ver];
    if (eos && new Date(eos) < now) {
      add({
        check: "win.os-support",
        severity: "critical",
        title: `Windows 11 ${ver} stopped getting security updates`,
        why: `Microsoft's last security fix for ${ver} was on ${fmtDate(eos)}. Newer holes in it stay open until you move to the current version.`,
        where: `${f.os?.caption} ${ver} (build ${build}.${f.ubr ?? ""})`,
        fix: { fixer: "win.open-settings", action: "Update Windows to the latest version", params: { uri: "ms-settings:windowsupdate" }, manual: "In Windows Update, install \"Windows 11, version 25H2\". It's free and keeps your files and apps." },
      });
    }
  }
  if (f.wuPaused && new Date(f.wuPaused) > now) {
    add({
      check: "win.updates-paused",
      severity: "high",
      title: "Windows updates are paused",
      why: "Security fixes won't install until the pause ends.",
      evidence: `paused until ${fmtDate(f.wuPaused)}`,
      fix: { fixer: "win.reg", action: "Resume Windows updates", admin: true, params: { ops: [{ path: "HKLM:\\SOFTWARE\\Microsoft\\WindowsUpdate\\UX\\Settings", name: "PauseUpdatesExpiryTime", delete: true }] } },
    });
  }
  if (Number(f.wuNoAuto) === 1) {
    add({
      check: "win.updates-off",
      severity: "high",
      title: "Automatic updates are turned off",
      why: "Most attacks use holes that already have a fix. Without automatic updates the fixes never arrive.",
      fix: { fixer: "win.reg", action: "Turn automatic updates back on", admin: true, params: { ops: [{ path: "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU", name: "NoAutoUpdate", delete: true }] } },
    });
  }
  if (f.rebootPending) {
    add({ check: "win.reboot", severity: "medium", title: "Updates are waiting for a restart", why: "Installed security fixes don't protect you until Windows restarts.", fix: { fixer: "none", action: "Restart when convenient", params: {}, manual: "Restart your PC to finish installing updates." } });
  }

  // --- Antivirus ---
  const d = f.defender;
  const thirdPartyAv = asArray(f.antivirus).some((a: any) => a?.name && !/defender/i.test(a.name));
  if (d && !thirdPartyAv) {
    if (!d.realtime || !d.enabled) {
      add({
        check: "win.defender-realtime",
        severity: "critical",
        title: "Real-time virus protection is off",
        why: "Nothing is checking files as they download or run.",
        fix: { fixer: "win.ps-admin", action: "Turn real-time protection on", admin: true, params: { script: "Set-MpPreference -DisableRealtimeMonitoring $false", undo: "Set-MpPreference -DisableRealtimeMonitoring $true" } },
      });
    }
    if (d.tamper === false) {
      add({ check: "win.defender-tamper", severity: "high", title: "Tamper protection is off", why: "Malware can switch your antivirus off without you noticing.", fix: { fixer: "win.open-settings", action: "Stop apps from switching off your antivirus", params: { uri: "windowsdefender://threatsettings" }, manual: "Turn on Tamper Protection under Virus & threat protection settings. Windows only lets you do this yourself." } });
    }
    if (Number(d.sigAgeDays) > 3) {
      add({ check: "win.defender-sigs", severity: "high", title: `Virus definitions are ${d.sigAgeDays} days old`, why: "New malware isn't recognized until definitions update.", fix: { fixer: "win.ps", action: "Update virus definitions now", params: { script: "Update-MpSignature" } } });
    }
    const p = f.defenderPrefs ?? {};
    if (Number(p.pua) === 0) {
      add({ check: "win.defender-pua", severity: "medium", title: "Unwanted-app blocking is off", why: "Bundled adware and fake cleaners slip in with free downloads.", fix: { fixer: "win.ps-admin", action: "Block potentially unwanted apps", admin: true, params: { script: "Set-MpPreference -PUAProtection Enabled", undo: "Set-MpPreference -PUAProtection Disabled" } } });
    }
    if (Number(p.network) === 0) {
      add({
        check: "win.defender-network",
        severity: "medium",
        title: "Network protection is off",
        why: "Windows won't stop apps from reaching known phishing and malware sites.",
        fix: { fixer: "win.ps-admin", action: "Turn on network protection", admin: true, params: { script: "Set-MpPreference -EnableNetworkProtection Enabled", undo: "Set-MpPreference -EnableNetworkProtection Disabled" } },
      });
    }
    if (Number(d.lastQuickScanDays) > 14) {
      add({ check: "win.defender-scan", severity: "low", title: Number(d.lastQuickScanDays) > 10000 ? "No virus scan has ever run" : `No virus scan in ${d.lastQuickScanDays} days`, why: "Scheduled scans catch what slipped past real-time checks.", fix: { fixer: "win.ps", action: "Run a quick virus scan", params: { script: "Start-MpScan -ScanType QuickScan" } } });
    }
  }

  // --- Firewall ---
  for (const p of asArray(f.firewall) as any[]) {
    if (!p.enabled) {
      add({
        layer: "network",
        check: "win.firewall",
        severity: p.name === "Public" ? "critical" : "high",
        title: `Firewall is off on ${p.name.toLowerCase()} networks`,
        why: "Anyone on the same network can reach every service on this PC.",
        where: `${p.name} profile`,
        fix: { fixer: "win.ps-admin", action: `Turn the firewall on for ${p.name.toLowerCase()} networks`, admin: true, params: { script: `Set-NetFirewallProfile -Profile ${p.name} -Enabled True`, undo: `Set-NetFirewallProfile -Profile ${p.name} -Enabled False` } },
      });
    } else if (p.inbound === "Allow") {
      add({ layer: "network", check: "win.firewall-inbound", severity: "high", title: `Firewall lets everything in on ${p.name.toLowerCase()} networks`, why: "The firewall is on but its default is to allow incoming connections.", fix: { fixer: "win.ps-admin", action: "Block incoming connections by default", admin: true, params: { script: `Set-NetFirewallProfile -Profile ${p.name} -DefaultInboundAction Block`, undo: `Set-NetFirewallProfile -Profile ${p.name} -DefaultInboundAction Allow` } } });
    }
  }

  // --- Disk encryption ---
  const sys = asArray(f.bitlocker).find((b: any) => /^C:/i.test(b.drive));
  if (sys && ![1, 3, 5].includes(Number(sys.protection))) {
    const home = Number(f.edition) === 101 || /home/i.test(f.os?.caption ?? "");
    add({
      check: "win.encryption",
      severity: "high",
      title: "Your disk isn't encrypted",
      why: "If this laptop is lost or stolen, anyone can pull the drive and read every file, saved password and key on it.",
      where: "C:",
      fix: {
        fixer: "win.open-settings",
        action: "Turn on disk encryption",
        params: { uri: "ms-settings:deviceencryption" },
        manual: home
          ? "Turn on Device encryption in Settings > Privacy & security. If that page is missing, this PC needs Windows 11 Pro for BitLocker."
          : "Turn on BitLocker for C: and save the recovery key to your Microsoft account.",
      },
    });
  }

  // --- Accounts and sign-in ---
  if (Number(f.uac?.lua) === 0) {
    add({ check: "win.uac", severity: "critical", title: "Admin prompts (UAC) are off", why: "Every program runs with full control of the PC, so one bad download owns everything.", fix: { fixer: "win.reg", action: "Turn admin prompts back on", admin: true, params: { restart: true, ops: [{ path: "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", name: "EnableLUA", type: "DWord", value: 1 }] } } });
  } else if (Number(f.uac?.admin) === 0) {
    add({ check: "win.uac-silent", severity: "high", title: "Admin prompts approve themselves", why: "Programs get admin rights without asking you.", fix: { fixer: "win.reg", action: "Ask before giving apps admin rights", admin: true, params: { ops: [{ path: "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", name: "ConsentPromptBehaviorAdmin", type: "DWord", value: 5 }] } } });
  }
  if (Number(f.uac?.secureDesktop) === 0) {
    add({ check: "win.uac-desktop", severity: "medium", title: "Admin prompts don't dim the screen", why: "Without the secure desktop, malware can click 'Yes' on admin prompts for you.", fix: { fixer: "win.reg", action: "Show admin prompts on the secure desktop", admin: true, params: { ops: [{ path: "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", name: "PromptOnSecureDesktop", type: "DWord", value: 1 }] } } });
  }
  if (f.user?.isAdminGroup) {
    add({ check: "win.daily-admin", severity: "medium", title: "You use an admin account every day", why: "Anything you run can change the whole system after one click on 'Yes'. A standard account limits the damage.", where: f.user?.name, fix: { fixer: "none", action: "Use a standard account day to day", params: {}, manual: "Create a separate admin account, then change your own account to Standard in Settings > Accounts > Other users." } });
  }
  if (String(f.autoLogon) === "1") {
    add({
      check: "win.autologon",
      severity: f.autoLogonPw ? "critical" : "high",
      title: f.autoLogonPw ? "Your Windows password is saved in plain text for auto sign-in" : "Windows signs in by itself at startup",
      why: "Anyone who turns the PC on is signed in as you" + (f.autoLogonPw ? ", and any program can read your password." : "."),
      fix: { fixer: "win.reg", action: "Turn off automatic sign-in", admin: true, params: { ops: [{ path: "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", name: "AutoAdminLogon", type: "String", value: "0" }, { path: "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", name: "DefaultPassword", delete: true }] } },
    });
  }
  for (const u of asArray(f.localUsers) as any[]) {
    if (u.enabled && u.pwRequired === false && !/^(WDAGUtilityAccount|DefaultAccount)$/i.test(u.name)) {
      add({ check: "win.user-nopw", severity: "high", title: `Account "${u.name}" can sign in without a password`, why: "Anyone at the keyboard or on the network can use it.", where: u.name, fix: { fixer: "none", action: "Set a password or disable the account", params: {}, manual: `Set a password for ${u.name}, or disable it in Computer Management.` } });
    }
    if (u.enabled && /^Guest$/i.test(u.name)) {
      add({ check: "win.guest", severity: "medium", title: "The Guest account is on", why: "It gives anyone a way in without a password.", fix: { fixer: "win.ps-admin", action: "Turn off the Guest account", admin: true, params: { script: "Disable-LocalUser -Name Guest", undo: "Enable-LocalUser -Name Guest" } } });
    }
  }
  const ss = f.screenSaver ?? {};
  if (!f.inactivityLock && !(String(ss.active) === "1" && String(ss.secure) === "1")) {
    add({
      check: "win.autolock",
      severity: "low",
      title: "Your PC doesn't lock when you walk away",
      why: "Anyone nearby can use it while you're gone.",
      fix: { fixer: "win.reg", action: "Lock the screen after 10 idle minutes", params: { ops: [{ path: "HKCU:\\Control Panel\\Desktop", name: "ScreenSaveActive", type: "String", value: "1" }, { path: "HKCU:\\Control Panel\\Desktop", name: "ScreenSaverIsSecure", type: "String", value: "1" }, { path: "HKCU:\\Control Panel\\Desktop", name: "ScreenSaveTimeOut", type: "String", value: "600" }, { path: "HKCU:\\Control Panel\\Desktop", name: "SCRNSAVE.EXE", type: "String", value: "C:\\Windows\\System32\\scrnsave.scr" }] } },
    });
  }

  // --- Hardening ---
  if (String(f.smartScreen?.explorer).toLowerCase() === "off" || (f.smartScreen?.policy != null && Number(f.smartScreen.policy) === 0)) {
    add({ check: "win.smartscreen", severity: "high", title: "SmartScreen is off", why: "Windows won't warn you before running unknown downloads.", fix: { fixer: "win.reg", action: "Turn SmartScreen on", admin: true, params: { ops: [{ path: "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer", name: "SmartScreenEnabled", type: "String", value: "Warn" }] } } });
  }
  if (f.secureBoot === false) {
    add({ check: "win.secureboot", severity: "medium", title: "Secure Boot is off", why: "Malware that loads before Windows (bootkits) can hide from your antivirus.", fix: { fixer: "none", action: "Turn on Secure Boot in firmware settings", params: {}, manual: "Restart into UEFI settings and enable Secure Boot." } });
  }
  if (Number(f.memIntegrity) !== 1) {
    add({ check: "win.memory-integrity", severity: "medium", title: "Memory integrity is off", why: "It stops malicious drivers from taking over the Windows kernel.", fix: { fixer: "win.reg", action: "Turn on memory integrity", admin: true, params: { restart: true, risk: "drivers", ops: [{ path: "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity", name: "Enabled", type: "DWord", value: 1 }] } } });
  }
  if (f.lsaPpl == null || Number(f.lsaPpl) === 0) {
    add({ check: "win.lsa", severity: "low", title: "Saved sign-ins aren't shielded from other programs", why: "LSA protection stops tools like Mimikatz from dumping your Windows credentials from memory.", fix: { fixer: "win.reg", action: "Turn on LSA protection", admin: true, params: { restart: true, risk: "lsa", ops: [{ path: "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa", name: "RunAsPPL", type: "DWord", value: 2 }] } } });
  }
  // Our own powershell runs with -ExecutionPolicy Bypass (process scope), so PowerShell reports a CurrentUser change as
  // "overridden by a more specific scope" even though it applied. Only fail if the setting really didn't change.
  const setUserEp = (v: string) => `try { Set-ExecutionPolicy -Scope CurrentUser ${v} -Force } catch { if ("$(Get-ExecutionPolicy -Scope CurrentUser)" -ne '${v}') { throw } }`;
  const ep = [f.execPolicy?.user, f.execPolicy?.machine].map((x) => String(x));
  if (ep.some((x) => /^(Unrestricted|Bypass)$/i.test(x))) {
    add({ check: "win.execpolicy", severity: "medium", title: "PowerShell runs any downloaded script", why: "A script from an email or website can run with no warning.", evidence: `policy: ${ep.join(" / ")}`, fix: { fixer: "win.ps", action: "Only run downloaded scripts that are signed", params: { script: setUserEp("RemoteSigned"), undo: setUserEp(f.execPolicy?.user || "Undefined"), risk: "scripts" } } });
  }
  if (f.autorun == null || Number(f.autorun) < 255) {
    add({ check: "win.autorun", severity: "low", title: "USB drives can start programs on their own", why: "AutoRun is how USB-stick malware spreads.", fix: { fixer: "win.reg", action: "Turn off AutoRun for every drive", params: { ops: [{ path: "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", name: "NoDriveTypeAutoRun", type: "DWord", value: 255 }] } } });
  }
  if (Number(f.showExt) === 1) {
    add({ check: "win.file-ext", severity: "low", title: "File extensions are hidden", why: "A file called invoice.pdf.exe shows up as invoice.pdf, a common trick to make you run malware.", fix: { fixer: "win.reg", action: "Show file extensions", params: { ops: [{ path: "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced", name: "HideFileExt", type: "DWord", value: 0 }] } } });
  }

  judgeWinNetwork(f, out);
  judgeWinApps(f, out);
  return out;
}

const DB_PORTS: Record<number, string> = { 3306: "MySQL", 5432: "Postgres", 6379: "Redis", 27017: "MongoDB", 9200: "Elasticsearch", 5984: "CouchDB", 11211: "Memcached", 8086: "InfluxDB", 9042: "Cassandra", 1433: "SQL Server" };
const SYSTEM_PROCS = /^(System|svchost|lsass|wininit|services|spoolsv|Idle)$/i;
const DEV_PROCS = /^(node|bun|deno|python\d*|ruby|php|java|dotnet|go|uvicorn|gunicorn|vite|esbuild|ollama)$/i;

function judgeWinNetwork(f: WinFacts, out: Omit<Finding, "id">[]) {
  const add = (x: Omit<Finding, "id" | "layer">) => out.push({ layer: "network", ...x });
  const fwOn = asArray(f.firewall).every((p: any) => p.enabled && p.inbound !== "Allow");
  const allow = asArray(f.fwAllow) as any[];
  const listening = (asArray(f.listening) as any[]).filter((l) => /^(0\.0\.0\.0|::|\*)$/.test(l.addr));
  const byPort = new Map<number, any>();
  for (const l of listening) if (!byPort.has(l.port)) byPort.set(l.port, l);
  const established = asArray(f.established) as any[];

  for (const [port, l] of byPort) {
    if (SYSTEM_PROCS.test(l.proc ?? "") || port >= 49152) continue;
    if (port === 22 || port === 3389) continue; // handled below as remote access
    const allowed = allow.some(
      (r) =>
        (r.program && l.path && r.program.toLowerCase() === String(l.path).toLowerCase()) ||
        (r.localport && r.localport !== "Any" && String(r.localport).split(",").includes(String(port))),
    );
    // A block rule wins over any allow rule in Windows Firewall.
    const blocked = (asArray(f.fwBlock) as any[]).some((r) => r.localport && String(r.localport).split(",").includes(String(port)) && /Any|Domain.*Private.*Public/i.test(String(r.profiles ?? "Any")));
    const reachable = (!fwOn || allowed) && !blocked;
    if (!reachable) continue;
    const db = DB_PORTS[port];
    const lanPeers = established.filter((e) => e.lport === port && /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|100\.)/.test(e.remote));
    const program = l.path || l.proc;
    add({
      check: "win.open-port",
      severity: db ? "high" : DEV_PROCS.test(l.proc ?? "") ? "medium" : "medium",
      title: db ? `${db} is reachable from your network` : `${l.proc ?? "A program"} is reachable from your network on port ${port}`,
      why: db
        ? "Databases on a laptop usually have no password. Anyone on the same Wi-Fi can read or wipe them."
        : "A dev server or app listening on every network can be reached by anyone on the same Wi-Fi, including coffee shops and airports.",
      where: `port ${port} · ${l.proc ?? "?"}`,
      evidence: allowed ? "a firewall rule lets it in" : "the firewall is off",
      fix: {
        fixer: "win.fw-block",
        action: `Block other devices from reaching port ${port}`,
        admin: true,
        params: { port, program, proc: l.proc, lanPeers: lanPeers.length },
      },
    });
  }

  // Remote access: SSH and Remote Desktop
  const svc = (n: string) => asArray(f.sshd).find((s: any) => s.name === n);
  const sshd = svc("sshd");
  if (sshd && sshd.status === "Running") {
    const peers = established.filter((e) => e.lport === 22).length;
    add({
      check: "win.sshd",
      severity: "high",
      title: "Anyone can try to sign in to this PC over SSH",
      why: "The OpenSSH server is running and listening on every network. One weak or reused password lets someone in.",
      where: "port 22 · sshd",
      evidence: sshd.start === "Automatic" ? "starts automatically with Windows" : undefined,
      fix: { fixer: "win.service", action: "Stop the SSH server and keep it from starting", admin: true, params: { name: "sshd", startup: "Disabled", peers } },
    });
  }
  const rdpOn = Number(f.rdp?.deny) === 0;
  if (rdpOn) {
    add({
      check: "win.rdp",
      severity: Number(f.rdp?.nla) === 0 ? "critical" : "high",
      title: Number(f.rdp?.nla) === 0 ? "Remote Desktop is on without network sign-in" : "Remote Desktop is on",
      why: "Remote Desktop is the most attacked service on Windows. Ransomware gangs scan for it all day.",
      fix: { fixer: "win.reg", action: "Turn Remote Desktop off", admin: true, params: { reliance: "remote-access", sessions: Number(f.rdpSessions) || 0, ops: [{ path: "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server", name: "fDenyTSConnections", type: "DWord", value: 1 }] } },
    });
  }
  for (const name of ["RemoteRegistry", "WinRM", "TlntSvr", "SNMP", "ftpsvc"]) {
    const s = svc(name);
    if (s && s.status === "Running") {
      add({ check: "win.remote-svc", severity: "high", title: `${name} remote service is running`, why: "It lets other computers control or read this PC.", where: name, fix: { fixer: "win.service", action: `Stop ${name}`, admin: true, params: { name, startup: "Disabled" } } });
    }
  }
  if (f.smb1 === true) {
    add({ check: "win.smb1", severity: "critical", title: "Old file sharing (SMBv1) is on", why: "SMBv1 is how WannaCry spread to 200,000 computers in a day.", fix: { fixer: "win.ps-admin", action: "Turn off SMBv1", admin: true, params: { reliance: "file-sharing", script: "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force", undo: "Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force" } } });
  }
  for (const s of asArray(f.shares) as any[]) {
    add({ check: "win.share", severity: "medium", title: `Folder "${s.name}" is shared on the network`, why: "Other computers on your network can open it.", where: s.path, fix: { fixer: "win.share-remove", action: `Stop sharing "${s.name}"`, admin: true, params: { name: s.name, path: s.path } } });
  }
  const open = asArray(f.openWifi) as string[];
  if (open.length) {
    add({
      check: "win.open-wifi",
      severity: "medium",
      title: `${open.length} open Wi-Fi network${open.length > 1 ? "s" : ""} will auto-join`,
      why: "Attackers name fake hotspots after common open networks. Your PC joins them on its own and its traffic can be watched.",
      evidence: open.slice(0, 5).join(", "),
      fix: { fixer: "win.wifi-forget", action: "Forget open Wi-Fi networks", params: { names: open } },
    });
  }
  // hosts file: redirects of real domains to real IPs are hijacks; 0.0.0.0 lines are blocks.
  const hosts = asArray(f.hostsLines) as string[];
  const redirects = hosts.filter((l) => {
    const [ip, ...names] = l.split(/\s+/);
    if (/^(0\.0\.0\.0|127\.|::1?$|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|fd)/.test(ip)) return false;
    return names.some((n) => !/(\.local|\.lan|\.internal|\.ts\.net|\.test|\.localhost|\.home\.arpa)\.?$/i.test(n) && !n.startsWith("#"));
  });
  if (redirects.length) {
    add({ check: "win.hosts-redirect", severity: "high", title: "Your hosts file sends websites to other addresses", why: "Malware edits the hosts file to send you to fake banking or login pages.", evidence: redirects.slice(0, 3).join(" | "), fix: { fixer: "none", action: "Review the hosts file", params: {}, manual: "Open C:\\Windows\\System32\\drivers\\etc\\hosts and remove lines you didn't add." } });
  }
  const adobeBlocks = hosts.filter((l) => /adobe|adobestats|adobelogin/i.test(l)).length;
  if (adobeBlocks >= 5) {
    add({ check: "win.hosts-adobe", layer: "apps", severity: "medium", title: "Adobe's license servers are blocked", why: "This is what cracked copies of Adobe apps do. Cracked installers are one of the most common ways malware gets onto a PC.", evidence: `${adobeBlocks} Adobe addresses blocked in the hosts file`, fix: { fixer: "none", action: "Reinstall Adobe apps from adobe.com", params: {}, manual: "Uninstall the Adobe apps, remove the Adobe lines from the hosts file, and reinstall from adobe.com." } } as any);
  }
  if (Number(f.proxy?.enabled) === 1 || f.proxy?.pac) {
    add({ check: "win.proxy", severity: "medium", title: "Your web traffic goes through a proxy", why: "A proxy you didn't set up can read and change everything you browse.", evidence: String(f.proxy?.server || f.proxy?.pac), fix: { fixer: "none", action: "Check the proxy is yours", params: {}, manual: "Settings > Network & internet > Proxy. Turn it off if you don't recognize it." } });
  }
}

const REMOTE_TOOLS = /\b(AnyDesk|TeamViewer|RustDesk|UltraViewer|ScreenConnect|ConnectWise Control|LogMeIn|Splashtop|Supremo|Ammyy|RemotePC|Zoho Assist|AeroAdmin|DWService|Atera|NinjaRMM)\b/i;
const ACTIVATORS = /\b(KMSpico|KMSAuto|KMS_VL|Microsoft Toolkit|AAct|Re-Loader)\b/i;
const TUNNELS = /^(ngrok|cloudflared|localtonet|bore|frpc|playit)$/i;
const EOL_APPS: [RegExp, string][] = [
  [/^Adobe Flash Player/i, "Flash Player has had no security fixes since 2020"],
  [/^Python 2\./i, "Python 2 has had no security fixes since 2020"],
  [/^Java\s?(\(TM\))?\s?(SE Runtime Environment )?[678]\b|^Java [678] Update/i, "This Java version is years out of date"],
  [/^Internet Explorer/i, "Internet Explorer is retired"],
  [/^Apple Software Update|^QuickTime/i, "QuickTime for Windows has known unpatched holes"],
  [/^WinRAR/i, "WinRAR has had file-extraction holes; make sure it's 7.x or newer"],
];

function judgeWinApps(f: WinFacts, out: Omit<Finding, "id">[]) {
  const add = (x: Omit<Finding, "id" | "layer">) => out.push({ layer: "apps", ...x });
  const apps = asArray(f.apps) as any[];
  const procs = asArray(f.processes) as any[];
  const seen = new Set<string>();
  for (const a of apps) {
    const name = String(a.name);
    if (seen.has(name)) continue;
    seen.add(name);
    const rt = name.match(REMOTE_TOOLS);
    if (rt) add({ check: "win.remote-tool", severity: "medium", title: `${rt[1]} is installed`, why: "Remote-control apps are the #1 tool in tech-support scams. If you don't use it, it's a door left open.", where: name, fix: { fixer: "none", action: `Uninstall ${rt[1]} if you don't use it`, params: {}, manual: `Uninstall ${rt[1]} in Settings > Apps if you don't use it.` } });
    if (ACTIVATORS.test(name)) add({ check: "win.activator", severity: "critical", title: `${name} is installed`, why: "Windows and Office activators are a common way malware is delivered.", fix: { fixer: "none", action: "Remove it and run a full virus scan", params: {}, manual: "Uninstall it, then run a Microsoft Defender Offline scan." } });
    for (const [re, why] of EOL_APPS) {
      if (re.test(name) && !(/^WinRAR/i.test(name) && Number(String(a.version).split(".")[0]) >= 7)) {
        add({ check: "win.eol-app", severity: "medium", title: `${name} is out of date`, why, where: `${name} ${a.version ?? ""}`.trim(), fix: { fixer: "none", action: `Update or uninstall ${name}`, params: {}, manual: `Update ${name} from its official site, or uninstall it in Settings > Apps.` } });
      }
    }
  }
  const tunnels = new Map<string, any>();
  for (const p of procs) if (TUNNELS.test(p.name ?? "")) tunnels.set(String(p.name).toLowerCase(), p);
  for (const p of tunnels.values()) {
    {
      const service = /Program Files/i.test(p.path ?? "");
      add({ check: "win.tunnel", severity: service ? "medium" : "high", title: `${p.name} is ${service ? "running as a service" : "running"}`, why: service ? "A tunnel puts services on this PC on the public internet. Make sure every route it serves needs a sign-in." : "Tunnels put a service on this PC on the public internet. Anyone with the link can reach it.", where: p.path, fix: { fixer: "none", action: "Stop the tunnel when you're done with it", params: {}, manual: `Stop ${p.name} when you're not demoing something.` } });
    }
  }
  // Startup programs that aren't signed or run from user-writable folders
  for (const s of asArray(f.startup) as any[]) {
    const exe = String(s.exe ?? s.cmd ?? "");
    const userDir = /\\(AppData\\(Local\\Temp|Roaming)|Temp|Downloads)\\/i.test(exe);
    const unsigned = s.signed && s.signed !== "Valid";
    if (!unsigned && !userDir) continue;
    if (/\\(Microsoft|Discord|Spotify|Slack|Zoom|Dropbox|Google|OneDrive|Steam|Docker)\\/i.test(exe) && !unsigned) continue;
    add({
      check: "win.startup",
      severity: unsigned && userDir ? "medium" : "low",
      title: `"${s.name}" starts with Windows${unsigned ? " and isn't signed" : ""}`,
      why: "Malware keeps itself running by adding a startup entry. Unsigned programs from your user folders are worth a look.",
      where: exe,
      evidence: s.signer ? `signed by ${String(s.signer).split(",")[0]}` : unsigned ? `signature: ${s.signed}` : undefined,
      fix: s.key === "folder" ? { fixer: "none", action: "Review this startup item", params: {}, manual: `Remove ${s.cmd} from the Startup folder if you don't recognize it.` } : { fixer: "win.startup-disable", action: `Stop "${s.name}" from starting with Windows`, params: { key: s.key, name: s.name, reliance: "running-app" } },
    });
  }
  for (const t of asArray(f.tasks) as any[]) {
    const exe = String(t.exe ?? "");
    if (/\\(AppData\\Local\\Temp|Temp|Downloads|Public)\\/i.test(exe) || /\b(powershell|mshta|wscript|cscript|rundll32)\b.*\b(-enc|http|frombase64)/i.test(`${exe} ${t.args}`)) {
      add({ check: "win.task", severity: "high", title: `Scheduled task "${t.name}" looks suspicious`, why: "It runs a script or program from a temp or download folder, a common malware pattern.", where: `${t.path}${t.name}`, evidence: `${exe} ${String(t.args).slice(0, 80)}`.trim(), fix: { fixer: "none", action: "Review this task", params: {}, manual: "Open Task Scheduler and disable it if you don't recognize it." } });
    }
  }
}

function fmtDate(s: string) {
  return new Date(s).toLocaleDateString("en-US", { month: "long", day: "numeric", year: "numeric", timeZone: "UTC" });
}

export async function scanWindows(ctx: ScanCtx) {
  let facts: WinFacts | null = null;
  await ctx.step("system", "win.facts", "Reading Windows security settings", async () => {
    facts = await gatherWinFacts();
  });
  if (!facts) return;
  const results = judgeWindows(facts);
  const byLayer: Record<string, typeof results> = {};
  for (const r of results) (byLayer[r.layer] ??= []).push(r);
  for (const [layer, label] of [
    ["system", "Updates, antivirus, encryption, sign-in"],
    ["network", "Firewall, open ports, remote access, Wi-Fi"],
    ["apps", "Installed apps, startup items, tasks"],
  ] as const) {
    await ctx.step(layer, `win.${layer}`, label, async () => {
      for (const r of byLayer[layer] ?? []) ctx.report(r, "machine");
    }, "machine");
  }
}

// macOS: system, network and apps layers. Read-only facts, then rules (testable on saved facts).
import { readFileSync } from "node:fs";
import type { ScanCtx } from "../context";
import type { Finding } from "../types";
import { sh } from "../util";

export type MacFacts = Record<string, string>;

const FACTS = `
k() { printf '%s\\t' "$1"; shift; "$@" 2>&1 | tr '\\n' '\\037'; printf '\\n'; }
k product sw_vers -productVersion
k filevault fdesetup status
k firewall /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate
k stealth /usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode
k gatekeeper spctl --status
k sip csrutil status
k autoupdate defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled
k autodownload defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload
k critical defaults read /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall
k osupdates defaults read /Library/Preferences/com.apple.commerce AutoUpdate
k autologin defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser
k guest defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled
k groups id -Gn
k screenlock sysadminctl -screenLock status
k airdrop defaults read com.apple.sharingd DiscoverableMode
k sshd launchctl print system/com.openssh.sshd
k screenshare launchctl print system/com.apple.screensharing
k smbd launchctl print system/com.apple.smbd
k ard pgrep -x ARDAgent
k listen lsof -nP -iTCP -sTCP:LISTEN
k agents ls -1 "$HOME/Library/LaunchAgents" /Library/LaunchAgents /Library/LaunchDaemons
k apps ls -1 /Applications
k procs ps -axco comm
`;

export async function gatherMacFacts(): Promise<MacFacts> {
  if (process.env.LOCKDOWN_MAC_FACTS) return JSON.parse(readFileSync(process.env.LOCKDOWN_MAC_FACTS, "utf8"));
  const r = await sh(FACTS, 120_000);
  const f: MacFacts = {};
  for (const line of r.stdout.split("\n")) {
    const i = line.indexOf("\t");
    if (i > 0) f[line.slice(0, i)] = line.slice(i + 1).replace(/\x1f/g, "\n").trim();
  }
  return f;
}

const REMOTE_APPS = /^(AnyDesk|TeamViewer|RustDesk|Splashtop.*|LogMeIn.*|ScreenConnect.*|UltraViewer|Chrome Remote Desktop.*)\.app$/i;
const DB_PORTS: Record<string, string> = { "3306": "MySQL", "5432": "Postgres", "6379": "Redis", "27017": "MongoDB", "9200": "Elasticsearch", "11211": "Memcached" };

export function judgeMac(f: MacFacts): Omit<Finding, "id">[] {
  const out: Omit<Finding, "id">[] = [];
  const add = (x: Omit<Finding, "id">) => out.push(x);
  const major = Number((f.product ?? "").split(".")[0]);
  // Apple patches the current macOS and the two before it. 15 = Sequoia, 26 = Tahoe, 27 = 2026's release.
  if (major && major < 15) {
    add({ layer: "system", check: "mac.os-support", severity: "critical", title: `macOS ${f.product} no longer gets all security fixes`, why: "Apple only fully patches the latest macOS and the two before it.", fix: { fixer: "mac.open", action: "Update macOS to the latest version", params: { url: "x-apple.systempreferences:com.apple.Software-Update-Settings.extension" }, manual: "Upgrade to the latest macOS in System Settings > General > Software Update." } });
  }
  if (!/FileVault is On/i.test(f.filevault ?? "")) {
    add({ layer: "system", check: "mac.filevault", severity: "high", title: "FileVault disk encryption is off", why: "If this Mac is lost or stolen, anyone can read every file and saved key on it.", fix: { fixer: "mac.open", action: "Turn on disk encryption", params: { url: "x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension?FileVault" }, manual: "Turn on FileVault in System Settings > Privacy & Security. Save the recovery key somewhere safe." } });
  }
  if (!/enabled|State = 1|State = 2/i.test(f.firewall ?? "") || /disabled/i.test(f.firewall ?? "")) {
    add({ layer: "network", check: "mac.firewall", severity: "high", title: "The macOS firewall is off", why: "Any service on this Mac can be reached by everyone on the same Wi-Fi.", fix: { fixer: "mac.admin", action: "Turn the firewall on", admin: true, params: { cmd: "/usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on", undo: "/usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate off" } } });
  } else if (!/enabled|on/i.test(f.stealth ?? "")) {
    add({ layer: "network", check: "mac.stealth", severity: "low", title: "Stealth mode is off", why: "Your Mac answers probes, so scanners on public Wi-Fi can find it.", fix: { fixer: "mac.admin", action: "Turn on stealth mode", admin: true, params: { cmd: "/usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on", undo: "/usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode off" } } });
  }
  if (/disabled/i.test(f.gatekeeper ?? "")) {
    add({ layer: "system", check: "mac.gatekeeper", severity: "critical", title: "Gatekeeper is off", why: "Your Mac runs any downloaded app without checking who made it.", fix: { fixer: "mac.admin", action: "Turn Gatekeeper back on", admin: true, params: { cmd: "spctl --master-enable", undo: "spctl --master-disable", reliance: "unsigned-scripts" } } });
  }
  if (/disabled/i.test(f.sip ?? "")) {
    add({ layer: "system", check: "mac.sip", severity: "high", title: "System Integrity Protection is off", why: "Malware can change core system files.", fix: { fixer: "none", action: "Turn SIP back on", params: {}, manual: "Restart into Recovery, open Terminal, run csrutil enable." } });
  }
  const autoKeys: [string, string][] = [["autoupdate", "AutomaticCheckEnabled"], ["autodownload", "AutomaticDownload"], ["critical", "CriticalUpdateInstall"]];
  const offUpd = autoKeys.filter(([k]) => (f[k] ?? "").trim() === "0");
  if (offUpd.length) {
    add({ layer: "system", check: "mac.autoupdate", severity: "high", title: "Automatic security updates are off", why: "Security fixes wait until you install them by hand.", fix: { fixer: "mac.admin", action: "Turn on automatic security updates", admin: true, params: { cmd: offUpd.map(([, key]) => `defaults write /Library/Preferences/com.apple.SoftwareUpdate ${key} -bool true`).join(" && "), undo: offUpd.map(([, key]) => `defaults write /Library/Preferences/com.apple.SoftwareUpdate ${key} -bool false`).join(" && ") } } });
  }
  if (f.autologin && !/does not exist/i.test(f.autologin)) {
    add({ layer: "system", check: "mac.autologin", severity: "high", title: "Your Mac signs in by itself", why: "Anyone who opens the lid is signed in as you.", fix: { fixer: "mac.admin", action: "Turn off automatic sign-in", admin: true, params: { cmd: "defaults delete /Library/Preferences/com.apple.loginwindow autoLoginUser", undo: `defaults write /Library/Preferences/com.apple.loginwindow autoLoginUser '${f.autologin.replace(/'/g, "")}'` } } });
  }
  if ((f.guest ?? "").trim() === "1") {
    add({ layer: "system", check: "mac.guest", severity: "medium", title: "The guest account is on", why: "It gives anyone a way to use this Mac without a password.", fix: { fixer: "mac.admin", action: "Turn off the guest account", admin: true, params: { cmd: "defaults write /Library/Preferences/com.apple.loginwindow GuestEnabled -bool false", undo: "defaults write /Library/Preferences/com.apple.loginwindow GuestEnabled -bool true" } } });
  }
  if (/\badmin\b/.test(f.groups ?? "")) {
    add({ layer: "system", check: "mac.daily-admin", severity: "low", title: "You use an admin account every day", why: "Any installer you approve can change the whole system. A standard account limits the damage.", fix: { fixer: "none", action: "Use a standard account day to day", params: {}, manual: "Make a separate admin account, then turn off 'Allow this user to administer this computer' for yours." } });
  }
  const lock = f.screenlock ?? "";
  const delay = Number(lock.match(/(\d+)\s*seconds/)?.[1] ?? (/immediate/i.test(lock) ? 0 : NaN));
  if (/off/i.test(lock) || delay > 300) {
    add({ layer: "system", check: "mac.screenlock", severity: "medium", title: "Your Mac doesn't lock right away", why: "Anyone nearby can use it while the screen is asleep.", evidence: lock.split("\n")[0], fix: { fixer: "none", action: "Require your password right after sleep", params: {}, manual: "System Settings > Lock Screen > Require password after screen saver begins: Immediately." } });
  }
  if (/everyone/i.test(f.airdrop ?? "")) {
    add({ layer: "network", check: "mac.airdrop", severity: "medium", title: "AirDrop is open to everyone", why: "Strangers nearby can send you files and see your device name.", fix: { fixer: "mac.user", action: "Set AirDrop to Contacts Only", params: { cmd: "defaults write com.apple.sharingd DiscoverableMode -string 'Contacts Only'", undo: "defaults write com.apple.sharingd DiscoverableMode -string 'Everyone'" } } });
  }
  const running = (k: string) => (f[k] ?? "") && !/Could not find|not find service|Bad request/i.test(f[k]) && /state = running|pid =/i.test(f[k]);
  if (running("sshd") || /\*:22 \(LISTEN\)/.test(f.listen ?? "")) {
    add({ layer: "network", check: "mac.ssh", severity: "high", title: "Remote Login (SSH) is on", why: "Anyone on your network can try to sign in to this Mac.", fix: { fixer: "mac.admin", action: "Turn off Remote Login", admin: true, params: { reliance: "remote-access", cmd: "launchctl disable system/com.openssh.sshd && launchctl bootout system/com.openssh.sshd", undo: "launchctl enable system/com.openssh.sshd && launchctl bootstrap system /System/Library/LaunchDaemons/ssh.plist" } } });
  }
  if (running("screenshare") || /\*:5900 \(LISTEN\)/.test(f.listen ?? "")) {
    add({ layer: "network", check: "mac.screenshare", severity: "high", title: "Screen Sharing is on", why: "Others on your network can try to view and control this Mac.", fix: { fixer: "mac.admin", action: "Turn off Screen Sharing", admin: true, params: { reliance: "remote-access", cmd: "launchctl disable system/com.apple.screensharing && launchctl bootout system/com.apple.screensharing", undo: "launchctl enable system/com.apple.screensharing && launchctl bootstrap system /System/Library/LaunchDaemons/com.apple.screensharing.plist" } } });
  }
  if (running("smbd") || /\*:445 \(LISTEN\)/.test(f.listen ?? "")) {
    add({ layer: "network", check: "mac.filesharing", severity: "medium", title: "File Sharing is on", why: "Other computers on your network can reach shared folders on this Mac.", fix: { fixer: "mac.admin", action: "Turn off File Sharing", admin: true, params: { reliance: "file-sharing", cmd: "launchctl disable system/com.apple.smbd && launchctl bootout system/com.apple.smbd", undo: "launchctl enable system/com.apple.smbd && launchctl bootstrap system /System/Library/LaunchDaemons/com.apple.smbd.plist" } } });
  }
  if ((f.ard ?? "").trim() && /^\d+/.test(f.ard.trim())) {
    add({ layer: "network", check: "mac.ard", severity: "high", title: "Remote Management is running", why: "Apple Remote Desktop gives full control of this Mac to anyone who can sign in.", fix: { fixer: "none", action: "Turn off Remote Management", params: {}, manual: "System Settings > General > Sharing > Remote Management: off." } });
  }
  const seen = new Set<string>();
  for (const line of (f.listen ?? "").split("\n").slice(1)) {
    const m = line.match(/^(\S+)\s+(\d+).*?TCP (\*|0\.0\.0\.0|\[::\]):(\d+) \(LISTEN\)/);
    if (!m) continue;
    const [, proc, pid, , port] = m;
    if (["22", "445", "5900", "88", "5000", "7000"].includes(port) || seen.has(port) || Number(port) >= 49152) continue;
    seen.add(port);
    const db = DB_PORTS[port];
    add({ layer: "network", check: "mac.open-port", severity: db ? "high" : "medium", title: db ? `${db} is reachable from your network` : `${proc} is reachable from your network on port ${port}`, why: db ? "Databases on a laptop usually have no password. Anyone on the same Wi-Fi can read or wipe them." : "Anyone on the same Wi-Fi can reach it, including coffee shops and airports.", where: `port ${port} · ${proc}`, fix: { fixer: "none", action: "Bind it to localhost", params: { pid }, manual: `Start ${proc} with host 127.0.0.1 instead of 0.0.0.0, or turn on the firewall's "Block all incoming connections".` } });
  }
  for (const a of (f.apps ?? "").split("\n")) {
    if (REMOTE_APPS.test(a)) add({ layer: "apps", check: "mac.remote-tool", severity: "medium", title: `${a.replace(/\.app$/, "")} is installed`, why: "Remote-control apps are the #1 tool in tech-support scams. If you don't use it, remove it.", where: `/Applications/${a}`, fix: { fixer: "none", action: "Remove it if you don't use it", params: {}, manual: `Drag /Applications/${a} to the Trash.` } });
  }
  for (const p of (f.procs ?? "").split("\n")) {
    if (/^(ngrok|cloudflared|frpc|bore)$/.test(p.trim())) add({ layer: "apps", check: "mac.tunnel", severity: "high", title: `${p.trim()} is running`, why: "A tunnel puts a service on this Mac on the public internet.", fix: { fixer: "none", action: "Stop it when you're done", params: {}, manual: `Quit ${p.trim()} when you're not using it.` } });
  }
  return out;
}

export async function scanMac(ctx: ScanCtx) {
  let facts: MacFacts | null = null;
  await ctx.step("system", "mac.facts", "Reading macOS security settings", async () => {
    facts = await gatherMacFacts();
  });
  if (!facts) return;
  const results = judgeMac(facts);
  for (const [layer, label] of [["system", "Updates, encryption, Gatekeeper, sign-in"], ["network", "Firewall, sharing, remote access, open ports"], ["apps", "Remote-control apps and tunnels"]] as const) {
    await ctx.step(layer, `mac.${layer}`, label, async () => {
      for (const r of results.filter((x) => x.layer === layer)) ctx.report(r, "machine");
    }, "machine");
  }
}

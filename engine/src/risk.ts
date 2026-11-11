// Break-risk detection: before a fix runs, work out what it could break on this machine or repo,
// using live evidence where we can get it, and say it in plain words.
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { basename, dirname, join } from "node:path";
import type { BreakRisk, Finding } from "./types";
import { asArray, IS_WIN, ps, run } from "./util";

export async function detectRisks(f: Finding): Promise<BreakRisk[]> {
  const fix = f.fix;
  if (!fix) return [];
  const p = fix.params as any;
  const risks: BreakRisk[] = [];
  const add = (r: BreakRisk) => risks.push(r);

  switch (fix.fixer) {
    case "win.service": {
      if (p.name === "sshd") {
        const tailscale = IS_WIN ? await ps<any>("(Get-Process tailscaled -ErrorAction SilentlyContinue) -ne $null | ConvertTo-Json") : null;
        if (p.peers > 0) add({ reliance: "remote-access", level: "likely", says: "This will cut off someone connected over SSH right now.", evidence: `${p.peers} SSH connection${p.peers > 1 ? "s" : ""} open` });
        else add({ reliance: "remote-access", level: tailscale ? "likely" : "possible", says: tailscale ? "This might break SSH into this PC from your other devices over Tailscale." : "This might break SSH into this PC from your other devices.", evidence: tailscale ? "Tailscale, an app for reaching this computer remotely, is running" : undefined });
      } else add({ reliance: "remote-access", level: "possible", says: `This might break tools that manage this PC remotely through ${p.name}.` });
      break;
    }
    case "win.fw-block": {
      const what = p.proc === "java" ? "a Java server (often a Minecraft server)" : p.proc === "node" ? "a Node dev server" : p.proc ?? "this program";
      // Dev tools and apps listening on high ports are usually the person's own work (a dev server, a game
      // server, an app's helper). Blocking them by surprise breaks their setup, so those always ask first.
      const own = /^(node|bun|deno|java|javaw|python\d*|pythonw|ruby|php|dotnet|go|cargo|electron|code|cursor|windsurf|idea64|pycharm64|webstorm64|rider64|studio64|docker.*|wsl.*|vmmem.*)$/i.test(String(p.proc ?? "").replace(/\.exe$/i, ""));
      add({ reliance: "lan-dev-servers", level: p.lanPeers > 0 || own || Number(p.port) >= 10000 ? "likely" : "possible", says: `This might break other devices on your network reaching ${what} on port ${p.port}. It keeps working on this PC.`, evidence: p.lanPeers > 0 ? `${p.lanPeers} device${p.lanPeers > 1 ? "s are" : " is"} connected to it now` : undefined });
      break;
    }
    case "win.reg": {
      if (p.reliance === "remote-access") add({ reliance: "remote-access", level: p.sessions > 0 ? "likely" : "possible", says: "This might break Remote Desktop into this PC.", evidence: p.sessions > 0 ? "a Remote Desktop session is open now" : undefined });
      if (p.risk === "drivers") add({ reliance: "running-app", level: "possible", says: "This might stop an old driver from loading (usually old anti-cheat, VPN or audio drivers). Takes effect after a restart." });
      if (p.risk === "lsa") add({ reliance: "running-app", level: "possible", says: "This might stop old password-manager or smart-card plugins from loading. Takes effect after a restart." });
      break;
    }
    case "win.ps":
    case "win.ps-admin": {
      if (p.risk === "scripts") add({ reliance: "unsigned-scripts", level: "possible", says: "This might stop PowerShell scripts you downloaded from running until you unblock them." });
      if (p.reliance === "file-sharing") add({ reliance: "file-sharing", level: "possible", says: "This might break very old printers or network drives that only speak SMBv1." });
      break;
    }
    case "win.share-remove":
      add({ reliance: "file-sharing", level: "possible", says: `This might break other computers that open "${p.name}" over the network.` });
      break;
    case "win.startup-disable":
      // Only the person knows whether an unsigned startup program is theirs: always ask.
      add({ reliance: "startup-apps", level: "likely", says: `"${p.name}" won't start on its own anymore. You can still open it yourself.` });
      break;
    case "mac.admin":
      if (p.reliance) add({ reliance: p.reliance, level: "possible", says: p.reliance === "remote-access" ? "This might break connecting to this Mac from your other devices." : p.reliance === "file-sharing" ? "This might break other computers that open shared folders on this Mac." : "This might stop unsigned apps you rely on from opening." });
      break;
    case "files.quarantine":
      if (p.reliance) add({ reliance: "running-app", level: "possible", says: `This might break scripts or apps that read ${basename(p.path)} from ${basename(dirname(p.path))}.` });
      break;
    case "files.git-credentials":
      add({ reliance: "running-app", level: "possible", says: "Git might ask you to sign in once more for each site. After that it remembers you in the system keychain." });
      break;
    case "gh.visibility": {
      if (p.pages) add({ reliance: "public-repos", level: "likely", says: "This will take down this repo's GitHub Pages site on a free plan.", evidence: "GitHub Pages is on" });
      if (p.stars > 0 || p.forks > 0) add({ reliance: "public-repos", level: "likely", says: `This will lock out ${p.stars} people who starred it; ${p.forks} fork${p.forks === 1 ? "" : "s"} stay public and get detached for good.` });
      if (p.homepage) add({ reliance: "public-repos", level: "possible", says: `Links to the code from ${p.homepage} will stop working.` });
      // Who can see someone's code is their call, never an automatic fix.
      if (!risks.length) add({ reliance: "public-repos", level: "likely", says: "If you meant to share this code, people with the link won't see it anymore." });
      break;
    }
    case "gh.actions-perms": {
      const pushes = p.local ? workflowsThatWrite(p.localPath) : [];
      add({ reliance: "build", level: pushes.length ? "likely" : "possible", says: pushes.length ? `This will break workflow${pushes.length > 1 ? "s" : ""} ${pushes.slice(0, 2).join(", ")} that push or publish without asking for write access.` : "This might break a workflow that pushes commits or publishes releases without declaring write access.", evidence: pushes.length ? "they push or publish and have no permissions: block" : undefined });
      break;
    }
    case "gh.deploy-key":
      add({ reliance: "running-app", level: p.lastUsed && Date.now() - Date.parse(p.lastUsed) < 30 * 864e5 ? "likely" : "possible", says: `Deploys that only pull keep working. Anything that pushes with "${p.title}" will stop.`, evidence: p.lastUsed ? `last used ${String(p.lastUsed).slice(0, 10)}` : undefined });
      break;
    case "gh.webhook-ssl":
      add({ reliance: "running-app", level: "possible", says: "If the receiving server has a self-signed certificate, GitHub's deliveries to it will fail." });
      break;
    case "gcp.key-disable":
      add({ reliance: "running-app", level: "likely", says: `Anything that signs in with this key file (scripts, CI, servers) will stop working until it's turned back on.` });
      break;
    case "gcp.bucket-private":
      add({ reliance: "running-app", level: /public|static|assets|cdn|www|download|images|media|site/i.test(p.bucket) ? "likely" : "possible", says: `Files served straight from gs://${p.bucket} (images, downloads, a website) will stop loading for visitors.` });
      break;
    case "deps.npm":
      add({ reliance: "build", level: "possible", says: "Newer package versions might change how your app behaves. It lands as a pull request; your checks run before it merges." });
      break;
    case "code.patch":
      add({ reliance: "build", level: "possible", says: "A code change might affect how this feature works. It lands as a pull request so you can see the diff." });
      break;
    case "git.untrack":
      add({ reliance: "running-app", level: "possible", says: "Deploys that read this file from the repo will need it set as an environment variable instead." });
      break;
    case "git.purge-history":
      add({ reliance: "git-history", level: "likely", says: "This rewrites git history. Everyone with a copy has to clone again, and open pull requests break." });
      break;
  }
  return risks;
}

function workflowsThatWrite(repo?: string): string[] {
  if (!repo) return [];
  const dir = join(repo, ".github", "workflows");
  if (!existsSync(dir)) return [];
  return readdirSync(dir).filter((f) => {
    const t = readFileSync(join(dir, f), "utf8");
    return !/^\s*permissions\s*:/m.test(t) && /(git push|gh release|softprops\/action-gh-release|peaceiris\/actions-gh-pages|EndBug\/add-and-commit|stefanzweifel\/git-auto-commit|actions\/create-release|gh pr create)/.test(t);
  });
}

export const _test = { workflowsThatWrite, asArray, run };

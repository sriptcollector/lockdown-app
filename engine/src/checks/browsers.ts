// Browser risks: extensions with broad powers, Safe Browsing turned off. Reads profile files only.
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import type { ScanCtx } from "../context";
import { HOME, IS_MAC, IS_WIN } from "../util";

const BROWSERS = (): { name: string; dir: string }[] => {
  if (IS_WIN) {
    const L = process.env.LOCALAPPDATA ?? join(HOME, "AppData", "Local");
    return [
      { name: "Chrome", dir: join(L, "Google", "Chrome", "User Data") },
      { name: "Edge", dir: join(L, "Microsoft", "Edge", "User Data") },
      { name: "Brave", dir: join(L, "BraveSoftware", "Brave-Browser", "User Data") },
      { name: "Arc", dir: join(L, "Packages", "TheBrowserCompany.Arc_ttt1ap7aakyb4", "LocalCache", "Local", "Arc", "User Data") },
    ];
  }
  if (IS_MAC) {
    const A = join(HOME, "Library", "Application Support");
    return [
      { name: "Chrome", dir: join(A, "Google", "Chrome") },
      { name: "Edge", dir: join(A, "Microsoft Edge") },
      { name: "Brave", dir: join(A, "BraveSoftware", "Brave-Browser") },
      { name: "Arc", dir: join(A, "Arc", "User Data") },
    ];
  }
  return [{ name: "Chrome", dir: join(HOME, ".config", "google-chrome") }];
};

const POWERFUL = ["cookies", "webRequest", "webRequestBlocking", "debugger", "nativeMessaging", "proxy", "clipboardRead", "history", "management", "declarativeNetRequestWithHostAccess", "scripting", "tabCapture", "desktopCapture"];
const BROAD = (h: string) => /^(<all_urls>|\*:\/\/\*\/\*|https?:\/\/\*\/\*|\*:\/\/\*\/)$/.test(h);

function readJson(p: string): any {
  try {
    return JSON.parse(readFileSync(p, "utf8"));
  } catch {
    return null;
  }
}

function extName(dir: string, m: any): string {
  let n = String(m?.name ?? "?");
  const k = n.match(/^__MSG_(.+)__$/)?.[1];
  if (k) {
    for (const loc of [m.default_locale, "en", "en_US"].filter(Boolean)) {
      const msgs = readJson(join(dir, "_locales", loc, "messages.json"));
      const hit = msgs && Object.entries(msgs).find(([kk]) => kk.toLowerCase() === k.toLowerCase());
      if (hit) {
        n = (hit[1] as any).message;
        break;
      }
    }
  }
  return n;
}

export async function scanBrowsers(ctx: ScanCtx) {
  await ctx.step("apps", "browser.extensions", "Browser extensions and safety settings", async () => {
    let any = false;
    for (const b of BROWSERS()) {
      if (!existsSync(b.dir)) continue;
      any = true;
      const profiles = readdirSync(b.dir).filter((d) => d === "Default" || /^Profile \d+$/.test(d));
      const risky: { name: string; why: string; store: boolean }[] = [];
      let safeOff = false;
      for (const prof of profiles) {
        const prefs = readJson(join(b.dir, prof, "Preferences"));
        if (prefs?.safebrowsing?.enabled === false) safeOff = true;
        const secure = readJson(join(b.dir, prof, "Secure Preferences"));
        const settings = { ...(prefs?.extensions?.settings ?? {}), ...(secure?.extensions?.settings ?? {}) };
        const extRoot = join(b.dir, prof, "Extensions");
        if (!existsSync(extRoot)) continue;
        for (const id of readdirSync(extRoot)) {
          const s = settings[id] ?? {};
          if (s.state === 0 || (s.disable_reasons && s.disable_reasons !== 0 && !Array.isArray(s.disable_reasons)) || (Array.isArray(s.disable_reasons) && s.disable_reasons.length)) continue;
          const vers = readdirSync(join(extRoot, id));
          const vdir = join(extRoot, id, vers[vers.length - 1] ?? "");
          const m = readJson(join(vdir, "manifest.json"));
          if (!m) continue;
          const perms: string[] = [...(m.permissions ?? []), ...(m.optional_permissions ?? [])].filter((x: any) => typeof x === "string");
          const hosts: string[] = [...(m.host_permissions ?? []), ...perms, ...((m.content_scripts ?? []).flatMap((c: any) => c.matches ?? []))];
          const broad = hosts.some(BROAD);
          const power = perms.filter((p) => POWERFUL.includes(p));
          const store = s.from_webstore !== false && s.location !== 4;
          if ((broad && power.length) || (!store && broad)) {
            risky.push({ name: extName(vdir, m), why: power.slice(0, 3).join(", "), store });
          }
        }
      }
      const offStore = risky.filter((r) => !r.store);
      if (offStore.length) {
        ctx.report({ layer: "apps", check: "browser.ext-sideloaded", severity: "high", title: `${offStore.length} ${b.name} extension${offStore.length > 1 ? "s" : ""} not from the store can read every site`, why: "Sideloaded extensions skip the store's review. Ones that see every page can read your logins, cookies and messages.", where: b.name, evidence: offStore.map((r) => r.name).slice(0, 5).join(", "), fix: { fixer: "none", action: "Remove the ones you don't need", params: {}, manual: `Open ${b.name}'s extensions page and remove anything you don't recognize or use.` } }, "machine");
      }
      const storeRisky = risky.filter((r) => r.store);
      if (storeRisky.length) {
        ctx.report({ layer: "apps", check: "browser.ext-broad", severity: storeRisky.length > 4 ? "medium" : "low", title: `${storeRisky.length} ${b.name} extension${storeRisky.length > 1 ? "s" : ""} can read and change every site you visit`, why: "Extensions get sold and updated with spyware; in 2024 and 2025 dozens of popular ones were hijacked this way. Fewer is safer.", where: b.name, evidence: storeRisky.map((r) => r.name).slice(0, 6).join(", "), fix: { fixer: "none", action: "Remove the ones you don't use", params: {}, manual: `Open ${b.name}'s extensions page and remove any you don't use every week.` } }, "machine");
      }
      if (safeOff) {
        ctx.report({ layer: "apps", check: "browser.safebrowsing", severity: "high", title: `Safe Browsing is off in ${b.name}`, why: "You won't be warned about phishing pages and malware downloads.", where: b.name, fix: { fixer: "none", action: "Turn on Safe Browsing", params: {}, manual: `${b.name} settings > Privacy and security > Security > Standard or Enhanced protection.` } }, "machine");
      }
    }
    if (!any) return "no Chromium browsers found";
  });
}

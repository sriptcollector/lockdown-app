// Sample scan for the demo and the product page. Every name here is made up.
import type { Ev, Finding } from "./state";

type F = Omit<Finding, "id"> & { id: string };
const f = (id: string, x: Omit<F, "id">): F => ({ id, ...x });

const FINDINGS: { at: number; layer: string; f: F }[] = [
  { at: 2.2, layer: "system", f: f("d1", { layer: "system", check: "win.os-support", severity: "critical", title: "Windows 11 23H2 stopped getting security updates", why: "Microsoft's last security fix for 23H2 was on November 11, 2025. Newer holes stay open until you move to the current version.", where: "Windows 11 Home 23H2", fix: { fixer: "win.open-settings", action: "Update Windows to the latest version", params: { uri: "ms-settings:windowsupdate" }, manual: "Install Windows 11, version 25H2. It's free and keeps your files and apps." } }) },
  { at: 3.0, layer: "files", f: f("d2", { layer: "files", check: "files.history-secrets", severity: "high", title: "2 secrets saved in your terminal history", why: "Anything you paste into a terminal is saved in plain text. Malware that steals files grabs these first.", where: "~/.zsh_history", evidence: "GitHub token, Stripe live key (ghp_••••••••••••7Q)", fix: { fixer: "files.scrub-lines", action: "Remove those lines from the history file", params: {} } }) },
  { at: 4.1, layer: "network", f: f("d3", { layer: "network", check: "win.sshd", severity: "high", title: "Anyone can try to sign in to this PC over SSH", why: "The SSH server is listening on every network. One weak or reused password lets someone in.", where: "port 22 · sshd", fix: { fixer: "win.service", action: "Stop the SSH server and keep it from starting", admin: true, params: {}, risks: [{ reliance: "remote-access", level: "likely", says: "This might break SSH into this PC from your other devices over Tailscale.", evidence: "Tailscale, an app for reaching this computer remotely, is running" }] } }) },
  { at: 5.2, layer: "network", f: f("d4", { layer: "network", check: "win.open-port", severity: "high", title: "Postgres is reachable from your network", why: "Databases on a laptop usually have no password. Anyone on the same Wi-Fi can read or wipe them.", where: "port 5432 · postgres", fix: { fixer: "win.fw-block", action: "Block other devices from reaching port 5432", admin: true, params: {} } }) },
  { at: 6.0, layer: "system", f: f("d5", { layer: "system", check: "win.encryption", severity: "high", title: "Your disk isn't encrypted", why: "If this laptop is lost or stolen, anyone can pull the drive and read every file and saved key on it.", where: "C:", fix: { fixer: "win.open-settings", action: "Turn on disk encryption", params: { uri: "ms-settings:deviceencryption" }, manual: "Turn on Device encryption in Settings > Privacy & security." } }) },
  { at: 7.4, layer: "code", f: f("d6", { layer: "code", check: "code.secret", severity: "critical", title: "A Stripe key committed in acme/storefront", why: "This repo is public. Bots scrape GitHub for keys within minutes of a push, so assume this key is in someone else's hands.", where: "acme/storefront/.env", evidence: "sk_l••••••••••••a9 · 3 commits", source: "gitleaks", fix: { fixer: "git.untrack", action: "Stop tracking .env and ignore it", pr: true, params: {}, manual: "Make a new Stripe key at dashboard.stripe.com/apikeys, then delete the old one." } }) },
  { at: 8.3, layer: "code", f: f("d7", { layer: "code", check: "code.client-secret", severity: "critical", title: "A server secret is built into acme/storefront's website code", why: "NEXT_PUBLIC_SUPABASE_SERVICE_KEY is copied into the JavaScript every visitor downloads. Anyone can open the browser tools and take it.", where: "acme/storefront/.env.production", evidence: "NEXT_PUBLIC_SUPABASE_SERVICE_KEY=eyJh••••••••••••J9", fix: { fixer: "none", action: "Get a new password for your website's database", params: { url: "https://supabase.com/dashboard" }, manual: "Rename it without NEXT_PUBLIC_, use it only in server code, and make a new key." } }) },
  { at: 9.6, layer: "code", f: f("d8", { layer: "code", check: "code.sql-string-concat", severity: "high", title: "SQL injection in acme/api", why: "SQL built by gluing user input into the query. Someone can rewrite the query and read or wipe your database.", where: "acme/api/src/routes/users.ts:42", source: "Opengrep", fix: { fixer: "code.patch", action: "Write a fix and open a pull request", pr: true, params: {} } }) },
  { at: 10.4, layer: "code", f: f("d9", { layer: "code", check: "code.deps", severity: "high", title: "6 packages with known holes in acme/api", why: "These versions have published attacks. Bots scan for apps running them.", where: "acme/api/package-lock.json", evidence: "next@14.1.0 (CVE-2025-29927), axios@1.6.0, ws@8.13.0 +3 more", source: "OSV-Scanner", fix: { fixer: "deps.npm", action: "Upgrade the affected packages", pr: true, params: {} } }) },
  { at: 11.5, layer: "code", f: f("d10", { layer: "code", check: "code.sourcemaps", severity: "medium", title: "acme/storefront ships its source code to the browser", why: "Source maps let anyone rebuild your original code, comments and all, from the live site.", where: "acme/storefront/vite.config.ts", fix: { fixer: "code.config-edit", action: "Turn off production source maps", pr: true, params: {} } }) },
  { at: 12.3, layer: "code", f: f("d11", { layer: "code", check: "code.no-rate-limit", severity: "medium", title: "acme/api's sign-in has no rate limit", why: "Bots can try thousands of passwords or one-time codes a minute until one works.", where: "acme/api/src/routes/auth.ts", fix: { fixer: "code.patch", action: "Add a rate limit to sign-in routes", pr: true, params: {} } }) },
  { at: 13.4, layer: "github", f: f("d12", { layer: "github", check: "gh.public-repo", severity: "high", title: "acme/client-invoices is public", why: "Its name suggests private work, and anyone on the internet can read all of its code and history.", where: "acme/client-invoices", fix: { fixer: "gh.visibility", action: "Make the repo private", params: {} } }) },
  { at: 14.2, layer: "github", f: f("d13", { layer: "github", check: "gh.actions-write", severity: "medium", title: "Workflows in acme/storefront get write access by default", why: "Any workflow step, including third-party actions, can push code with the built-in token.", where: "acme/storefront", fix: { fixer: "gh.actions-perms", action: "Make workflow tokens read-only by default", params: {}, risks: [{ reliance: "build", level: "likely", says: "This will break workflow release.yml that publishes without asking for write access.", evidence: "it publishes and has no permissions: block" }] } }) },
  { at: 15.0, layer: "github", f: f("d14", { layer: "github", check: "gh.deploy-key", severity: "medium", title: "Deploy key \"vps\" can push to acme/api", why: "Whoever holds this key can change your code. Most deploys only need to read.", where: "acme/api", fix: { fixer: "gh.deploy-key", action: "Replace it with a read-only key", params: {} } }) },
  { at: 15.8, layer: "github", f: f("d15", { layer: "github", check: "gh.push-protection", severity: "medium", title: "Push protection is off for acme/storefront", why: "GitHub can block a push that contains a key before it goes public. It's free on public repos.", where: "acme/storefront", fix: { fixer: "gh.security-features", action: "Turn on secret scanning and push protection", params: {} } }) },
  { at: 16.9, layer: "files", f: f("d16", { layer: "files", check: "files.password-export", severity: "critical", title: "Password export sitting in Downloads", why: "An exported password list is every account you have in one unencrypted file.", where: "~/Downloads/Chrome Passwords.csv", fix: { fixer: "files.quarantine", action: "Lock it away in Lockdown's vault folder", params: {} } }) },
  { at: 17.6, layer: "files", f: f("d17", { layer: "files", check: "files.perms", severity: "medium", title: "SSH private key can be read by other accounts", why: "Other users and some services on this PC can read it.", where: "~/.ssh/id_ed25519", fix: { fixer: "files.restrict", action: "Make it readable only by you", params: {} } }) },
  { at: 18.8, layer: "apps", f: f("d18", { layer: "apps", check: "browser.ext-broad", severity: "medium", title: "5 Chrome extensions can read and change every site you visit", why: "Extensions get sold and updated with spyware. Fewer is safer.", where: "Chrome", evidence: "PDF Converter Pro, Coupon Finder, Tab Saver +2", fix: { fixer: "none", action: "Remove browser extensions you don't use", params: { url: "https://chromewebstore.google.com" }, manual: "Open Chrome's extensions page and remove any you don't use every week." } }) },
  { at: 19.7, layer: "apps", f: f("d19", { layer: "apps", check: "win.remote-tool", severity: "medium", title: "AnyDesk is installed", why: "Remote-control apps are the #1 tool in tech-support scams. If you don't use it, it's a door left open.", fix: { fixer: "none", action: "Uninstall AnyDesk if you don't use it", params: { uri: "ms-settings:appsfeatures" }, manual: "Uninstall AnyDesk in Settings > Apps." } }) },
  { at: 20.6, layer: "system", f: f("d20", { layer: "system", check: "win.file-ext", severity: "low", title: "File extensions are hidden", why: "A file called invoice.pdf.exe shows up as invoice.pdf, a common trick.", fix: { fixer: "win.reg", action: "Show file extensions", params: {} } }) },
  { at: 21.5, layer: "network", f: f("d21", { layer: "network", check: "win.open-wifi", severity: "medium", title: "3 open Wi-Fi networks will auto-join", why: "Attackers name fake hotspots after common open networks. Your PC joins them on its own.", evidence: "Airport Free WiFi, Hotel Guest, CoffeeShop", fix: { fixer: "win.wifi-forget", action: "Forget open Wi-Fi networks", params: {} } }) },
  { at: 22.6, layer: "cloud", f: f("d22", { layer: "cloud", check: "gcp.public-bucket", severity: "critical", title: "Anyone can upload to bucket acme-uploads", why: "Strangers can upload files, host malware on your account, and run up your bill.", where: "acme-prod · gs://acme-uploads", fix: { fixer: "gcp.bucket-private", action: "Remove public access from the bucket", params: {} } }) },
  { at: 23.4, layer: "cloud", f: f("d23", { layer: "cloud", check: "gcp.sa-key", severity: "high", title: "Downloadable key for deployer (412 days old)", why: "Service-account key files never expire. If one leaks, it works until someone notices.", where: "acme-prod · deployer@", fix: { fixer: "gcp.key-disable", action: "Turn the key off (can be turned back on)", params: {}, risks: [{ reliance: "running-app", level: "likely", says: "Anything that signs in with this key file (scripts, CI, servers) will stop working until it's turned back on." }] } }) },
];

const CHECKS: { at: number; end: number; layer: string; check: string; label: string; target?: string }[] = [
  { at: 0.3, end: 2.4, layer: "system", check: "win.facts", label: "Reading Windows security settings" },
  { at: 0.4, end: 3.2, layer: "files", check: "files.history", label: "Shell and console history" },
  { at: 0.5, end: 6.4, layer: "network", check: "win.network", label: "Firewall, open ports, remote access" },
  { at: 2.5, end: 6.2, layer: "system", check: "win.system", label: "Updates, antivirus, encryption, sign-in" },
  { at: 6.6, end: 9.0, layer: "code", check: "code.secrets", label: "Leaked keys in acme/storefront", target: "repo:storefront" },
  { at: 7.0, end: 9.8, layer: "code", check: "code.secrets", label: "Leaked keys in acme/api", target: "repo:api" },
  { at: 9.0, end: 12.6, layer: "code", check: "code.patterns", label: "Injection, auth, CORS, debug endpoints" },
  { at: 9.4, end: 11.0, layer: "code", check: "code.deps", label: "Known-vulnerable packages" },
  { at: 12.8, end: 16.2, layer: "github", check: "gh.repos", label: "Settings on 14 repos" },
  { at: 16.3, end: 18.2, layer: "files", check: "files.exports", label: "Password exports and key files" },
  { at: 18.3, end: 20.2, layer: "apps", check: "browser.extensions", label: "Browser extensions and startup items" },
  { at: 20.3, end: 22.0, layer: "network", check: "win.wifi", label: "Saved Wi-Fi networks" },
  { at: 21.8, end: 24.0, layer: "cloud", check: "gcp.project", label: "acme-prod: keys and buckets" },
];

const TARGETS = [
  { kind: "machine", id: "machine", name: "Studio laptop", layer: "system" },
  ...["storefront", "api", "landing", "mobile", "admin", "scripts"].map((n) => ({ kind: "repo", id: `repo:${n}`, name: `acme/${n}`, layer: "code" })),
  ...["storefront", "api", "landing", "client-invoices", "mobile", "admin", "docs", "infra"].map((n) => ({ kind: "github-repo", id: `ghr:${n}`, name: `acme/${n}`, layer: "github" })),
  { kind: "cloud", id: "gcp:acme-prod", name: "acme-prod", layer: "cloud" },
  { kind: "cloud", id: "gcp:acme-staging", name: "acme-staging", layer: "cloud" },
];

let timers: ReturnType<typeof setTimeout>[] = [];

export function demoScan(emit: (e: Ev) => void, speed = 1) {
  timers.forEach(clearTimeout);
  timers = [];
  const at = (s: number, e: Ev) => timers.push(setTimeout(() => emit(e), (s * 1000) / speed));
  at(0, { type: "start", runId: "demo", layers: ["code", "github", "system", "network", "files", "apps", "cloud"] });
  TARGETS.forEach((t, i) => at(0.05 + i * 0.04, { type: "target", target: t }));
  for (const c of CHECKS) {
    at(c.at, { type: "check-start", layer: c.layer, check: c.check, label: c.label, targetId: c.target });
    at(c.end, { type: "check-done", layer: c.layer, check: c.check, targetId: c.target, ms: (c.end - c.at) * 1000, status: "ok" });
  }
  for (const x of FINDINGS) at(x.at, { type: "finding", finding: x.f });
  at(24.4, { type: "done", summary: { runId: "demo", platform: "windows", score: 0, counts: {}, byLayer: {}, targets: TARGETS.length, checksRun: 86, checksSkipped: 0, fixable: 17 } });
}

let cancelledOnce = false;

export function demoFix(findings: Finding[], approve: string[], prefs: any, emit: (e: Ev) => void, only?: string[]) {
  const mode = prefs?.mode ?? "safe-auto";
  const keep: string[] = prefs?.keep ?? [];
  const items = findings.filter((x) => !only?.length || only.includes(x.id)).map((x) => {
    const risks = x.fix?.risks ?? [];
    const manual = !x.fix || x.fix.fixer === "none" || x.fix.fixer === "win.open-settings";
    const kept = risks.find((r) => keep.includes(r.reliance));
    const decision = manual ? "manual" : kept ? "skip" : risks.some((r) => r.level === "likely") && !approve.includes(x.id) ? "skip" : "apply";
    return { id: x.id, decision, reason: kept ? `you rely on this: ${kept.says}` : risks[0]?.says ?? (manual ? x.fix?.manual ?? "" : "safe"), risks };
  });
  emit({ type: "fix-plan", items });
  let t = 400;
  const apply = items.filter((i) => i.decision === "apply").map((i) => findings.find((y) => y.id === i.id)!);
  // Like the engine: everyday fixes first, then one admin prompt for the rest.
  // ?demo&cancel plays someone pressing No on that prompt the first time.
  const admin = apply.filter((x) => x.fix?.admin);
  const cancel = new URLSearchParams(location.search).has("cancel") && !cancelledOnce;
  for (const x of apply.filter((y) => !y.fix?.admin)) {
    setTimeout(() => emit({ type: "fix-start", findingId: x.id, action: x.fix!.action }), t);
    t += 550;
    setTimeout(() => emit({ type: "fix-done", change: { id: `demo:${x.id}`, findingId: x.id, result: x.fix!.pr ? "pr-opened" : "applied", note: x.fix!.pr ? "opened a pull request" : undefined } }), t);
  }
  if (admin.length) {
    for (const x of admin) setTimeout(() => emit({ type: "fix-start", findingId: x.id, action: x.fix!.action }), t);
    setTimeout(() => emit({ type: "admin-prompt", count: admin.length }), t + 100);
    t += 2800;
    if (cancel) cancelledOnce = true;
    for (const x of admin) setTimeout(() => emit({ type: "fix-done", change: { id: `demo:${x.id}`, findingId: x.id, result: cancel ? "failed" : "applied", note: cancel ? "admin prompt was cancelled" : undefined } }), t);
  }
  setTimeout(() => emit({ type: "fix-finished", runId: "demo-fix" }), t + 300);
}

// Same plain questions the engine asks, for the sample data.
export function demoQuestions(findings: Finding[]) {
  const ask: Record<string, [string, string, string, string]> = {
    "remote-access": ["Do you ever get into this computer from another device?", "Like controlling it from your phone or from another computer. Most people don't.", "Yes, keep that working", "No, lock it"],
    build: ["Lock down the steps that publish your code?", "Only matters if someone publishes a website or app from your GitHub. It might need a small change after.", "Not now", "Yes, fix them"],
    "running-app": ["Turn off old keys that could let someone in?", "A website or app that still uses one would stop until it gets a new one.", "Not now", "Yes, fix them"],
  };
  const by = new Map<string, Finding[]>();
  for (const f of findings) {
    const r = f.fix?.risks?.find((x) => x.level === "likely");
    if (r) (by.get(r.reliance) ?? by.set(r.reliance, []).get(r.reliance)!).push(f);
  }
  return [...by].map(([reliance, fs]) => {
    const a = ask[reliance] ?? ask["running-app"];
    const evidence = ["remote-access", "lan-dev-servers", "file-sharing"].includes(reliance) ? fs.flatMap((f) => f.fix?.risks ?? []).map((r) => r.evidence).find(Boolean) : undefined;
    const recommended = evidence ? "keep" : "fix";
    const options: { value: string; label: string; unsure?: boolean }[] = [{ value: "fix", label: a[3] }, { value: "keep", label: a[2] }];
    if (recommended === "keep") options.reverse();
    options.push({ value: "keep", label: "I'm not sure, leave it as it is", unsure: true });
    return { reliance, question: a[0], help: evidence ? `${a[1]} We noticed: ${evidence}.` : a[1], options, recommended, findingIds: fs.map((f) => f.id), touches: [...new Set(fs.map((f) => f.fix?.action ?? f.title))].slice(0, 3) };
  });
}

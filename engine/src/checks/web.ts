// Live sites, seen the way an attacker sees them: what the browser downloads (source maps,
// keys, AI prompts, unminified code), missing security headers, files that should never be
// served, and CORS that trusts any website. Read-only GET requests, a few per site.
import type { ScanCtx } from "../context";
import type { Finding } from "../types";
import { findSecrets } from "../secrets";
import { redact } from "../util";

type F = Omit<Finding, "id" | "layer">;
const UA = "Mozilla/5.0 (Lockdown security check; +https://lockdown.westwardconsulting.ai/about)";

async function get(url: string, headers: Record<string, string> = {}, max = 3_000_000) {
  try {
    const r = await fetch(url, { headers: { "user-agent": UA, ...headers }, redirect: "follow", signal: AbortSignal.timeout(15_000) });
    const buf = await r.arrayBuffer();
    return { status: r.status, headers: r.headers, url: r.url, text: Buffer.from(buf.slice(0, max)).toString("utf8") };
  } catch {
    return null;
  }
}

const AI_HOSTS = /https:\/\/(api\.openai\.com|api\.anthropic\.com|generativelanguage\.googleapis\.com|api\.groq\.com|api\.deepseek\.com|api\.elevenlabs\.io|openrouter\.ai\/api)/;
const PROMPT = /["'`](You are (a|an|the) [^"'`]{20,}|System prompt:[^"'`]{10,})/;
const SERVER_ONLY = /(sk_live_[A-Za-z0-9]{10,}|rk_live_[A-Za-z0-9]{10,}|sk-ant-api|sk-proj-[A-Za-z0-9_-]{20,}|service_role|sb_secret_|whsec_[A-Za-z0-9]{10,}|-----BEGIN [A-Z ]*PRIVATE KEY-----)/;

export async function auditSite(site: string): Promise<F[]> {
  const out: F[] = [];
  const add = (f: F) => out.push({ ...f, where: f.where ?? site });
  const home = await get(site);
  if (!home) return [{ check: "web.down", severity: "info", title: `${site} didn't answer`, why: "Couldn't load the page to check it.", where: site }];
  const host = new URL(home.url).host;
  const h = home.headers;

  // Headers
  if (!h.get("strict-transport-security")) add({ check: "web.hsts", severity: "low", title: `${host} doesn't force HTTPS`, why: "Without HSTS, someone on public Wi-Fi can downgrade a visitor's first request and read it.", fix: { fixer: "none", action: "Send Strict-Transport-Security", params: {}, manual: "Add the header Strict-Transport-Security: max-age=63072000; includeSubDomains." } });
  const csp = h.get("content-security-policy") ?? "";
  if (!csp) add({ check: "web.csp", severity: "medium", title: `${host} has no Content-Security-Policy`, why: "If anyone gets a script onto a page, nothing stops it from stealing sessions or rewriting the page.", fix: { fixer: "none", action: "Add a Content-Security-Policy", params: {}, manual: "Start with default-src 'self' and allow only the hosts the site needs." } });
  if (!/frame-ancestors/.test(csp) && !h.get("x-frame-options")) add({ check: "web.framing", severity: "low", title: `${host} can be framed by any site`, why: "Another site can load yours invisibly and trick visitors into clicking buttons (clickjacking).", fix: { fixer: "none", action: "Block framing", params: {}, manual: "Add frame-ancestors 'self' to the CSP, or X-Frame-Options: DENY." } });
  if (!h.get("x-content-type-options")) add({ check: "web.nosniff", severity: "low", title: `${host} is missing X-Content-Type-Options`, why: "Browsers may run an uploaded file as a script.", fix: { fixer: "none", action: "Send X-Content-Type-Options: nosniff", params: {}, manual: "Add the header X-Content-Type-Options: nosniff." } });
  const powered = h.get("x-powered-by");
  if (powered) add({ check: "web.powered-by", severity: "low", title: `${host} announces it runs ${powered}`, why: "It tells attackers exactly which exploits to try.", evidence: `X-Powered-By: ${powered}`, fix: { fixer: "none", action: "Remove the X-Powered-By header", params: {}, manual: "Turn it off in the framework (Next.js: poweredByHeader: false)." } });

  // What the browser downloads
  const scripts = [...home.text.matchAll(/<script[^>]+src=["']([^"']+)["']/g)].map((m) => new URL(m[1], home.url).href).filter((u) => new URL(u).host === host).slice(0, 25);
  let maps = 0;
  let mapExample = "";
  let unminified = 0;
  const secretHits: string[] = [];
  const aiCalls = new Set<string>();
  let promptExample = "";
  for (const s of scripts) {
    const js = await get(s);
    if (!js || js.status !== 200) continue;
    const text = js.text;
    const mapRef = text.match(/\/\/[#@] sourceMappingURL=([^\s]+)\s*$/m)?.[1];
    const mapUrl = mapRef && !mapRef.startsWith("data:") ? new URL(mapRef, s).href : `${s}.map`;
    const m = await get(mapUrl, {}, 200_000);
    if (m && m.status === 200 && /"mappings"\s*:/.test(m.text) && /"sources(Content)?"\s*:/.test(m.text)) {
      maps++;
      mapExample ||= new URL(mapUrl).pathname;
    } else if (mapRef?.startsWith("data:")) {
      maps++;
      mapExample ||= `${new URL(s).pathname} (inline)`;
    }
    const lines = text.split("\n");
    if (text.length > 20_000 && lines.length > 400 && text.length / lines.length < 60) unminified++;
    for (const hit of findSecrets(text).filter((x) => !["google", "bearer-cli", "db-url"].includes(x.rule.id))) secretHits.push(`${hit.rule.name} ${redact(hit.value)}`);
    const so = text.match(SERVER_ONLY);
    if (so) secretHits.push(`server-only value ${redact(so[0])}`);
    for (const a of text.matchAll(new RegExp(AI_HOSTS, "g"))) aiCalls.add(a[1]);
    promptExample ||= text.match(PROMPT)?.[1]?.slice(0, 70) ?? "";
  }
  if (maps) add({ check: "web.sourcemaps", severity: "high", title: `${host} serves its source code (source maps)`, why: "Anyone can download the original code, with comments, file names and logic, and copy or attack it.", evidence: `${maps} of ${scripts.length} scripts, e.g. ${mapExample}`, fix: { fixer: "none", action: "Stop publishing source maps", params: {}, manual: "Turn off production source maps (Next.js productionBrowserSourceMaps: false; Vite build.sourcemap: false) or upload them privately to your error tracker." } });
  if (unminified) add({ check: "web.unminified", severity: "low", title: `${host} ships readable, unminified code`, why: "Readable code is easy to copy and study for weaknesses.", evidence: `${unminified} script${unminified > 1 ? "s" : ""}`, fix: { fixer: "none", action: "Minify production builds", params: {}, manual: "Build in production mode with minification on." } });
  if (secretHits.length) add({ check: "web.client-secret", severity: "critical", title: `${host} sends a secret key to every visitor`, why: "Anything in the page's JavaScript is public. This key can be used by anyone.", evidence: [...new Set(secretHits)].slice(0, 3).join(", "), fix: { fixer: "none", action: "Move the key to the server and replace it", params: {}, manual: "Use the key only in server code, then make a new one at the provider and delete this one." } });
  if (aiCalls.size) add({ check: "web.client-ai", severity: "high", title: `${host} calls AI providers straight from the browser`, why: "The request, and usually the key and your prompts, are visible to anyone who opens the browser's network tab.", evidence: [...aiCalls].join(", "), fix: { fixer: "none", action: "Call the AI from your server", params: {}, manual: "Proxy AI calls through a server route that checks the user and keeps the key and prompt server-side." } });
  if (promptExample) add({ check: "web.client-prompt", severity: "medium", title: `${host} ships an AI prompt to the browser`, why: "Your prompts are product logic. In the bundle, anyone can copy them.", evidence: `"${promptExample}…"`, fix: { fixer: "none", action: "Keep prompts on the server", params: {}, manual: "Build prompts in a server route and send only the user's input from the browser." } });

  // Files that should never be served
  const probes: [string, RegExp, string][] = [
    ["/.env", /^\s*[A-Z][A-Z0-9_]+=.+/m, "The site's .env file is downloadable"],
    ["/.git/HEAD", /^ref: refs\//, "The site's git folder is downloadable"],
    ["/.git/config", /\[core\]/, "The site's git folder is downloadable"],
    ["/.DS_Store", /Bud1/, "A Mac folder index is downloadable"],
    ["/server-status", /Apache Server Status/i, "Apache server status is public"],
  ];
  for (const [path, sig, title] of probes) {
    const r = await get(new URL(path, home.url).href, {}, 20_000);
    if (r && r.status === 200 && sig.test(r.text) && !/<html/i.test(r.text.slice(0, 200))) {
      add({ check: "web.exposed-file", severity: "critical", title: `${title} (${host}${path})`, why: "Anyone can download it. It usually holds keys, passwords or the whole source history.", where: `${host}${path}`, fix: { fixer: "none", action: "Stop serving it and replace any keys in it", params: {}, manual: `Block ${path} on the server, then replace every key it contained.` } });
      break;
    }
  }
  for (const path of ["/api/debug", "/debug", "/api/env", "/api/config"]) {
    const r = await get(new URL(path, home.url).href, {}, 50_000);
    if (r && r.status === 200 && /^\s*[{[]/.test(r.text) && /(env|secret|key|token|password|database|NODE_)/i.test(r.text)) {
      add({ check: "web.debug-endpoint", severity: "high", title: `${host}${path} is open and returns internal settings`, why: "Debug endpoints leak configuration and sometimes keys.", where: `${host}${path}`, fix: { fixer: "none", action: "Remove it or require an admin sign-in", params: {}, manual: `Delete ${path} or put it behind admin auth.` } });
    }
  }

  // CORS: does it trust any website, with cookies?
  const evil = "https://lockdown-cors-check.example";
  for (const path of ["/", "/api/me", "/api/user", "/api/session", "/api/account"]) {
    const r = await get(new URL(path, home.url).href, { origin: evil }, 5_000);
    if (!r) continue;
    const acao = r.headers.get("access-control-allow-origin");
    const cred = r.headers.get("access-control-allow-credentials") === "true";
    if (acao === evil && cred) {
      add({ check: "web.cors", severity: "high", title: `${host} lets any website read signed-in responses`, why: "A page on any site can call this API as a signed-in visitor and read their data.", where: `${host}${path}`, evidence: `Origin reflected with credentials`, fix: { fixer: "none", action: "Allow only your own sites", params: {}, manual: "Set Access-Control-Allow-Origin to an allowlist of your domains." } });
      break;
    }
  }
  return out;
}

export async function scanSites(ctx: ScanCtx, sites: string[]) {
  for (const site of sites) {
    const tid = `site:${site}`;
    ctx.target({ kind: "cloud", id: tid, name: new URL(site).host, layer: "cloud" });
    await ctx.step("cloud", "web.site", `What an attacker sees on ${new URL(site).host}`, async () => {
      for (const f of await auditSite(site)) ctx.report({ layer: "cloud", ...f }, tid);
    }, tid);
  }
}

// Fixing is paid. Licenses are signed by the Lockdown server (Ed25519) and checked here offline.
import { createPublicKey, verify } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { dataDir } from "./util";
import publicPem from "./license-public.pem" with { type: "text" };

export const API = process.env.LOCKDOWN_API ?? "https://lockdown.westwardconsulting.ai";
const file = () => join(dataDir(), "account.json");

export interface Account {
  email?: string;
  session?: string;
  license?: string;
}

export function loadAccount(): Account {
  try {
    return existsSync(file()) ? JSON.parse(readFileSync(file(), "utf8")) : {};
  } catch {
    return {};
  }
}
export function saveAccount(a: Account) {
  writeFileSync(file(), JSON.stringify(a), { mode: 0o600 });
}

export function checkLicense(token?: string): { ok: boolean; plan: string; email?: string; until?: number } {
  if (!token) return { ok: false, plan: "free" };
  const [body, sig] = token.split(".");
  try {
    const good = verify(null, Buffer.from(body), createPublicKey(publicPem), Buffer.from(sig, "base64url"));
    const p = JSON.parse(Buffer.from(body, "base64url").toString());
    return good && p.until > Date.now() ? { ok: true, plan: p.plan, email: p.email, until: p.until } : { ok: false, plan: "free", email: p.email };
  } catch {
    return { ok: false, plan: "free" };
  }
}

/** Fixing is allowed with a valid license, or in the local sandbox test. CI buys a trial on staging like a customer. */
export function canFix(): boolean {
  if (process.env.LOCKDOWN_SANDBOX === "1") return true;
  return checkLicense(loadAccount().license).ok;
}

async function post(path: string, body: unknown, session?: string) {
  const r = await fetch(API + path, { method: body === undefined ? "GET" : "POST", headers: { "content-type": "application/json", ...(session ? { authorization: `Bearer ${session}` } : {}) }, body: body === undefined ? undefined : JSON.stringify(body) });
  const d = (await r.json().catch(() => ({}))) as any;
  if (!r.ok) throw new Error(d.error ?? "Couldn't reach Lockdown. Check your connection.");
  return d;
}

export const account = {
  start: (email: string) => post("/api/auth/start", { email }),
  async verify(email: string, code: string) {
    const d = await post("/api/auth/verify", { email, code });
    saveAccount({ email, session: d.session });
    return this.refresh();
  },
  async refresh() {
    const a = loadAccount();
    if (!a.session) return { signedIn: false, plan: "free" };
    const d = await post("/api/license", undefined, a.session).catch(() => null);
    if (d) saveAccount({ ...a, license: d.license ?? undefined });
    const lic = checkLicense(d?.license ?? a.license);
    return { signedIn: true, email: a.email, plan: lic.ok ? lic.plan : "free" };
  },
  async checkout(plan: "monthly" | "yearly", email?: string) {
    const a = loadAccount();
    return post("/api/checkout", { email: email ?? a.email, plan }, a.session);
  },
  async checkoutOpen(): Promise<boolean> {
    const r = await fetch(API + "/api/status").then((x) => x.json()).catch(() => ({ checkout: false }));
    return !!(r as any).checkout;
  },
  async summary(s: { score: number; platform: string; counts: Record<string, number>; fixed?: number }) {
    const a = loadAccount();
    if (a.session) await post("/api/summary", s, a.session).catch(() => {});
  },
};

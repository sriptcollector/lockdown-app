// Minimal GitHub REST client. Token comes from the app's GitHub connection
// (LOCKDOWN_GITHUB_TOKEN) or the GitHub CLI if it's signed in. Never logged.
import { run, scanStop } from "./util";

let tokenPromise: Promise<string | null> | null = null;

export function githubToken(): Promise<string | null> {
  if (!tokenPromise) {
    tokenPromise = (async () => {
      if (process.env.LOCKDOWN_GITHUB_TOKEN) return process.env.LOCKDOWN_GITHUB_TOKEN;
      const r = await run("gh", ["auth", "token"], { timeoutMs: 15_000 });
      const t = r.stdout.trim();
      return r.code === 0 && t ? t : null;
    })();
  }
  return tokenPromise;
}

export interface GhResponse<T = any> {
  status: number;
  data: T;
  scopes: string[];
}

export async function gh<T = any>(path: string, init: { method?: string; body?: unknown } = {}): Promise<GhResponse<T>> {
  // A stopped check makes no new GitHub calls (fixes never run while a check is stopping).
  if (scanStop.stopped && (init.method ?? "GET") === "GET") throw new Error("stopped early");
  const token = await githubToken();
  if (!token) throw new Error("GitHub isn't connected");
  const res = await fetch(path.startsWith("http") ? path : `https://api.github.com${path}`, {
    method: init.method ?? "GET",
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
      "User-Agent": "Lockdown",
      ...(init.body ? { "Content-Type": "application/json" } : {}),
    },
    body: init.body ? JSON.stringify(init.body) : undefined,
  });
  const text = await res.text();
  let data: any = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = text;
  }
  return { status: res.status, data, scopes: (res.headers.get("x-oauth-scopes") ?? "").split(",").map((s) => s.trim()).filter(Boolean) };
}

export async function ghAll<T = any>(path: string, max = 1000): Promise<T[]> {
  const out: T[] = [];
  let url: string | null = `https://api.github.com${path}${path.includes("?") ? "&" : "?"}per_page=100`;
  const token = await githubToken();
  while (url && out.length < max) {
    const res: Response = await fetch(url, { headers: { Authorization: `Bearer ${token}`, Accept: "application/vnd.github+json", "User-Agent": "Lockdown" } });
    if (!res.ok) break;
    const page = (await res.json()) as T[];
    out.push(...page);
    const link = res.headers.get("link") ?? "";
    url = link.match(/<([^>]+)>;\s*rel="next"/)?.[1] ?? null;
  }
  return out;
}

/** owner/repo from a git remote URL, if it's on github.com. */
export function parseGithubRemote(url: string): { owner: string; repo: string } | null {
  const m = url.trim().match(/github\.com[:/]([^/]+)\/([^/\s]+?)(\.git)?\/?$/i);
  return m ? { owner: m[1], repo: m[2] } : null;
}

const repoCache = new Map<string, Promise<any | null>>();
export function repoInfo(owner: string, repo: string): Promise<any | null> {
  const k = `${owner}/${repo}`.toLowerCase();
  if (!repoCache.has(k)) repoCache.set(k, gh(`/repos/${owner}/${repo}`).then((r) => (r.status === 200 ? r.data : null)).catch(() => null));
  return repoCache.get(k)!;
}

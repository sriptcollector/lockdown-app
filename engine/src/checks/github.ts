// GitHub layer: account and repo settings, read through the API.
import type { ScanCtx } from "../context";
import type { Finding } from "../types";
import { gh, ghAll, githubToken } from "../gh";
import type { RepoMeta } from "./repos";

type F = Omit<Finding, "id" | "layer">;

async function pool<T>(items: T[], n: number, fn: (x: T) => Promise<void>) {
  let i = 0;
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, async () => { while (i < items.length) await fn(items[i++]); }));
}

const PRIVATE_NAME = /(client|internal|private|secret|backup|prod|admin|crm|invoice|payroll|customer|leads|personal|keys|creds|credentials)/i;

export async function scanGithub(ctx: ScanCtx, localRepos: RepoMeta[]) {
  const token = await githubToken();
  if (!token) {
    await ctx.step("github", "gh.connect", "GitHub account", async () => "GitHub isn't connected");
    return;
  }
  const me = await gh("/user");
  if (me.status !== 200) {
    await ctx.step("github", "gh.connect", "GitHub account", async () => "GitHub sign-in expired");
    return;
  }
  const login: string = me.data.login;
  ctx.target({ kind: "github-account", id: `gh:${login}`, name: `@${login}`, layer: "github" });
  const report = (f: F, targetId = `gh:${login}`) => ctx.report({ layer: "github", ...f }, targetId);

  await ctx.step("github", "gh.account", `@${login} account security`, async () => {
    const tfa = me.data.two_factor_authentication;
    if (tfa === false) {
      report({ check: "gh.2fa", severity: "critical", title: "Two-factor sign-in is off on GitHub", why: "A leaked or reused password is all it takes to take over every repo you own.", fix: { fixer: "none", action: "Turn on two-factor sign-in", params: { url: "https://github.com/settings/security" }, manual: "Turn it on at github.com/settings/security. Use a passkey or an authenticator app, not SMS." } });
    }
    if (tfa == null && !me.scopes.includes("user") && !me.scopes.includes("read:user")) {
      // Can't see it with this token. The app's own GitHub connection asks for read:user.
    }
    const keys = await gh("/user/keys");
    if (keys.status === 200 && Array.isArray(keys.data)) {
      const old = keys.data.filter((k: any) => k.created_at && Date.now() - Date.parse(k.created_at) > 2 * 365 * 864e5);
      if (old.length) report({ check: "gh.old-ssh", severity: "low", title: `${old.length} SSH key${old.length > 1 ? "s are" : " is"} over two years old`, why: "Old keys on old laptops are a common way in. Remove keys you don't use.", evidence: old.map((k: any) => k.title).slice(0, 4).join(", "), fix: { fixer: "none", action: "Remove keys you don't recognize", params: {}, manual: "Review them at github.com/settings/keys." } });
    }
  });

  const only = process.env.LOCKDOWN_GITHUB_ONLY?.toLowerCase().split(",");
  const repos = (await ghAll<any>("/user/repos?affiliation=owner&sort=pushed", ctx.prefs.allGithubRepos ? 300 : 100)).filter((r) => !only || only.includes(r.full_name.toLowerCase()));
  const localNames = new Set(localRepos.filter((r) => r.gh).map((r) => `${r.gh!.owner}/${r.gh!.repo}`.toLowerCase()));
  const active = repos.filter((r) => !r.archived);
  for (const r of active) ctx.target({ kind: "github-repo", id: `ghr:${r.full_name}`, name: r.full_name, layer: "github" });

  const noDependabot: string[] = [];
  const forcePush: { repo: string; branch: string }[] = [];
  await ctx.step("github", "gh.repos", `Settings on ${active.length} repos`, async () => {
    await pool(active, 6, async (r) => {
      const tid = `ghr:${r.full_name}`;
      const full = r.full_name;
      // Public repos that look private
      if (!r.private && !r.fork) {
        const noLicense = !r.license;
        if (PRIVATE_NAME.test(r.name) || (noLicense && r.stargazers_count === 0 && r.forks_count === 0)) {
          report({
            check: "gh.public-repo",
            severity: PRIVATE_NAME.test(r.name) ? "high" : "medium",
            title: `${full} is public`,
            why: PRIVATE_NAME.test(r.name) ? "Its name suggests private work, and anyone on the internet can read all of its code and history." : "It has no license and no stars, so it's probably not meant to be open source. Anyone can read its code and history.",
            where: full,
            fix: { fixer: "gh.visibility", action: "Make the repo private", params: { repo: full, private: true, pages: r.has_pages, stars: r.stargazers_count, forks: r.forks_count, homepage: r.homepage } },
          }, tid);
        }
      }
      // Default workflow token permissions
      const wf = await gh(`/repos/${full}/actions/permissions/workflow`);
      if (wf.status === 200 && wf.data?.default_workflow_permissions === "write") {
        report({ check: "gh.actions-write", severity: "medium", title: `Workflows in ${full} get write access by default`, why: "Any workflow step, including third-party actions, can push code and change releases with the built-in token.", where: full, fix: { fixer: "gh.actions-perms", action: "Make workflow tokens read-only by default", params: { repo: full, local: localNames.has(full.toLowerCase()), localPath: localRepos.find((x) => x.gh && `${x.gh.owner}/${x.gh.repo}`.toLowerCase() === full.toLowerCase())?.path } } }, tid);
      }
      // Deploy keys that can push
      const keys = await gh(`/repos/${full}/keys`);
      if (keys.status === 200 && Array.isArray(keys.data)) {
        for (const k of keys.data.filter((k: any) => !k.read_only)) {
          report({ check: "gh.deploy-key", severity: "medium", title: `Deploy key "${k.title}" can push to ${full}`, why: "Whoever holds this key can change your code. Most deploys only need to read.", where: full, evidence: `added ${String(k.created_at).slice(0, 10)}${k.last_used ? `, last used ${String(k.last_used).slice(0, 10)}` : ""}`, fix: { fixer: "gh.deploy-key", action: "Replace it with a read-only key", params: { repo: full, id: k.id, title: k.title, key: k.key, lastUsed: k.last_used } } }, tid);
        }
      }
      // Webhooks without TLS checks
      const hooks = await gh(`/repos/${full}/hooks`);
      if (hooks.status === 200 && Array.isArray(hooks.data)) {
        for (const h of hooks.data) {
          const url = String(h.config?.url ?? "");
          if (h.config?.insecure_ssl === "1" || url.startsWith("http://")) {
            report({ check: "gh.webhook", severity: "medium", title: `A webhook on ${full} sends data without HTTPS checks`, why: "Anyone on the path can read or fake what GitHub sends.", where: full, evidence: url.replace(/\/\/([^/]+).*/, "//$1/…"), fix: h.config?.insecure_ssl === "1" ? { fixer: "gh.webhook-ssl", action: "Turn on HTTPS certificate checks", params: { repo: full, id: h.id } } : { fixer: "none", action: "Use an https:// URL", params: {}, manual: "Change the webhook URL to https://." } }, tid);
          }
          if (!h.config?.secret) {
            report({ check: "gh.webhook-secret", severity: "low", title: `A webhook on ${full} has no secret`, why: "The receiver can't tell real GitHub events from fakes.", where: full, fix: { fixer: "none", action: "Add a webhook secret", params: {}, manual: "Set a secret on the webhook and verify X-Hub-Signature-256 on the receiver." } }, tid);
          }
        }
      }
      // Free security features left off
      const va = await gh(`/repos/${full}/vulnerability-alerts`);
      if (va.status === 404) noDependabot.push(full);
      if (!r.private) {
        const sa = r.security_and_analysis ?? (await gh(`/repos/${full}`)).data?.security_and_analysis;
        if (sa && sa.secret_scanning_push_protection?.status !== "enabled") {
          report({ check: "gh.push-protection", severity: "medium", title: `Push protection is off for ${full}`, why: "GitHub can block a push that contains a key before it goes public. It's free on public repos.", where: full, fix: { fixer: "gh.security-features", action: "Turn on secret scanning and push protection", params: { repo: full, features: ["secret_scanning", "secret_scanning_push_protection"] } } }, tid);
        }
        const prot = await gh(`/repos/${full}/rulesets`);
        const hasRules = prot.status === 200 && Array.isArray(prot.data) && prot.data.length > 0;
        const bp = hasRules ? null : await gh(`/repos/${full}/branches/${encodeURIComponent(r.default_branch)}/protection`);
        if (!hasRules && bp && bp.status === 404) forcePush.push({ repo: full, branch: r.default_branch });
      }
    });
  });

  // Settings that are off across many repos are one finding with one fix.
  if (noDependabot.length) {
    report({ check: "gh.dependabot", severity: "low", title: `Dependabot alerts are off on ${noDependabot.length} repo${noDependabot.length > 1 ? "s" : ""}`, why: "GitHub won't tell you when a package you use gets a known hole. It's free and changes nothing else.", evidence: noDependabot.slice(0, 4).join(", ") + (noDependabot.length > 4 ? ` +${noDependabot.length - 4} more` : ""), fix: { fixer: "gh.security-features", action: "Turn on Dependabot alerts everywhere", params: { repos: noDependabot, features: ["vulnerability-alerts"] } } });
  }
  if (forcePush.length) {
    report({ check: "gh.force-push", severity: "low", title: `${forcePush.length} public repo${forcePush.length > 1 ? "s" : ""} can have main force-pushed or deleted`, why: "A stolen token or a bad command can wipe your history. Blocking force-pushes doesn't change how you work.", evidence: forcePush.slice(0, 4).map((x) => x.repo).join(", ") + (forcePush.length > 4 ? ` +${forcePush.length - 4} more` : ""), fix: { fixer: "gh.ruleset", action: "Block force-pushes and deletion of main", params: { repos: forcePush } } });
  }

  await ctx.step("github", "gh.apps", "Apps with access to your GitHub", async () => {
    report({ check: "gh.oauth-review", severity: "info", title: "Review apps that can act as you on GitHub", why: "Old OAuth apps and integrations keep access until you remove them. GitHub doesn't let other apps list them for you.", fix: { fixer: "none", action: "Remove apps you don't use", params: { url: "https://github.com/settings/applications" }, manual: "Open github.com/settings/applications and revoke what you don't use." } });
  });
}

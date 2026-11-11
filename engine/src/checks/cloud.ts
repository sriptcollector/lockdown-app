// Cloud layer: what your signed-in cloud CLIs can reach. Read-only calls only.
import { existsSync } from "node:fs";
import { join } from "node:path";
import type { ScanCtx } from "../context";
import type { Finding } from "../types";
import { HOME, IS_WIN, run } from "../util";

type F = Omit<Finding, "id" | "layer">;

const gcloudBin = () => (IS_WIN ? "gcloud.cmd" : "gcloud");

async function gcloud(args: string[], timeoutMs = 60_000): Promise<any | null> {
  const r = await run(gcloudBin(), [...args, "--format=json", "--quiet"], { timeoutMs });
  if (r.code !== 0) return null;
  try {
    return JSON.parse(r.stdout);
  } catch {
    return null;
  }
}

// gcloud takes a few seconds per call, so projects, accounts and buckets are looked at side by side.
async function each<T>(items: T[], n: number, fn: (x: T) => Promise<void>) {
  let i = 0;
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, async () => { while (i < items.length) await fn(items[i++]); }));
}

export async function scanCloud(ctx: ScanCtx) {
  const report = (f: F, t = "cloud") => ctx.report({ layer: "cloud", ...f }, t);

  await ctx.step("cloud", "gcp.account", "Google Cloud access", async () => {
    const auth = await gcloud(["auth", "list"], 30_000);
    if (!auth) return "Google Cloud CLI isn't signed in";
    const active = auth.find((a: any) => a.status === "ACTIVE");
    if (!active) return "Google Cloud CLI isn't signed in";
    ctx.target({ kind: "cloud", id: "gcp", name: "Google Cloud", layer: "cloud" });
    const projects = ((await gcloud(["projects", "list", "--limit=8"], 60_000)) ?? []) as any[];
    await each(projects, 4, async (p) => {
      const pid = p.projectId;
      const tid = `gcp:${pid}`;
      ctx.target({ kind: "cloud", id: tid, name: pid, layer: "cloud" });
      await ctx.step("cloud", "gcp.project", `${pid}: keys and buckets`, async () => {
        const [sas, buckets] = await Promise.all([gcloud(["iam", "service-accounts", "list", `--project=${pid}`]), gcloud(["storage", "buckets", "list", `--project=${pid}`], 90_000)]);
        await each((sas ?? []) as any[], 6, async (sa) => {
          const keys = ((await gcloud(["iam", "service-accounts", "keys", "list", `--iam-account=${sa.email}`, "--managed-by=user", `--project=${pid}`])) ?? []) as any[];
          for (const k of keys.filter((k) => !k.disabled)) {
            const ageDays = Math.floor((Date.now() - Date.parse(k.validAfterTime)) / 864e5);
            report({
              check: "gcp.sa-key",
              severity: ageDays > 90 ? "high" : "medium",
              title: `Downloadable key for ${sa.email.split("@")[0]} (${ageDays} days old)`,
              why: "Service-account key files never expire. If one leaks, it works until someone notices.",
              where: `${pid} · ${sa.email}`,
              evidence: `key ${String(k.name).split("/").pop()?.slice(0, 8)}…`,
              fix: { fixer: "gcp.key-disable", action: "Turn the key off (can be turned back on)", params: { project: pid, account: sa.email, key: String(k.name).split("/").pop() } },
            }, tid);
          }
        });
        await each((buckets ?? []) as any[], 6, async (b) => {
          const name = b.name ?? String(b.storage_url ?? "").replace(/^gs:\/\/|\/$/g, "");
          const pol = await gcloud(["storage", "buckets", "get-iam-policy", `gs://${name}`]);
          const pubRoles = ((pol?.bindings ?? []) as any[]).filter((x) => (x.members ?? []).some((m: string) => m === "allUsers" || m === "allAuthenticatedUsers"));
          if (!pubRoles.length) return;
          const canWrite = pubRoles.some((x) => /admin|objectCreator|objectUser|legacyBucketWriter|storage\.objectAdmin/i.test(x.role));
          report({
            check: "gcp.public-bucket",
            severity: canWrite ? "critical" : "medium",
            title: canWrite ? `Anyone can upload to bucket ${name}` : `Bucket ${name} is public`,
            why: canWrite ? "Strangers can upload files, host malware on your account, and run up your bill." : "Every file in it can be listed or downloaded by anyone with the name.",
            where: `${pid} · gs://${name}`,
            evidence: pubRoles.map((x) => x.role.replace("roles/", "")).join(", "),
            fix: { fixer: "gcp.bucket-private", action: "Remove public access from the bucket", params: { bucket: name, project: pid, roles: pubRoles.map((x) => x.role) } },
          }, tid);
        });
      }, tid);
    });
    const adc = IS_WIN ? join(process.env.APPDATA ?? "", "gcloud", "application_default_credentials.json") : join(HOME, ".config", "gcloud", "application_default_credentials.json");
    if (existsSync(adc)) {
      report({ check: "gcp.adc", severity: "info", title: "Your Google Cloud login is saved for local apps", why: "Any program on this computer can use it to act as you in Google Cloud. Normal for developers; keep this PC locked down.", where: "application_default_credentials.json", fix: { fixer: "none", action: "Revoke it when you're not developing", params: {}, manual: "Run gcloud auth application-default revoke when you don't need it." } });
    }
  });

  await ctx.step("cloud", "aws.account", "AWS access", async () => {
    const r = await run(IS_WIN ? "aws.exe" : "aws", ["sts", "get-caller-identity", "--output", "json"], { timeoutMs: 30_000 });
    if (r.code !== 0) return "AWS CLI isn't signed in";
    const id = JSON.parse(r.stdout);
    ctx.target({ kind: "cloud", id: "aws", name: `AWS ${id.Account}`, layer: "cloud" });
    if (/:root$/.test(id.Arn)) {
      report({ check: "aws.root", severity: "critical", title: "You're using the AWS root account's keys", why: "Root keys can do anything, including closing the account, and can't be limited.", where: id.Arn, fix: { fixer: "none", action: "Delete root keys and use an IAM Identity Center user", params: {}, manual: "Delete the root access keys in IAM > Security credentials, then sign in with aws sso login." } }, "aws");
    }
  });
}

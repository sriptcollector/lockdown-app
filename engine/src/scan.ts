import { writeFileSync } from "node:fs";
import { hostname } from "node:os";
import { join } from "node:path";
import { scanBrowsers } from "./checks/browsers";
import { scanCloud } from "./checks/cloud";
import { scanFiles } from "./checks/files";
import { scanGithub } from "./checks/github";
import { scanMac } from "./checks/mac";
import { discoverRepos, scanRepos } from "./checks/repos";
import { scanWindows } from "./checks/windows";
import { scanSites } from "./checks/web";
import { makeCtx } from "./context";
import type { Layer, Preferences, ScanEvent, ScanResult, ScanSummary, Severity } from "./types";
import { LAYERS } from "./types";
import { dataDir, IS_MAC, IS_WIN, scanStop } from "./util";

// Points off per severity, growing with the square root of the count so 50 low findings don't
// outweigh one critical. Score starts at 100, floors at 0.
const WEIGHT: Record<Severity, number> = { critical: 20, high: 8, medium: 3, low: 1, info: 0 };

export function summarize(runId: string, r: Omit<ScanResult, "summary">): ScanSummary {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 } as Record<Severity, number>;
  const byLayer = Object.fromEntries(LAYERS.map((l) => [l.id, 0])) as Record<Layer, number>;
  let penalty = 0;
  for (const f of r.findings) {
    counts[f.severity]++;
    byLayer[f.layer]++;
  }
  for (const sev of Object.keys(counts) as Severity[]) penalty += WEIGHT[sev] * Math.sqrt(counts[sev]);
  return {
    runId,
    platform: IS_WIN ? "windows" : IS_MAC ? "macos" : "linux",
    score: Math.max(0, Math.round(100 - penalty)),
    counts,
    byLayer,
    targets: r.targets.length,
    checksRun: r.checks.filter((c) => c.status === "ok").length,
    checksSkipped: r.checks.filter((c) => c.status !== "ok").length,
    fixable: r.findings.filter((f) => f.fix && !["none", "win.open-settings", "mac.open"].includes(f.fix.fixer)).length,
  };
}

export async function runScan(prefs: Preferences, emit: (e: ScanEvent) => void, only?: Layer[]): Promise<ScanResult> {
  const runId = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
  scanStop.reset();
  const ctx = makeCtx(runId, prefs, emit);
  const want = (l: Layer) => !only || only.includes(l);
  emit({ type: "start", runId, at: new Date().toISOString(), platform: IS_WIN ? "windows" : IS_MAC ? "macos" : "linux", layers: (only ?? LAYERS.map((l) => l.id)) as Layer[] });
  ctx.target({ kind: "machine", id: "machine", name: hostname(), layer: "system" });

  const repos = want("code") || want("github") ? await discoverRepos(ctx) : [];
  // Rough size of the job so the progress bar moves evenly: ~30 machine, file and account checks, plus 4 per project.
  emit({ type: "plan", total: 30 + (want("code") ? repos.length * 4 + 1 : 0) + (want("github") ? 3 : 0) });

  // Machine, files, cloud and GitHub run side by side; code scanning is the long pole.
  await Promise.all([
    (async () => {
      if (want("system") || want("network") || want("apps")) {
        if (IS_WIN) await scanWindows(ctx);
        else if (IS_MAC) await scanMac(ctx);
      }
      if (want("apps")) await scanBrowsers(ctx);
    })(),
    want("files") ? scanFiles(ctx) : null,
    want("cloud") ? scanCloud(ctx) : null,
    want("cloud") && prefs.sites?.length ? scanSites(ctx, prefs.sites) : null,
    want("github") ? scanGithub(ctx, repos) : null,
    want("code") ? scanRepos(ctx, repos) : null,
  ]);

  const result: ScanResult = { summary: { ...summarize(runId, ctx), partial: scanStop.stopped || undefined }, findings: ctx.findings, targets: ctx.targets, checks: ctx.checks };
  scanStop.reset();
  const order: Severity[] = ["critical", "high", "medium", "low", "info"];
  result.findings.sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity));
  writeFileSync(join(dataDir("scans"), `${runId}.json`), JSON.stringify(result, null, 1));
  writeFileSync(join(dataDir("scans"), `latest.json`), JSON.stringify(result, null, 1));
  emit({ type: "done", at: new Date().toISOString(), summary: result.summary });
  return result;
}

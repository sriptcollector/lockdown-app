#!/usr/bin/env bun
// lockdown scan [--json|--events] [--layers code,github] [--report out.md]
// lockdown fix [--dry-run] [--only id,id] [--yes]      (applies per preferences)
// lockdown undo <changeId|runId|last>
// lockdown prefs [key=value ...]
// lockdown credits
import { writeFileSync } from "node:fs";
import { loadPrefs, savePrefs } from "./prefs";
import { renderReport } from "./report";
import { runScan } from "./scan";
import { credits } from "./scanners/tools";
import type { Layer, ScanEvent } from "./types";

const args = process.argv.slice(2);
const cmd = args[0] ?? "scan";
const flag = (n: string) => args.includes(`--${n}`);
const opt = (n: string) => {
  const i = args.indexOf(`--${n}`);
  return i >= 0 ? args[i + 1] : undefined;
};

async function main() {
  if (cmd === "scan") {
    const events = flag("events");
    const only = opt("layers")?.split(",") as Layer[] | undefined;
    const emit = (e: ScanEvent) => {
      if (events) process.stdout.write(JSON.stringify(e) + "\n");
      else if (!flag("json") && !flag("quiet")) {
        if (e.type === "check-start") process.stderr.write(`· ${e.label}\n`);
        if (e.type === "check-done" && e.status !== "ok") process.stderr.write(`  ${e.status}: ${e.note ?? ""}\n`);
      }
    };
    const result = await runScan(loadPrefs(), emit, only);
    if (flag("json")) process.stdout.write(JSON.stringify(result, null, 1));
    const reportPath = opt("report");
    if (reportPath) writeFileSync(reportPath, renderReport(result));
    if (!events && !flag("json")) {
      const s = result.summary;
      process.stderr.write(`\nScore ${s.score}/100 · ${s.counts.critical} critical, ${s.counts.high} high, ${s.counts.medium} medium, ${s.counts.low} low · ${s.fixable} fixable\n`);
    }
    return;
  }
  if (cmd === "fix" || cmd === "undo" || cmd === "plan") {
    const { cliFix } = await import("./fix");
    await cliFix(cmd, args.slice(1));
    return;
  }
  if (cmd === "prefs") {
    const kv = args.slice(1).filter((a) => a.includes("="));
    if (kv.length) {
      const patch: any = {};
      for (const a of kv) {
        const [k, v] = a.split("=");
        patch[k] = v === "true" ? true : v === "false" ? false : k === "keep" || k === "codeRoots" ? (v ? v.split(",") : []) : v;
      }
      savePrefs(patch);
    }
    process.stdout.write(JSON.stringify(loadPrefs(), null, 2) + "\n");
    return;
  }
  if (cmd === "serve") {
    const { serve } = await import("./serve");
    serve(Number(opt("port") ?? 0));
    return;
  }
  if (cmd === "credits") {
    process.stdout.write(JSON.stringify(credits(), null, 2) + "\n");
    return;
  }
  process.stderr.write("usage: lockdown scan|plan|fix|undo|prefs|credits\n");
  process.exit(2);
}

main().catch((e) => {
  process.stderr.write(String(e?.stack ?? e) + "\n");
  process.exit(1);
});

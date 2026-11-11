// Plan → apply → undo. Preferences decide what runs on its own; break risks are shown in plain
// words and anything that could break something the user relies on is held or skipped.
import { existsSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { AdminBatch, FIXERS, type FixCtx } from "./fixers";
import { canFix } from "./license";
import { OPTIONAL_SAYS, optionalWhy } from "./policy";
import { ghCaching } from "./gh";
import { loadPrefs } from "./prefs";
import { detectRisks } from "./risk";
import type { BreakRisk, Change, Finding, Preferences, ScanResult } from "./types";
import { dataDir } from "./util";

export type Decision = "apply" | "hold" | "skip" | "manual" | "optional";

export interface PlanItem {
  finding: Finding;
  decision: Decision;
  risks: BreakRisk[];
  reason: string;
}

export function decide(f: Finding, risks: BreakRisk[], prefs: Preferences): { decision: Decision; reason: string } {
  if (!f.fix || ["none", "win.open-settings", "mac.open"].includes(f.fix.fixer) || !FIXERS[f.fix.fixer]) return { decision: "manual", reason: f.fix?.manual ?? "needs you" };
  const kept = risks.find((r) => prefs.keep.includes(r.reliance));
  if (kept) return { decision: "skip", reason: `you rely on this: ${kept.says}` };
  // Admin, code and other people's software never run by themselves: they wait, unticked, on the optional list.
  const why = optionalWhy(f);
  if (why && prefs.mode !== "all-auto") return { decision: "optional", reason: OPTIONAL_SAYS[why] };
  if (prefs.mode === "review") return { decision: "hold", reason: "you review every fix" };
  if (prefs.mode === "all-auto") return { decision: "apply", reason: risks.length ? "you chose to fix everything" : "safe" };
  // safe-auto: everything can be undone, so only a fix that will likely break something waits
  // for a plain yes/no question. "Possible" side effects just apply.
  const likely = risks.find((r) => r.level === "likely");
  if (likely) return { decision: "hold", reason: likely.says };
  return { decision: "apply", reason: "safe" };
}

export async function makePlan(scan: ScanResult, prefs: Preferences, only?: string[]): Promise<PlanItem[]> {
  const items: PlanItem[] = [];
  for (const f of scan.findings) {
    if (only && !only.includes(f.id)) continue;
    const risks = await detectRisks(f);
    if (f.fix) f.fix.risks = risks;
    const { decision, reason } = decide(f, risks, prefs);
    items.push({ finding: f, decision, risks, reason });
  }
  return items;
}

const journalPath = (runId: string) => join(dataDir("journal"), `${runId}.json`);

function saveJournal(runId: string, changes: Change[]) {
  writeFileSync(journalPath(runId), JSON.stringify(changes, null, 1));
}

export function loadJournal(runId: string): Change[] {
  return existsSync(journalPath(runId)) ? JSON.parse(readFileSync(journalPath(runId), "utf8")) : [];
}

export function listRuns(): string[] {
  return readdirSync(dataDir("journal")).filter((f) => f.endsWith(".json")).map((f) => f.slice(0, -5)).sort();
}

export type FixEvent =
  | { type: "fix-start"; findingId: string; action: string }
  | { type: "fix-done"; change: Change }
  | { type: "fix-held"; findingId: string; reason: string; risks: BreakRisk[] }
  /** The system is about to ask for an admin password or a Yes; the app shows what to press. */
  | { type: "admin-prompt"; count: number };

/** Apply every "apply" item. Admin steps are gathered and run behind one prompt. */
export async function applyPlan(plan: PlanItem[], prefs: Preferences, emit: (e: FixEvent) => void = () => {}): Promise<{ runId: string; changes: Change[] }> {
  if (!canFix()) throw new Error("Fixing needs Lockdown Pro. Sign in to unlock it.");
  ghCaching.on = false; // fixes always read GitHub fresh
  const runId = `fix-${new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19)}`;
  const ctx: FixCtx = { runId, backupDir: dataDir("backups", runId), prefs, admin: new AdminBatch() };
  const changes: Change[] = [];
  for (const item of plan) {
    if (item.decision === "hold") emit({ type: "fix-held", findingId: item.finding.id, reason: item.reason, risks: item.risks });
    if (item.decision !== "apply") continue;
    const f = item.finding;
    emit({ type: "fix-start", findingId: f.id, action: f.fix!.action });
    const base = { id: `${runId}:${f.id}`, runId, findingId: f.id, fixer: f.fix!.fixer, action: f.fix!.action, at: new Date().toISOString() };
    try {
      const r = await FIXERS[f.fix!.fixer].apply(f, ctx);
      const ch: Change = { ...base, before: r.before, after: r.after, backups: r.backups, result: r.result ?? "applied", note: r.note };
      changes.push(ch);
      if (!ctx.admin.steps.some((s) => s.id === f.id)) emit({ type: "fix-done", change: ch });
    } catch (e: any) {
      const ch: Change = { ...base, before: null, result: "failed", note: String(e?.message ?? e).slice(0, 300) };
      changes.push(ch);
      emit({ type: "fix-done", change: ch });
    }
    saveJournal(runId, changes);
  }
  // One admin prompt for everything that needs it.
  const queued = ctx.admin.steps.map((s) => s.id);
  ctx.admin.onPrompt = () => emit({ type: "admin-prompt", count: queued.length });
  await ctx.admin.flush();
  for (const id of queued) {
    const ch = changes.find((c) => c.findingId === id)!;
    const res = ctx.admin.results.get(id);
    if (!res?.ok) {
      ch.result = res?.out.startsWith("sandbox") ? "skipped" : "failed";
      ch.note = res?.out.trim().slice(0, 300) || "not run";
    }
    emit({ type: "fix-done", change: ch });
  }
  saveJournal(runId, changes);
  return { runId, changes };
}

/** Undo one change, or every change in a run (newest first). */
export async function undo(target: string, prefs: Preferences = loadPrefs()): Promise<Change[]> {
  const runId = target === "last" ? listRuns().pop() : target.split(":")[0];
  if (!runId) throw new Error("nothing to undo");
  const changes = loadJournal(runId);
  const pick = target.includes(":") ? changes.filter((c) => c.id === target) : changes;
  const scan = latestScan();
  const ctx: FixCtx = { runId, backupDir: dataDir("backups", runId), prefs, admin: new AdminBatch() };
  const done: Change[] = [];
  for (const c of [...pick].reverse()) {
    if (c.undone || !["applied", "pr-opened"].includes(c.result) || c.before == null) continue;
    const f = scan?.findings.find((x) => x.id === c.findingId) ?? ({ id: c.findingId, fix: { fixer: c.fixer, action: c.action, params: {} } } as Finding);
    await FIXERS[c.fixer].undo(c.before, f, ctx);
    c.undone = new Date().toISOString();
    done.push(c);
  }
  await ctx.admin.flush();
  for (const [id, r] of ctx.admin.results) {
    if (!r.ok) {
      const c = done.find((d) => `undo-${d.findingId}` === id);
      if (c) {
        c.undone = undefined;
        c.note = `undo failed: ${r.out.slice(0, 200)}`;
      }
    }
  }
  saveJournal(runId, changes);
  return done;
}

export function latestScan(): ScanResult | null {
  const p = join(dataDir("scans"), "latest.json");
  return existsSync(p) ? JSON.parse(readFileSync(p, "utf8")) : null;
}

export async function cliFix(cmd: string, args: string[]) {
  const prefs = loadPrefs();
  if (cmd === "undo") {
    const done = await undo(args[0] ?? "last", prefs);
    process.stdout.write(JSON.stringify(done.map((c) => ({ id: c.id, action: c.action, undone: !!c.undone, note: c.note })), null, 2) + "\n");
    return;
  }
  const scan = latestScan();
  if (!scan) throw new Error("run a scan first");
  const onlyIdx = args.indexOf("--only");
  const only = onlyIdx >= 0 ? args[onlyIdx + 1].split(",") : undefined;
  const plan = await makePlan(scan, prefs, only);
  if (cmd === "plan" || args.includes("--dry-run") || !args.includes("--yes")) {
    const rows = plan.map((p) => ({ id: p.finding.id, severity: p.finding.severity, title: p.finding.title, decision: p.decision, action: p.finding.fix?.action, risks: p.risks.map((r) => `${r.level}: ${r.says}`), reason: p.reason }));
    process.stdout.write(JSON.stringify(rows, null, 2) + "\n");
    if (cmd !== "plan" && !args.includes("--yes")) process.stderr.write("dry run: add --yes to apply\n");
    return;
  }
  const { runId, changes } = await applyPlan(plan, prefs, (e) => process.stderr.write(JSON.stringify(e) + "\n"));
  process.stdout.write(JSON.stringify({ runId, changes: changes.map((c) => ({ id: c.id, action: c.action, result: c.result, note: c.note })) }, null, 2) + "\n");
}

// ---------- plain questions for the few fixes that will likely break something ----------
const ASK: Record<string, { q: string; help: string; keep: string; fix: string }> = {
  "remote-access": { q: "Do you ever get into this computer from another device?", help: "Like controlling it from your phone or from another computer.", keep: "Yes, keep that working", fix: "No, lock it" },
  "lan-dev-servers": { q: "Do you open things running on this computer from your phone?", help: "Like a website you're building, or a game server for friends.", keep: "Yes, keep that working", fix: "No, lock it" },
  "file-sharing": { q: "Do other computers open folders on this one?", help: "Like a shared folder at home or work.", keep: "Yes, keep sharing", fix: "No, turn it off" },
  "public-repos": { q: "Should some of your code stay public?", help: "Like an open-source project other people download.", keep: "Yes, leave it public", fix: "No, make it private" },
  "build": { q: "Tighten how your code gets published?", help: "Only matters if your website or app is published from GitHub. It might need a small change after.", keep: "Not now", fix: "Yes, tighten it" },
  "running-app": { q: "Turn off old keys that could let someone in?", help: "A website or app that still uses one would stop until it gets a new one.", keep: "Not now", fix: "Yes, fix them" },
  "startup-apps": { q: "Do you know these programs that start with Windows?", help: "They aren't signed by their maker, which is common for small apps and also for malware.", keep: "Yes, they're mine", fix: "No, stop them" },
  "unsigned-scripts": { q: "Do you run scripts you download from the internet?", help: "Most people don't.", keep: "Yes, keep that working", fix: "No, block them" },
  "git-history": { q: "Clean leaked keys out of your code history?", help: "Anyone else working on the code will need a fresh copy.", keep: "Not now", fix: "Yes, clean it" },
  "direct-push": { q: "Protect your main code branch?", help: "Scripts that push straight to it might need a change.", keep: "Not now", fix: "Yes, protect it" },
};

export interface Question {
  reliance: string;
  question: string;
  help: string;
  options: { value: "keep" | "fix"; label: string; unsure?: boolean }[];
  recommended: "keep" | "fix";
  findingIds: string[];
  why?: string;
  touches?: string[];
}

export function questionsFor(plan: PlanItem[]): Question[] {
  const by = new Map<string, PlanItem[]>();
  for (const p of plan.filter((x) => x.decision === "hold")) {
    const r = p.risks.find((x) => x.level === "likely") ?? p.risks[0];
    if (!r) continue;
    (by.get(r.reliance) ?? by.set(r.reliance, []).get(r.reliance)!).push(p);
  }
  return [...by].map(([reliance, items]) => {
    const a = ASK[reliance] ?? ASK["running-app"];
    // Only say what we noticed when it is plain words about their own setup (like "Tailscale is running").
    const evidence = ["remote-access", "lan-dev-servers", "file-sharing"].includes(reliance) ? items.flatMap((i) => i.risks.map((r) => r.evidence)).find(Boolean) : undefined;
    // If we saw it being used right now, keeping it is the safe default. Public code is never hidden by
    // default either (open source is public on purpose), unless its name says it's private work.
    const publicNames = reliance === "public-repos" ? items.map((i) => String(i.finding.where ?? "").split("/").pop()).filter(Boolean) : [];
    const recommended = evidence ? "keep" : reliance === "public-repos" ? (items.every((i) => i.finding.severity === "high") ? "fix" : "keep") : "fix";
    const options: Question["options"] = [{ value: "fix", label: a.fix }, { value: "keep", label: a.keep }];
    if (recommended === "keep") options.reverse();
    options.push({ value: "keep", label: "I'm not sure, leave it as it is", unsure: true });
    const touches = [...new Set(items.map((i) => i.finding.fix?.action ?? i.finding.title))].slice(0, 3);
    const help = evidence
      ? `${a.help} We noticed: ${evidence}.`
      : publicNames.length
        ? `${a.help} Public right now: ${publicNames.slice(0, 4).join(", ")}${publicNames.length > 4 ? ` and ${publicNames.length - 4} more` : ""}.`
        : reliance === "remote-access"
          ? `${a.help} Most people don't.`
          : a.help;
    return { reliance, question: a.q, help, options, recommended, findingIds: items.map((i) => i.finding.id), why: evidence, touches };
  });
}

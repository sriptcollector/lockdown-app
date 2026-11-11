import type { BreakRisk, Change, Finding, Layer, Preferences, ScanSummary, Severity, Target } from "../../engine/src/types";
export type { BreakRisk, Change, Finding, Layer, Preferences, ScanSummary, Severity, Target };

export const LAYERS: { id: Layer; name: string; blurb: string }[] = [
  { id: "code", name: "Code", blurb: "Leaked keys, risky packages, injection, source maps" },
  { id: "github", name: "GitHub", blurb: "Public repos, tokens, workflows, deploy keys" },
  { id: "system", name: "This computer", blurb: "Updates, antivirus, encryption, sign-in" },
  { id: "network", name: "Internet", blurb: "Firewall, open ports, remote access, Wi-Fi" },
  { id: "files", name: "Files", blurb: "Keys and passwords sitting in plain files" },
  { id: "apps", name: "Apps", blurb: "Risky apps, extensions, startup items" },
  { id: "cloud", name: "Cloud", blurb: "Cloud keys, public buckets, broad access" },
];

export const SEV_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];
export const SEV_WORD: Record<Severity, string> = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Review" };

export type Phase = "idle" | "scanning" | "results" | "fixing" | "fixed";
export type FixState = "applied" | "pr-opened" | "failed" | "skipped" | "held" | "working" | "undone";

export interface PlanRow {
  id: string;
  decision: "apply" | "hold" | "skip" | "manual";
  reason: string;
  risks: BreakRisk[];
}

export interface State {
  phase: Phase;
  runId?: string;
  startedAt?: number;
  targets: Target[];
  findings: Finding[];
  layerStatus: Record<Layer, "waiting" | "checking" | "done">;
  activeChecks: { key: string; layer: Layer; label: string }[];
  feed: { at: number; text: string; layer: Layer; tone?: "found" | "ok" | "skip" }[];
  checksDone: number;
  summary?: ScanSummary;
  scoreBefore?: number;
  plan: Record<string, PlanRow>;
  fixes: Record<string, { state: FixState; note?: string; changeId?: string }>;
  fixRunId?: string;
  error?: string;
}

export const initialState = (): State => ({
  phase: "idle",
  targets: [],
  findings: [],
  layerStatus: Object.fromEntries(LAYERS.map((l) => [l.id, "waiting"])) as State["layerStatus"],
  activeChecks: [],
  feed: [],
  checksDone: 0,
  plan: {},
  fixes: {},
});

export type Ev = { type: string; [k: string]: any };

export function reduce(s: State, e: Ev): State {
  switch (e.type) {
    case "reset":
      return initialState();
    case "load-latest":
      return { ...initialState(), phase: "results", findings: e.result.findings, targets: e.result.targets, summary: e.result.summary, runId: e.result.summary.runId, layerStatus: Object.fromEntries(LAYERS.map((l) => [l.id, "done"])) as State["layerStatus"] };
    case "start":
      return { ...initialState(), phase: "scanning", runId: e.runId, startedAt: Date.now(), layerStatus: Object.fromEntries(LAYERS.map((l) => [l.id, e.layers.includes(l.id) ? "waiting" : "done"])) as State["layerStatus"] };
    case "target":
      return { ...s, targets: [...s.targets, e.target] };
    case "check-start": {
      const key = `${e.check}|${e.targetId ?? ""}`;
      return { ...s, layerStatus: { ...s.layerStatus, [e.layer]: "checking" }, activeChecks: [...s.activeChecks.filter((c) => c.key !== key), { key, layer: e.layer, label: e.label }] };
    }
    case "check-done": {
      const key = `${e.check}|${e.targetId ?? ""}`;
      const done = s.activeChecks.find((c) => c.key === key);
      const active = s.activeChecks.filter((c) => c.key !== key);
      const stillLayer = active.some((c) => c.layer === e.layer);
      const tone = e.status === "ok" ? "ok" : "skip";
      return {
        ...s,
        activeChecks: active,
        checksDone: s.checksDone + 1,
        layerStatus: { ...s.layerStatus, [e.layer]: stillLayer ? "checking" : "done" },
        feed: done ? [{ at: Date.now(), text: e.status === "ok" ? done.label : `${done.label}: ${e.note ?? "skipped"}`, layer: e.layer as Layer, tone: tone as "ok" | "skip" }, ...s.feed].slice(0, 40) : s.feed,
      };
    }
    case "finding":
      return { ...s, findings: [...s.findings, e.finding], feed: [{ at: Date.now(), text: e.finding.title, layer: e.finding.layer, tone: "found" as const }, ...s.feed].slice(0, 40) };
    case "done":
      return { ...s, phase: "results", summary: e.summary, activeChecks: [], layerStatus: Object.fromEntries(LAYERS.map((l) => [l.id, "done"])) as State["layerStatus"] };
    case "fix-plan":
      return { ...s, phase: "fixing", scoreBefore: s.summary?.score, plan: Object.fromEntries(e.items.map((p: PlanRow) => [p.id, p])), fixes: Object.fromEntries(e.items.filter((p: PlanRow) => p.decision === "hold").map((p: PlanRow) => [p.id, { state: "held" as FixState, note: p.reason }])) };
    case "fix-start":
      return { ...s, fixes: { ...s.fixes, [e.findingId]: { state: "working" } } };
    case "fix-held":
      return { ...s, fixes: { ...s.fixes, [e.findingId]: { state: "held", note: e.reason } } };
    case "fix-done":
      return { ...s, fixes: { ...s.fixes, [e.change.findingId]: { state: e.change.result, note: e.change.note, changeId: e.change.id } } };
    case "fix-finished":
      return { ...s, phase: "fixed", fixRunId: e.runId };
    case "undo-done": {
      const fixes = { ...s.fixes };
      for (const c of e.changes as Change[]) fixes[c.findingId] = { state: "undone", changeId: c.id };
      return { ...s, fixes };
    }
    case "error":
      return { ...s, error: e.message };
  }
  return s;
}

/** Findings still open after fixes. */
export function openFindings(s: State): Finding[] {
  return s.findings.filter((f) => !["applied", "pr-opened"].includes(s.fixes[f.id]?.state ?? ""));
}

export function scoreOf(findings: Finding[]): number {
  const W: Record<Severity, number> = { critical: 20, high: 8, medium: 3, low: 1, info: 0 };
  const c = { critical: 0, high: 0, medium: 0, low: 0, info: 0 } as Record<Severity, number>;
  for (const f of findings) c[f.severity]++;
  let p = 0;
  for (const k of SEV_ORDER) p += W[k] * Math.sqrt(c[k]);
  return Math.max(0, Math.round(100 - p));
}

export function worst(findings: Finding[]): Severity | null {
  for (const s of SEV_ORDER) if (findings.some((f) => f.severity === s)) return s;
  return null;
}

/** Fixes the user has to do (or that only open a settings page). */
export const isManual = (f: Finding) => !f.fix || ["none", "win.open-settings", "mac.open"].includes(f.fix.fixer);

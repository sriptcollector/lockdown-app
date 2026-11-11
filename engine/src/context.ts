import type { Finding, Layer, Preferences, ScanEvent, Target } from "./types";
import { hash } from "./util";

export interface ScanCtx {
  runId: string;
  prefs: Preferences;
  emit(e: ScanEvent): void;
  target(t: Target): void;
  report(f: Omit<Finding, "id"> & { id?: string }, targetId?: string): void;
  /** Time a check and send start/done events around it. */
  step(layer: Layer, check: string, label: string, fn: () => Promise<void | string>, targetId?: string): Promise<void>;
}

export function makeCtx(runId: string, prefs: Preferences, emit: (e: ScanEvent) => void): ScanCtx & {
  findings: Finding[];
  targets: Target[];
  checks: { layer: Layer; check: string; targetId?: string; status: string; note?: string; ms: number }[];
} {
  const findings: Finding[] = [];
  const targets: Target[] = [];
  const checks: { layer: Layer; check: string; targetId?: string; status: string; note?: string; ms: number }[] = [];
  const seen = new Set<string>();
  return {
    runId,
    prefs,
    findings,
    targets,
    checks,
    emit,
    target(t) {
      if (targets.some((x) => x.id === t.id)) return;
      targets.push(t);
      emit({ type: "target", target: t });
    },
    report(f, targetId) {
      const id = f.id ?? `${f.layer}.${f.check}.${hash(f.where ?? "", f.title, f.evidence ?? "")}`;
      if (seen.has(id)) return;
      seen.add(id);
      const finding: Finding = { ...f, id };
      findings.push(finding);
      emit({ type: "finding", finding, targetId });
    },
    async step(layer, check, label, fn, targetId) {
      emit({ type: "check-start", layer, check, label, targetId });
      const t0 = Date.now();
      let status: "ok" | "skipped" | "error" = "ok";
      let note: string | undefined;
      try {
        const r = await fn();
        if (typeof r === "string") {
          status = "skipped";
          note = r;
        }
      } catch (e: any) {
        status = "error";
        note = String(e?.message ?? e).slice(0, 300);
      }
      const ms = Date.now() - t0;
      checks.push({ layer, check, targetId, status, note, ms });
      emit({ type: "check-done", layer, check, targetId, ms, status, note });
    },
  };
}

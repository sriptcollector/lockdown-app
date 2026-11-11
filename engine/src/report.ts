import { credits } from "./scanners/tools";
import type { ScanResult } from "./types";
import { LAYERS } from "./types";

/** Plain-text findings report. Secrets are already redacted in findings. */
export function renderReport(r: ScanResult): string {
  const s = r.summary;
  const lines = [
    `# Lockdown scan · ${s.runId}`,
    "",
    `Score **${s.score}/100** · ${s.counts.critical} critical · ${s.counts.high} high · ${s.counts.medium} medium · ${s.counts.low} low · ${s.counts.info} to review`,
    `${s.targets} things checked (${r.targets.filter((t) => t.kind === "repo").length} local repos, ${r.targets.filter((t) => t.kind === "github-repo").length} GitHub repos) · ${s.checksRun} checks ran · ${s.checksSkipped} skipped · ${s.fixable} fixable automatically`,
    "",
  ];
  for (const l of LAYERS) {
    const fs = r.findings.filter((f) => f.layer === l.id);
    lines.push(`## ${l.name} (${fs.length})`, "");
    for (const f of fs) {
      lines.push(`- **[${f.severity}] ${f.title}**${f.where ? ` · \`${f.where}\`` : ""}`);
      lines.push(`  ${f.why}${f.evidence ? ` _(${f.evidence})_` : ""}`);
      if (f.fix) lines.push(`  Fix: ${f.fix.action}${f.fix.fixer === "none" ? " (you)" : f.fix.pr ? " (pull request)" : f.fix.admin ? " (admin)" : ""}${f.fix.manual ? `. ${f.fix.manual}` : ""}`);
    }
    lines.push("");
  }
  const skipped = r.checks.filter((c) => c.status !== "ok");
  if (skipped.length) {
    lines.push("## Not checked", "");
    for (const c of skipped) lines.push(`- ${c.check}${c.targetId ? ` (${c.targetId.replace(/^repo:/, "")})` : ""}: ${c.note}`);
    lines.push("");
  }
  lines.push("Scanners: " + credits().map((c) => `${c.name} ${c.version} (${c.license})`).join(", "));
  return lines.join("\n");
}

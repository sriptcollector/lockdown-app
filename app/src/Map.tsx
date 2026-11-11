// The live map: your computer in the middle, the seven layers around it, one dot per finding.
// Layers light up while they're checked, take the color of their worst finding, and go green
// as fixes land.
import { useMemo } from "react";
import { LAYERS, type Layer, type State, SEV_WORD, worst } from "./state";

const W = 800;
const H = 660;
const CX = W / 2;
const CY = H / 2;
const ORBIT = 228;
const NODE = 36;

const fixedStates = new Set(["applied", "pr-opened"]);

export function SecurityMap({ s, score, selected, onSelect }: { s: State; score: number | null; selected: Layer | null; onSelect: (l: Layer | null) => void }) {
  const nodes = useMemo(
    () =>
      LAYERS.map((l, i) => {
        const a = -Math.PI / 2 + (i * 2 * Math.PI) / LAYERS.length;
        return { ...l, a, x: CX + ORBIT * Math.cos(a), y: CY + ORBIT * Math.sin(a) };
      }),
    [],
  );
  const scanning = s.phase === "scanning";
  const ringLen = 2 * Math.PI * 78;

  return (
    <svg className="map" viewBox={`0 0 ${W} ${H}`} role="img" aria-label="Map of your computer, code and accounts by security layer">
      <defs>
        <radialGradient id="sweep-fade" cx="0" cy="0" r="1">
          <stop offset="0" stopColor="var(--ink)" stopOpacity="0.10" />
          <stop offset="1" stopColor="var(--ink)" stopOpacity="0" />
        </radialGradient>
        <linearGradient id="sweep" x1="0" y1="0" x2="1" y2="0">
          <stop offset="0" stopColor="var(--ink)" stopOpacity="0" />
          <stop offset="1" stopColor="var(--ink)" stopOpacity="0.07" />
        </linearGradient>
      </defs>

      {/* orbit rings */}
      <circle cx={CX} cy={CY} r={ORBIT} className="orbit" />
      <circle cx={CX} cy={CY} r={ORBIT - 92} className="orbit faint" />
      <circle cx={CX} cy={CY} r={ORBIT + 84} className="orbit faint" />

      {scanning && (
        <g className="sweep" style={{ transformOrigin: `${CX}px ${CY}px` }}>
          <path d={`M ${CX} ${CY} L ${CX + ORBIT + 84} ${CY} A ${ORBIT + 84} ${ORBIT + 84} 0 0 0 ${CX + (ORBIT + 84) * Math.cos(-0.7)} ${CY + (ORBIT + 84) * Math.sin(-0.7)} Z`} fill="url(#sweep)" />
          <line x1={CX} y1={CY} x2={CX + ORBIT + 84} y2={CY} className="sweep-line" />
        </g>
      )}

      {/* links */}
      {nodes.map((n) => {
        const st = s.layerStatus[n.id];
        return <line key={`l-${n.id}`} x1={CX} y1={CY} x2={n.x} y2={n.y} className={`link ${st === "checking" ? "flow" : ""}`} />;
      })}

      {/* layer nodes + finding dots */}
      {nodes.map((n) => {
        const fs = s.findings.filter((f) => f.layer === n.id && f.severity !== "info");
        const open = fs.filter((f) => !fixedStates.has(s.fixes[f.id]?.state ?? ""));
        const st = s.layerStatus[n.id];
        const sev = worst(open);
        const allFixed = fs.length > 0 && open.length === 0;
        const tone = st === "checking" ? "checking" : st === "waiting" && s.phase !== "idle" ? "waiting" : allFixed ? "fixed" : s.phase === "idle" ? "idle" : sev ?? "clean";
        const targets = s.targets.filter((t) => t.layer === n.id && t.kind !== "machine").length;
        const dots = fs.slice(0, 14);
        const out = n.a; // dots fan outward from the center
        // Labels sit beside each node (clockwise), clear of the links (radial) and the dots (outward).
        const tx = -Math.sin(n.a);
        const ty = Math.cos(n.a);
        const gap = NODE + 14;
        const lx = n.x + tx * gap;
        const ly = n.y + ty * gap + (ty > 0.5 ? 16 : ty < -0.5 ? -22 : -4);
        const anchor = Math.abs(tx) < 0.5 ? "middle" : tx > 0 ? "start" : "end";
        const count = open.length;
        return (
          <g
            key={n.id}
            className={`layer tone-${tone} ${selected === n.id ? "selected" : ""}`}
            role="button"
            tabIndex={0}
            aria-label={`${n.name}: ${st === "checking" ? "checking" : count ? `${count} open, worst ${SEV_WORD[sev!]}` : allFixed ? "all fixed" : "nothing found"}`}
            onClick={() => onSelect(selected === n.id ? null : n.id)}
            onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && (e.preventDefault(), onSelect(selected === n.id ? null : n.id))}
          >
            {dots.map((f, i) => {
              const spread = 0.17;
              const k = i - (Math.min(dots.length, 7) - 1) / 2;
              const ring = i < 7 ? 0 : 1;
              const kk = i < 7 ? k : i - 7 - (dots.length - 8) / 2;
              const ang = out + kk * spread;
              const r = NODE + 22 + ring * 16;
              const fixed = fixedStates.has(s.fixes[f.id]?.state ?? "");
              return <circle key={f.id} cx={n.x + r * Math.cos(ang)} cy={n.y + r * Math.sin(ang)} r={5} className={`dot sev-${fixed ? "fixed" : f.severity}`} style={{ animationDelay: `${i * 40}ms` }} />;
            })}
            {st === "checking" && <circle cx={n.x} cy={n.y} r={NODE} className="pulse" />}
            <circle cx={n.x} cy={n.y} r={NODE} className="node" />
            <LayerGlyph id={n.id} x={n.x} y={n.y} />
            <text x={lx} y={ly} textAnchor={anchor} className="node-name">
              {n.name}
            </text>
            <text x={lx} y={ly + 17} textAnchor={anchor} className="node-meta">
              {st === "checking" ? "checking…" : st === "waiting" && s.phase !== "idle" ? "" : s.phase === "idle" ? "" : allFixed ? "fixed" : count ? `${count} to fix` : "safe"}
            </text>
          </g>
        );
      })}

      {/* center: this computer + score */}
      <g className="core">
        <circle cx={CX} cy={CY} r={92} className="core-halo" />
        <circle cx={CX} cy={CY} r={78} className="core-track" />
        {score != null && (
          <circle
            cx={CX}
            cy={CY}
            r={78}
            className={`core-ring ${score >= 80 ? "good" : score >= 50 ? "mid" : "bad"}`}
            strokeDasharray={`${(score / 100) * ringLen} ${ringLen}`}
            transform={`rotate(-90 ${CX} ${CY})`}
          />
        )}
        <text x={CX} y={CY + (score == null ? 6 : 14)} textAnchor="middle" className={score == null ? "core-label" : "core-score"}>
          {score == null ? (scanning ? "Checking" : "Not checked") : score}
        </text>
        <text x={CX} y={CY + (score == null ? 28 : 38)} textAnchor="middle" className="core-sub">
          {score == null ? (scanning ? "please wait" : "yet") : "out of 100"}
        </text>
      </g>
    </svg>
  );
}

function LayerGlyph({ id, x, y }: { id: Layer; x: number; y: number }) {
  // 18px line icons, drawn on a 24 grid and centered on the node.
  const d: Record<Layer, string> = {
    code: "M8 7l-5 5 5 5M16 7l5 5-5 5M13.5 5l-3 14",
    github: "M6 4v10M6 14a2.5 2.5 0 1 0 0 5 2.5 2.5 0 0 0 0-5zM6 4a2.5 2.5 0 1 0 0 0zM18 6a2.5 2.5 0 1 0 0 5 2.5 2.5 0 0 0 0-5zM18 11c0 4-6 3-11 6",
    system: "M4 5h16v11H4zM9 20h6M12 16v4",
    network: "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18zM3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18",
    files: "M6 3h8l4 4v14H6zM14 3v4h4M9 13h6M9 17h4",
    apps: "M4 4h7v7H4zM13 4h7v7h-7zM4 13h7v7H4zM13 13h7v7h-7z",
    cloud: "M7 18h10a4 4 0 0 0 .5-7.97A6 6 0 0 0 6.1 9.5 4.25 4.25 0 0 0 7 18z",
  };
  return <path d={d[id]} transform={`translate(${x - 12} ${y - 12})`} className="glyph" />;
}

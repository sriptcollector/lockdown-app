// Shared shapes for scans, findings, fixes and the undo journal.

export type Layer =
  | "code" // secrets, dependencies, insecure code, reverse engineering
  | "github" // account and repo settings
  | "system" // OS updates, firewall, encryption, admin, startup
  | "network" // open ports, sharing, remote access, Wi-Fi
  | "files" // secrets sitting in plain files, key permissions
  | "apps" // risky apps, browser extensions
  | "cloud"; // cloud keys, buckets, tokens

export const LAYERS: { id: Layer; name: string }[] = [
  { id: "code", name: "Code" },
  { id: "github", name: "GitHub" },
  { id: "system", name: "System" },
  { id: "network", name: "Network" },
  { id: "files", name: "Files" },
  { id: "apps", name: "Apps" },
  { id: "cloud", name: "Cloud" },
];

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export const SEVERITY_RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

/** Something the user relies on that a fix could take away. Preferences say which ones to keep. */
export type Reliance =
  | "remote-access" // Remote Desktop, SSH in, screen sharing
  | "file-sharing" // shared folders other devices use
  | "lan-dev-servers" // phones or other PCs reach a dev server on this machine
  | "public-repos" // repos that are meant to be open source
  | "direct-push" // pushing straight to main, from you or your scripts/agents
  | "unsigned-scripts" // running scripts you downloaded or wrote
  | "git-history" // rewriting history would disrupt other clones
  | "build" // the project's build or tests
  | "running-app"; // an app or service that is running now

export interface BreakRisk {
  /** Plain words shown to the user: "this might break X". */
  says: string;
  reliance: Reliance;
  /** What we saw that makes the risk real, e.g. "an RDP session is connected now". */
  evidence?: string;
  level: "likely" | "possible";
}

export interface FixPlan {
  /** Fixer id from the registry, e.g. "win.firewall.enable". */
  fixer: string;
  /** Short action in plain words: "Turn the firewall on for all networks". */
  action: string;
  params: Record<string, unknown>;
  /** Needs an admin prompt (UAC / sudo). */
  admin?: boolean;
  /** Lands as a pull request rather than a local change. */
  pr?: boolean;
  /** Filled by the break-risk check before applying. */
  risks?: BreakRisk[];
  /** A fix that can only be done by the user (e.g. rotate a key at the provider). */
  manual?: string;
}

export interface Finding {
  id: string; // stable: layer + check + subject hash
  layer: Layer;
  check: string; // check id, e.g. "win.firewall"
  severity: Severity;
  title: string; // plain, short: "Firewall is off on public networks"
  why: string; // one sentence on how this gets you hacked
  where?: string; // path, repo, port, setting
  /** Redacted evidence; never a full secret. */
  evidence?: string;
  fix?: FixPlan;
  /** Which open-source scanner found it, for credit. */
  source?: string;
}

export interface Target {
  kind: "machine" | "repo" | "github-account" | "github-repo" | "cloud";
  id: string;
  name: string;
  layer: Layer;
}

export type ScanEvent =
  | { type: "start"; runId: string; at: string; platform: string; layers: Layer[] }
  | { type: "target"; target: Target }
  | { type: "check-start"; layer: Layer; check: string; label: string; targetId?: string }
  | { type: "finding"; finding: Finding; targetId?: string }
  | { type: "check-done"; layer: Layer; check: string; targetId?: string; ms: number; status: "ok" | "skipped" | "error"; note?: string }
  | { type: "progress"; done: number; total: number }
  | { type: "done"; at: string; summary: ScanSummary };

export interface ScanSummary {
  runId: string;
  platform: string;
  score: number; // 0..100
  counts: Record<Severity, number>;
  byLayer: Record<Layer, number>;
  targets: number;
  checksRun: number;
  checksSkipped: number;
  fixable: number;
}

export interface ScanResult {
  summary: ScanSummary;
  findings: Finding[];
  targets: Target[];
  checks: { layer: Layer; check: string; targetId?: string; status: string; note?: string; ms: number }[];
}

/** One applied change, with everything needed to undo it. */
export interface Change {
  id: string;
  runId: string;
  findingId: string;
  fixer: string;
  action: string;
  at: string;
  /** Opaque before-state the fixer's undo understands. */
  before: unknown;
  after?: unknown;
  /** Files copied aside before editing: original path -> backup path. */
  backups?: Record<string, string>;
  undone?: string; // timestamp
  result: "applied" | "failed" | "skipped" | "pr-opened";
  note?: string;
}

export interface Preferences {
  /** How fixes apply. */
  mode: "safe-auto" | "all-auto" | "review";
  /** For code fixes. */
  code: "pr-automerge" | "pr-only" | "direct";
  /** Things the user relies on; fixes that would break them are held back. */
  keep: Reliance[];
  /** Allowed to rewrite git history to purge leaked secrets. */
  rewriteHistory: boolean;
  /** Folders to look for code in; empty = home folder. */
  codeRoots: string[];
  /** Check every GitHub repo, not only the ones on this computer. */
  allGithubRepos: boolean;
  /** Weekly re-scan. */
  watch: boolean;
  /** Live sites to check from the outside (your own sites only). */
  sites?: string[];
}

export const DEFAULT_PREFS: Preferences = {
  mode: "safe-auto",
  code: "pr-automerge",
  keep: [],
  rewriteHistory: false,
  codeRoots: [],
  allGithubRepos: true,
  watch: true,
};

import { existsSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { mayRead } from "./permissions";
import { HOME, IS_MAC, IS_WIN } from "./util";

const SKIP_DIRS = new Set([
  "node_modules", ".git", ".next", ".nuxt", ".svelte-kit", "dist", "build", "out", "target", ".venv", "venv", "env",
  "__pycache__", ".cache", ".gradle", ".m2", ".npm", ".pnpm-store", ".yarn", ".cargo", ".rustup", "Pods", "DerivedData",
  "AppData", "Library", "Application Data", "Local Settings", ".Trash", "$RECYCLE.BIN", "System Volume Information",
  ".tmp", "tmp", "temp", "vendor", "site-packages", ".terraform", ".turbo", ".vercel", ".firebase", "coverage",
]);

/** Folders where people keep code; the user's chosen roots win. */
export function codeRoots(prefRoots: string[]): string[] {
  if (prefRoots.length) return prefRoots.filter(existsSync);
  const c = ["code", "Code", "dev", "Developer", "projects", "Projects", "src", "repos", "git", "GitHub", "workspace", "Sites", "Desktop", "Documents"];
  const roots = c.map((d) => join(HOME, d));
  for (const cloud of cloudFolders()) roots.push(join(cloud, "Desktop"), join(cloud, "Documents"), join(cloud, "code"));
  roots.push(HOME); // shallow pass over home itself
  return [...new Set(roots)].filter((p) => existsSync(p) && mayRead(p));
}

/** Folders that sync to someone else's cloud. */
export function cloudFolders(): string[] {
  const out: string[] = [];
  if (IS_WIN) {
    for (const v of ["OneDrive", "OneDriveConsumer", "OneDriveCommercial"]) if (process.env[v]) out.push(process.env[v]!);
  }
  for (const d of ["OneDrive", "Dropbox", "Google Drive", "iCloudDrive", "Box"]) out.push(join(HOME, d));
  if (IS_MAC) out.push(join(HOME, "Library", "Mobile Documents", "com~apple~CloudDocs"));
  return [...new Set(out)].filter((p) => existsSync(p));
}

export function inCloudFolder(p: string): string | null {
  const n = p.toLowerCase().replace(/\\/g, "/");
  for (const c of cloudFolders()) {
    if (n.startsWith(c.toLowerCase().replace(/\\/g, "/") + "/")) return c.split(/[\\/]/).pop() || c;
  }
  return null;
}

export interface WalkOpts {
  maxDepth: number;
  /** Return true to collect this entry. */
  match: (name: string, full: string, isDir: boolean) => boolean;
  /** Don't descend into a matched directory. */
  stopAtMatch?: boolean;
  limit?: number;
  skipDirs?: Set<string>;
}

export function walk(root: string, opts: WalkOpts): string[] {
  const out: string[] = [];
  const skip = opts.skipDirs ?? SKIP_DIRS;
  const seen = new Set<string>();
  const visit = (dir: string, depth: number) => {
    if (out.length >= (opts.limit ?? 5000)) return;
    const key = dir.toLowerCase();
    if (seen.has(key)) return;
    seen.add(key);
    // Never look inside a folder macOS guards unless the person allowed it (no surprise popups).
    if (!mayRead(dir)) return;
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      if (e.isSymbolicLink()) continue;
      const full = join(dir, e.name);
      const isDir = e.isDirectory();
      if (opts.match(e.name, full, isDir)) {
        out.push(full);
        if (isDir && opts.stopAtMatch) continue;
      }
      if (isDir && depth < opts.maxDepth && !skip.has(e.name) && !(e.name.startsWith(".") && e.name !== ".config")) visit(full, depth + 1);
    }
  };
  visit(root, 0);
  return out;
}

export function fileSize(p: string): number {
  try {
    return statSync(p).size;
  } catch {
    return -1;
  }
}

/** Every git repo under the code roots. */
export function findRepos(roots: string[]): string[] {
  const repos = new Set<string>();
  for (const r of roots) {
    const depth = r === HOME ? 1 : 4;
    for (const g of walk(r, { maxDepth: depth, match: (n, _f, d) => d && n === ".git", limit: 2000, skipDirs: new Set([...SKIP_DIRS].filter((x) => x !== ".git")) })) {
      repos.add(g.slice(0, -5));
    }
    if (existsSync(join(r, ".git")) && r !== HOME) repos.add(r + (r.endsWith("\\") || r.endsWith("/") ? "" : IS_WIN ? "\\" : "/"));
  }
  const home = HOME.replace(/[\\/]+$/, "").toLowerCase();
  return [...repos].map((p) => p.replace(/[\\/]+$/, "")).filter((p) => p.toLowerCase() !== home);
}

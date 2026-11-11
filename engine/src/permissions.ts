// macOS asks once per protected folder ("Lockdown would like to access files in your Documents folder").
// A scan must never set off those popups by surprise: the app asks for them up front in a guided step,
// remembers each answer, and the scan only reads folders the person allowed.
import { existsSync, readdirSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { readdir } from "node:fs/promises";
import { join, sep } from "node:path";
import { dataDir, HOME, IS_MAC } from "./util";

export type Access = "allowed" | "denied" | "unasked";
export interface Folder {
  id: string;
  label: string;
  path: string;
  state: Access;
}

const file = () => join(dataDir(), "folders.json");
function saved(): Record<string, Access> {
  try {
    return existsSync(file()) ? JSON.parse(readFileSync(file(), "utf8")) : {};
  } catch {
    return {};
  }
}
function save(id: string, state: Access) {
  writeFileSync(file(), JSON.stringify({ ...saved(), [id]: state }));
  cache = null;
}
// The scan checks every folder it walks, so keep the list for a moment instead of re-reading it each time.
let cache: { at: number; list: Folder[] } | null = null;

/** Folders macOS guards with a popup, that Lockdown wants to look in. Empty on Windows. */
export function protectedFolders(): Folder[] {
  if (!IS_MAC) return [];
  if (cache && Date.now() - cache.at < 2000) return cache.list;
  const s = saved();
  const list: [string, string, string][] = [
    ["desktop", "Desktop", join(HOME, "Desktop")],
    ["documents", "Documents", join(HOME, "Documents")],
    ["downloads", "Downloads", join(HOME, "Downloads")],
    ["icloud", "iCloud Drive", join(HOME, "Library", "Mobile Documents", "com~apple~CloudDocs")],
  ];
  const cloud = join(HOME, "Library", "CloudStorage");
  try {
    for (const d of readdirSync(cloud)) {
      const label = d.split("-")[0].replace(/([a-z])([A-Z])/g, "$1 $2");
      list.push([`cloud-${d.toLowerCase()}`, label, join(cloud, d)]);
    }
  } catch {}
  const out = list.filter(([, , p]) => existsSync(p)).map(([id, label, path]) => ({ id, label, path, state: s[id] ?? ("unasked" as Access) }));
  cache = { at: Date.now(), list: out };
  return out;
}

/** True once the person has answered every folder popup (or on Windows, where there are none). */
export function foldersAnswered(): boolean {
  return protectedFolders().every((f) => f.state !== "unasked");
}

/**
 * Asks for one folder: the first look shows the macOS popup and waits for the answer. Later calls never
 * show a popup (macOS only asks once), so they double as "did you turn it on in Settings yet?".
 */
export async function requestFolder(id: string): Promise<Access> {
  const f = protectedFolders().find((x) => x.id === id);
  if (!f) return "denied";
  let state: Access;
  try {
    await readdir(f.path);
    state = "allowed";
  } catch (e: any) {
    state = e?.code === "EPERM" || e?.code === "EACCES" ? "denied" : "allowed";
  }
  save(id, state);
  return state;
}

/** Re-checks folders that were refused, without any popup. */
export async function recheckDenied(): Promise<Folder[]> {
  for (const f of protectedFolders()) if (f.state === "denied") await requestFolder(f.id);
  return protectedFolders();
}

/** The scan asks this before reading a path: false inside a guarded folder that wasn't allowed. */
export function mayRead(p: string): boolean {
  if (!IS_MAC) return true;
  // ~/Dropbox and friends are links into ~/Library/CloudStorage; resolving a link never shows a popup.
  let real = p;
  try {
    real = realpathSync(p);
  } catch {}
  for (const f of protectedFolders()) {
    for (const q of new Set([p, real])) if (q === f.path || q.startsWith(f.path + sep)) return f.state === "allowed";
  }
  return true;
}

/** Guarded folders the scan had to skip, for an honest "not checked" note. */
export function skippedFolders(): Folder[] {
  return protectedFolders().filter((f) => f.state !== "allowed");
}

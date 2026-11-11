import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { DEFAULT_PREFS, type Preferences } from "./types";
import { dataDir } from "./util";

const file = () => join(dataDir(), "preferences.json");

export function loadPrefs(): Preferences {
  if (!existsSync(file())) return { ...DEFAULT_PREFS };
  try {
    return { ...DEFAULT_PREFS, ...JSON.parse(readFileSync(file(), "utf8")) };
  } catch {
    return { ...DEFAULT_PREFS };
  }
}

export function savePrefs(p: Partial<Preferences>): Preferences {
  const next = { ...loadPrefs(), ...p };
  writeFileSync(file(), JSON.stringify(next, null, 2));
  return next;
}

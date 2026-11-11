// Talks to the local engine (127.0.0.1, per-launch token). In the browser with ?demo it replays
// a recorded-style scan with sample data instead, so the page can show it working.
import { demoFix, demoQuestions, demoScan } from "./demo";
import type { Ev } from "./state";

export interface Bridge {
  demo: boolean;
  onEvent(fn: (e: Ev) => void): () => void;
  state(): Promise<any>;
  scan(): Promise<void>;
  fix(approve?: string[], only?: string[], keep?: string[]): Promise<void>;
  questions(): Promise<any[]>;
  openTarget(target: string): Promise<void>;
  undo(target: string): Promise<void>;
  savePrefs(p: unknown): Promise<void>;
  account(body: { action: string; email?: string; code?: string; plan?: string }): Promise<any>;
  open(url: string): Promise<void>;
  /** macOS folder popups, asked up front (empty list on Windows). */
  permissions(): Promise<{ platform: string; folders: Folder[]; answered: boolean }>;
  requestFolder(id: string): Promise<{ id: string; state: Folder["state"] }>;
  recheckFolders(): Promise<{ folders: Folder[] }>;
}

export interface Folder {
  id: string;
  label: string;
  path: string;
  state: "allowed" | "denied" | "unasked";
}

async function openUrl(url: string) {
  if ((window as any).__TAURI_INTERNALS__) {
    const { openUrl } = await import("@tauri-apps/plugin-opener");
    await openUrl(url);
  } else window.open(url, "_blank", "noopener");
}

async function engineInfo(): Promise<{ port: number; token: string } | null> {
  const q = new URLSearchParams(location.search);
  if (q.get("port") && q.get("t")) return { port: Number(q.get("port")), token: q.get("t")! };
  if ((window as any).__TAURI_INTERNALS__) {
    const { invoke } = await import("@tauri-apps/api/core");
    for (let i = 0; i < 60; i++) {
      const info = await invoke<{ port: number; token: string } | null>("engine_info");
      if (info) return info;
      await new Promise((r) => setTimeout(r, 250));
    }
  }
  return null;
}

export async function connect(): Promise<Bridge> {
  const info = new URLSearchParams(location.search).has("demo") ? null : await engineInfo();
  const subs = new Set<(e: Ev) => void>();
  const emit = (e: Ev) => subs.forEach((s) => s(e));
  if (!info) return demoBridge(subs, emit);

  const base = `http://127.0.0.1:${info.port}`;
  const headers = { authorization: `Bearer ${info.token}`, "content-type": "application/json" };
  const call = async (path: string, body?: unknown) => {
    const r = await fetch(base + path, { method: body === undefined ? "GET" : "POST", headers, body: body === undefined ? undefined : JSON.stringify(body) });
    if (!r.ok) throw new Error((await r.json().catch(() => ({})))?.error ?? `engine said ${r.status}`);
    return r.json();
  };
  const es = new EventSource(`${base}/events?t=${info.token}`);
  es.onmessage = (m) => emit(JSON.parse(m.data));
  return {
    demo: false,
    onEvent: (fn) => (subs.add(fn), () => subs.delete(fn)),
    state: () => call("/state"),
    scan: () => call("/scan", {}),
    fix: (approve, only, keep) => call("/fix", { approve, only, keep }),
    questions: () => call("/questions"),
    openTarget: (target) => call("/open", { target }),
    undo: (target) => call("/undo", { target }),
    savePrefs: (p) => call("/prefs", p),
    account: (b) => (b.action === "refresh" ? call("/account") : call("/account", b)),
    open: openUrl,
    permissions: () => call("/permissions"),
    requestFolder: (id) => call("/permissions/request", { id }),
    recheckFolders: () => call("/permissions/recheck", {}),
  };
}

function demoBridge(subs: Set<(e: Ev) => void>, emit: (e: Ev) => void): Bridge {
  let prefs: any = JSON.parse(localStorage.getItem("lockdown-demo-prefs") ?? "null");
  let lastFindings: any[] = [];
  // ?demo&mac plays the macOS folder step: Documents gets "Don't Allow", then gets turned on in Settings.
  const mac = new URLSearchParams(location.search).has("mac");
  const folders: Folder[] = mac
    ? [
        { id: "desktop", label: "Desktop", path: "~/Desktop", state: "unasked" },
        { id: "documents", label: "Documents", path: "~/Documents", state: "unasked" },
        { id: "downloads", label: "Downloads", path: "~/Downloads", state: "unasked" },
      ]
    : [];
  let rechecks = 0;
  return {
    demo: true,
    permissions: async () => ({ platform: mac ? "darwin" : "demo", folders: folders.map((f) => ({ ...f })), answered: folders.every((f) => f.state !== "unasked") }),
    requestFolder: async (id) => {
      await new Promise((r) => setTimeout(r, 1400));
      const f = folders.find((x) => x.id === id)!;
      f.state = id === "documents" ? "denied" : "allowed";
      return { id, state: f.state };
    },
    recheckFolders: async () => {
      if (++rechecks > 2) for (const f of folders) if (f.state === "denied") f.state = "allowed";
      return { folders: folders.map((f) => ({ ...f })) };
    },
    onEvent: (fn) => (subs.add(fn), () => subs.delete(fn)),
    state: async () => ({ prefs, latest: null, runs: [], busy: null, canFix: true }),
    account: async () => ({ canFix: true, plan: "pro", checkoutOpen: false }),
    open: openUrl,
    scan: async () => {
      lastFindings = [];
      // ?demo&instant jumps straight to results (for screenshots); otherwise it plays in real time.
      const speed = new URLSearchParams(location.search).has("instant") ? 400 : 1;
      demoScan((e) => {
        if (e.type === "finding") lastFindings.push(e.finding);
        emit(e);
      }, speed);
    },
    fix: async (approve, only, keep) => demoFix(lastFindings, approve ?? [], { ...(prefs ?? {}), keep: keep ?? [] }, emit, only),
    questions: async () => demoQuestions(lastFindings),
    openTarget: async () => {},
    undo: async (target) => {
      emit({ type: "undo-done", changes: lastFindings.filter((f) => target === "last" || target.endsWith(f.id)).map((f) => ({ id: `demo:${f.id}`, findingId: f.id })) });
    },
    savePrefs: async (p) => {
      prefs = { ...(prefs ?? {}), ...(p as object) };
      localStorage.setItem("lockdown-demo-prefs", JSON.stringify(prefs));
    },
  };
}

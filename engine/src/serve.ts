// Local bridge for the desktop UI: 127.0.0.1 only, random port, and a per-launch token the app
// passes in a header. Streams scan and fix events as server-sent events.
import { randomBytes } from "node:crypto";
import { applyPlan, latestScan, listRuns, loadJournal, makePlan, questionsFor, undo } from "./fix";
import { IS_MAC, IS_WIN, run } from "./util";
import { account, canFix } from "./license";
import { foldersAnswered, protectedFolders, recheckDenied, requestFolder } from "./permissions";
import { loadPrefs, savePrefs } from "./prefs";
import { runScan } from "./scan";
import { credits } from "./scanners/tools";
import type { Layer } from "./types";

export function serve(port = 0, token = process.env.LOCKDOWN_TOKEN || randomBytes(24).toString("hex")) {
  const listeners = new Set<(e: unknown) => void>();
  const broadcast = (e: unknown) => listeners.forEach((l) => l(e));
  let busy: "scan" | "fix" | null = null;
  const allowedOrigins = /^(tauri:\/\/localhost|https?:\/\/tauri\.localhost|http:\/\/(localhost|127\.0\.0\.1):\d+)$/;

  const server = Bun.serve({
    hostname: "127.0.0.1",
    port,
    idleTimeout: 0,
    async fetch(req) {
      const origin = req.headers.get("origin") ?? "";
      const cors: Record<string, string> = allowedOrigins.test(origin) ? { "Access-Control-Allow-Origin": origin, "Access-Control-Allow-Headers": "authorization,content-type", "Access-Control-Allow-Methods": "GET,POST" } : {};
      if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });
      const url = new URL(req.url);
      const auth = req.headers.get("authorization") ?? `Bearer ${url.searchParams.get("t") ?? ""}`;
      if (auth !== `Bearer ${token}`) return new Response("forbidden", { status: 403, headers: cors });
      const json = (d: unknown, status = 200) => new Response(JSON.stringify(d), { status, headers: { ...cors, "content-type": "application/json" } });

      if (url.pathname === "/events") {
        let send: (e: unknown) => void;
        const stream = new ReadableStream({
          start(c) {
            send = (e) => c.enqueue(`data: ${JSON.stringify(e)}\n\n`);
            listeners.add(send);
            c.enqueue(`: hi\n\n`);
          },
          cancel() {
            listeners.delete(send);
          },
        });
        return new Response(stream, { headers: { ...cors, "content-type": "text/event-stream", "cache-control": "no-store" } });
      }
      if (url.pathname === "/account") {
        try {
          if (req.method === "POST") {
            const b = (await req.json()) as { action: string; email?: string; code?: string; plan?: "monthly" | "yearly" };
            if (b.action === "start") return json(await account.start(String(b.email)));
            if (b.action === "verify") return json(await account.verify(String(b.email), String(b.code)));
            if (b.action === "checkout") return json(await account.checkout(b.plan ?? "yearly", b.email));
          }
          return json({ ...(await account.refresh()), canFix: canFix(), checkoutOpen: await account.checkoutOpen() });
        } catch (e: any) {
          return json({ error: String(e?.message ?? e) }, 400);
        }
      }
      if (url.pathname === "/state") return json({ busy, canFix: canFix(), prefs: loadPrefs(), latest: latestScan(), runs: listRuns().slice(-20).map((r) => ({ runId: r, changes: loadJournal(r) })), credits: credits() });
      if (url.pathname === "/prefs" && req.method === "POST") return json(savePrefs(await req.json()));
      // macOS folder popups, asked up front one at a time (see permissions.ts).
      if (url.pathname === "/permissions") return json({ platform: process.platform, folders: protectedFolders(), answered: foldersAnswered() });
      if (url.pathname === "/permissions/request" && req.method === "POST") {
        const { id } = (await req.json()) as { id: string };
        return json({ id, state: await requestFolder(String(id)) });
      }
      if (url.pathname === "/permissions/recheck" && req.method === "POST") return json({ folders: await recheckDenied() });
      if (url.pathname === "/scan" && req.method === "POST") {
        if (busy) return json({ error: `already running a ${busy}` }, 409);
        const body = (await req.json().catch(() => ({}))) as { layers?: Layer[] };
        busy = "scan";
        runScan(loadPrefs(), broadcast, body.layers ?? (process.env.LOCKDOWN_LAYERS?.split(",") as Layer[] | undefined)).then((r) => account.summary({ score: r.summary.score, platform: r.summary.platform, counts: r.summary.counts })).catch((e) => broadcast({ type: "error", message: String(e?.message ?? e) })).finally(() => (busy = null));
        return json({ ok: true });
      }
      if (url.pathname === "/questions") {
        const scan = latestScan();
        if (!scan) return json([]);
        return json(questionsFor(await makePlan(scan, loadPrefs())));
      }
      if (url.pathname === "/open" && req.method === "POST") {
        // Opens a settings page or a provider page for the few things only the user can do.
        const { target } = (await req.json()) as { target: string };
        if (!/^(ms-settings:|windowsdefender:|x-apple\.systempreferences:|https:\/\/)/.test(target)) return json({ error: "not allowed" }, 400);
        if (IS_WIN) await run("cmd.exe", ["/c", "start", "", target]);
        else if (IS_MAC) await run("open", [target]);
        return json({ ok: true });
      }
      if (url.pathname === "/plan") {
        const scan = latestScan();
        if (!scan) return json({ error: "no scan yet" }, 400);
        const plan = await makePlan(scan, loadPrefs());
        return json(plan.map((p) => ({ id: p.finding.id, decision: p.decision, reason: p.reason, risks: p.risks })));
      }
      if (url.pathname === "/fix" && req.method === "POST") {
        if (busy) return json({ error: `already running a ${busy}` }, 409);
        const body = (await req.json().catch(() => ({}))) as { only?: string[]; approve?: string[]; keep?: string[] };
        // Answers to the plain questions: "keep" remembers what they rely on, so it's never asked again.
        if (body.keep?.length) savePrefs({ keep: [...new Set([...loadPrefs().keep, ...body.keep])] as any });
        const scan = latestScan();
        if (!scan) return json({ error: "no scan yet" }, 400);
        busy = "fix";
        (async () => {
          const prefs = loadPrefs();
          const plan = await makePlan(scan, prefs, body.only);
          // Items the user approved in the app run even if the preferences would hold them.
          for (const p of plan) if (body.approve?.includes(p.finding.id) && p.decision === "hold") p.decision = "apply";
          broadcast({ type: "fix-plan", items: plan.map((p) => ({ id: p.finding.id, decision: p.decision, reason: p.reason, risks: p.risks })) });
          const r = await applyPlan(plan, prefs, broadcast);
          broadcast({ type: "fix-finished", runId: r.runId, changes: r.changes });
        })()
          .catch((e) => broadcast({ type: "error", message: String(e?.message ?? e) }))
          .finally(() => (busy = null));
        return json({ ok: true });
      }
      if (url.pathname === "/undo" && req.method === "POST") {
        const body = (await req.json()) as { target: string };
        const done = await undo(body.target);
        broadcast({ type: "undo-done", changes: done });
        return json(done);
      }
      return new Response("not found", { status: 404, headers: cors });
    },
  });
  // The desktop shell reads this line to find the bridge.
  process.stdout.write(JSON.stringify({ ready: true, port: server.port, token }) + "\n");
  return server;
}

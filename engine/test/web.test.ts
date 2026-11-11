// The live-site check must catch a served source map, a key in a bundle, and a browser-side AI call.
import { expect, test } from "bun:test";
import { auditSite } from "../src/checks/web";

test("flags source maps, client keys and browser AI calls", async () => {
  const key = "sk_live_" + "Zq8".repeat(4) + "Xw2Lp9Rt7Vb";
  const srv = Bun.serve({
    port: 0,
    fetch(req) {
      const p = new URL(req.url).pathname;
      if (p === "/") return new Response(`<html><script src="/app.js"></script></html>`, { headers: { "content-type": "text/html" } });
      if (p === "/app.js") return new Response(`const k="${key}";fetch("https://api.openai.com/v1/chat");\n//# sourceMappingURL=app.js.map`);
      if (p === "/app.js.map") return Response.json({ version: 3, sources: ["src/app.ts"], mappings: "AAAA" });
      return new Response("no", { status: 404 });
    },
  });
  const checks = (await auditSite(`http://127.0.0.1:${srv.port}/`)).map((f) => f.check);
  srv.stop();
  expect(checks).toContain("web.sourcemaps");
  expect(checks).toContain("web.client-secret");
  expect(checks).toContain("web.client-ai");
  expect(checks).toContain("web.csp");
});

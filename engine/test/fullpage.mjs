// Full-page screenshots (every step visible) for persona tests.
//   node fullpage.mjs <devtools-url> <url> <out.png> <width> [dark]
import { writeFileSync } from "node:fs";
const [devtools, url, out, width, dark] = process.argv.slice(2);
const t = await (await fetch(`${devtools}/json/new?about:blank`, { method: "PUT" })).json();
const ws = new WebSocket(t.webSocketDebuggerUrl);
await new Promise((r) => (ws.onopen = r));
let id = 0;
const pend = new Map();
ws.onmessage = (m) => { const d = JSON.parse(m.data); if (pend.has(d.id)) { pend.get(d.id)(d); pend.delete(d.id); } };
const send = (method, params = {}) => new Promise((r) => { const i = ++id; pend.set(i, r); ws.send(JSON.stringify({ id: i, method, params })); });
await send("Page.enable");
await send("Emulation.setDeviceMetricsOverride", { width: Number(width), height: 900, deviceScaleFactor: 1, mobile: Number(width) < 600 });
if (dark) await send("Emulation.setEmulatedMedia", { features: [{ name: "prefers-color-scheme", value: "dark" }] });
await send("Page.navigate", { url });
await new Promise((r) => setTimeout(r, 3500));
const r = await send("Page.captureScreenshot", { format: "png", captureBeyondViewport: true });
writeFileSync(out, Buffer.from(r.result.data, "base64"));
await send("Page.close");
ws.close();

// Drives Lockdown the way a non-technical person would: one click to check, one click to fix,
// accept the recommended answers, read the result. Takes a screenshot at every step.
// Talks Chrome DevTools Protocol to either the real app's WebView2 (Windows) or Chrome (Mac).
//   node consumer-drive.mjs <devtools-http-url> <outDir> [appUrl]
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const [devtools, out, appUrl] = process.argv.slice(2);
mkdirSync(out, { recursive: true });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let target;
for (let i = 0; i < 120 && !target; i++) {
  try {
    const list = await (await fetch(`${devtools}/json/list`)).json();
    target = list.find((t) => t.type === "page" && !/devtools/.test(t.url));
  } catch {}
  if (!target) await sleep(1000);
}
if (!target) throw new Error("no page to drive");
const ws = new WebSocket(target.webSocketDebuggerUrl);
await new Promise((r) => (ws.onopen = r));
let id = 0;
const pending = new Map();
ws.onmessage = (m) => {
  const d = JSON.parse(m.data);
  if (d.id && pending.has(d.id)) {
    pending.get(d.id)(d);
    pending.delete(d.id);
  }
};
const send = (method, params = {}) => new Promise((r) => { const i = ++id; pending.set(i, r); ws.send(JSON.stringify({ id: i, method, params })); });
const evaluate = async (expr) => (await send("Runtime.evaluate", { expression: expr, awaitPromise: true, returnByValue: true })).result?.result?.value;
const text = () => evaluate(`document.querySelector('.findings') ? 'What changed: ' + document.querySelectorAll('.finding.is-fixed').length + ' fixed of ' + document.querySelectorAll('.finding').length : (document.querySelector('.panel h1')?.textContent||'') + ' | ' + (document.querySelector('.panel .lede')?.textContent||'')`);
let n = 0;
const steps = [];
const shot = async (name) => {
  const r = await send("Page.captureScreenshot", { format: "png" });
  const file = `${String(++n).padStart(2, "0")}-${name}.png`;
  writeFileSync(join(out, file), Buffer.from(r.result.data, "base64"));
  const t = await text();
  steps.push({ file, screen: t });
  console.log(`${file}: ${t}`);
};
const waitFor = async (pred, ms) => {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (await evaluate(pred)) return true;
    await sleep(1000);
  }
  return false;
};
const click = (sel) => evaluate(`(()=>{const b=document.querySelector(${JSON.stringify(sel)}); if(b){b.click(); return true} return false})()`);

await send("Page.enable");
await send("Emulation.setDeviceMetricsOverride", { width: 1280, height: 820, deviceScaleFactor: 1, mobile: false });
if (appUrl) {
  await send("Page.navigate", { url: appUrl });
  await sleep(3000);
}
if (!(await waitFor(`!!document.querySelector('.btn.huge')`, 60000))) throw new Error("the app never showed its button");
await shot("welcome");
await click(".btn.huge");
await sleep(6000);
await shot("checking");
if (!(await waitFor(`/We found|You're safe/.test(document.querySelector('.panel h1')?.textContent||'')`, 20 * 60000))) throw new Error("the check never finished");
await shot("found");
await click(".btn.huge");
await sleep(2500);
for (let i = 0; i < 8 && (await evaluate(`!!document.querySelector('.choices')`)); i++) {
  await shot(`question-${i + 1}`);
  await click(".btn.huge"); // keep the recommended answer, like most people would
  await sleep(1200);
}
await sleep(2000);
await shot("fixing");
if (!(await waitFor(`/You're safe|Almost safe|Much safer/.test(document.querySelector('.panel h1')?.textContent||'')`, 15 * 60000))) throw new Error("fixing never finished");
await sleep(1500);
await shot("done");
await evaluate(`[...document.querySelectorAll(".textlink")].find(l=>/what changed/i.test(l.textContent))?.click()`);
await sleep(1500);
await shot("what-changed");
const jargon = await evaluate(`[...document.querySelectorAll('.panel.hero, .topbar')].map(e=>e.innerText).join(' ').match(/\\b(CVE|IAM|UAC|firewall rule|fix 0|registry|HKLM|sshd|CORS)\\b/gi)`);
writeFileSync(join(out, "steps.json"), JSON.stringify({ steps, jargonOnMainPath: jargon ?? [] }, null, 1));
console.log(`jargon on the main path: ${jargon ? jargon.join(", ") : "none"}`);
ws.close();

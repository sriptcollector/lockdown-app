// Signed-in walkthrough: check, press Fix, sign in with a real emailed code, then fix.
// Waits for the code to appear in <outDir>/code.txt (read from the inbox by the tester).
//   node account-drive.mjs <devtools-url> <outDir> <appUrl> <email>
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const [devtools, out, appUrl, email] = process.argv.slice(2);
mkdirSync(out, { recursive: true });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const list = await (await fetch(`${devtools}/json/list`)).json();
const ws = new WebSocket(list.find((t) => t.type === "page").webSocketDebuggerUrl);
await new Promise((r) => (ws.onopen = r));
let id = 0;
const pending = new Map();
ws.onmessage = (m) => { const d = JSON.parse(m.data); if (pending.has(d.id)) { pending.get(d.id)(d); pending.delete(d.id); } };
const send = (method, params = {}) => new Promise((r) => { const i = ++id; pending.set(i, r); ws.send(JSON.stringify({ id: i, method, params })); });
const ev = async (e) => (await send("Runtime.evaluate", { expression: e, awaitPromise: true, returnByValue: true })).result?.result?.value;
let n = 0;
const shot = async (name) => {
  const r = await send("Page.captureScreenshot", { format: "png" });
  const f = `${String(++n).padStart(2, "0")}-${name}.png`;
  writeFileSync(join(out, f), Buffer.from(r.result.data, "base64"));
  console.log(f, "|", await ev(`(document.querySelector('.unlock strong')?.textContent||document.querySelector('.panel h1')?.textContent||'')+' | '+(document.querySelector('.panel .lede')?.textContent||document.querySelector('.unlock .small')?.textContent||'')`));
};
const until = async (expr, ms) => { const end = Date.now() + ms; while (Date.now() < end) { if (await ev(expr)) return true; await sleep(800); } throw new Error(`timed out waiting for ${expr}`); };
const type = async (sel, value) => ev(`(()=>{const i=document.querySelector(${JSON.stringify(sel)});const set=Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set;set.call(i,${JSON.stringify(value)});i.dispatchEvent(new Event('input',{bubbles:true}));return true})()`);

await send("Page.enable");
await send("Emulation.setDeviceMetricsOverride", { width: 1280, height: 820, deviceScaleFactor: 1, mobile: false });
await send("Page.navigate", { url: appUrl });
await until(`!!document.querySelector('.btn.huge')`, 60000);
await shot("welcome");
await ev(`document.querySelector('.btn.huge').click()`);
await until(`/We found|You're safe/.test(document.querySelector('.panel h1')?.textContent||'')`, 600000);
await shot("found");
await ev(`document.querySelector('.btn.huge').click()`);
await until(`!!document.querySelector('.unlock input[type=email]')`, 30000);
await shot("sign-in");
await type(".unlock input[type=email]", email);
await ev(`document.querySelector('.unlock form button').click()`);
await until(`!!document.querySelector('.unlock input[inputmode=numeric]')`, 30000);
await shot("code-sent");
const codeFile = join(out, "code.txt");
console.log("WAITING_FOR_CODE");
while (!existsSync(codeFile)) await sleep(1000);
await type(".unlock input[inputmode=numeric]", readFileSync(codeFile, "utf8").trim());
await ev(`document.querySelector('.unlock form button').click()`);
await until(`!document.querySelector('.unlock') || /fix|safe|Fixing/i.test(document.querySelector('.panel h1')?.textContent||'')`, 60000);
for (let i = 0; i < 6 && (await ev(`!!document.querySelector('.choices')`)); i++) { await shot(`question-${i + 1}`); await ev(`document.querySelector('.btn.huge').click()`); await sleep(1000); }
await until(`/You're safe|Almost safe|Much safer/.test(document.querySelector('.panel h1')?.textContent||'')`, 600000);
await shot("done");
ws.close();

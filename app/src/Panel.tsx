// The main path, written for someone who has never heard of a firewall: one button, watch it work,
// one button to fix, a plain "You're safe". Everything technical lives behind "See what changed".
import { useEffect, useMemo, useState } from "react";
import { Check } from "./Onboarding";
import { AdminAsk, AdminRetry } from "./Permissions";
import { type Finding, isManual, type Layer, LAYERS, openFindings, SEV_ORDER, SEV_WORD, type Severity, type State } from "./state";

const fixedStates = new Set(["applied", "pr-opened"]);

export interface Question {
  reliance: string;
  question: string;
  help: string;
  options: { value: "keep" | "fix"; label: string; unsure?: boolean }[];
  recommended: "keep" | "fix";
  findingIds: string[];
  touches?: string[];
}

const isMac = /Mac/i.test(navigator.userAgent);
const PERMISSION = isMac ? "Your Mac may ask for your password once. That's Lockdown." : "Windows may ask “Allow this app to make changes?” once. Press Yes.";

export function Panel(props: {
  s: State;
  layer: Layer | null;
  setLayer: (l: Layer | null) => void;
  onScan: () => void;
  onFix: (approve?: string[], only?: string[], keep?: string[]) => void;
  onUndo: (target: string) => void;
  onOpen: (target: string) => void;
  getQuestions: () => Promise<Question[]>;
  demo: boolean;
}) {
  const { s } = props;
  const [details, setDetails] = useState(false);
  const [questions, setQuestions] = useState<Question[] | null>(null);
  // Answers survive Back, so stepping out of the questions and in again keeps what you picked.
  const [answers, setAnswers] = useState<Record<string, number>>({});
  useEffect(() => {
    if (s.phase === "scanning") setDetails(false);
  }, [s.phase]);

  if (details) return <Details {...props} back={() => setDetails(false)} />;
  if (s.phase === "idle") return <Idle onScan={props.onScan} />;
  if (s.phase === "scanning") return <Scanning s={s} />;
  if (questions) {
    return (
      <Questions
        questions={questions}
        picked={answers}
        setPicked={setAnswers}
        onBack={() => setQuestions(null)}
        onDone={(approve, keep) => {
          setQuestions(null);
          props.onFix(approve, undefined, keep);
        }}
      />
    );
  }
  if (s.phase === "fixing") return <Fixing s={s} />;
  if (s.phase === "fixed") return <Done s={s} onOpen={props.onOpen} onScan={props.onScan} onFix={props.onFix} seeDetails={() => setDetails(true)} />;
  return (
    <Found
      s={s}
      onFix={async () => {
        const q = await props.getQuestions().catch(() => []);
        if (q.length) setQuestions(q);
        else props.onFix();
      }}
      seeDetails={() => setDetails(true)}
    />
  );
}

function Idle({ onScan }: { onScan: () => void }) {
  return (
    <section className="panel hero">
      <h1>Is your computer safe?</h1>
      <p className="lede">Press the button. Lockdown checks your computer, your accounts and your code for every way someone could break in, then fixes it.</p>
      <button className="btn primary huge" onClick={onScan} autoFocus>
        <Shield /> Check my computer
      </button>
      <p className="fine">Free · about 3 minutes · nothing leaves your computer</p>
    </section>
  );
}

const PLAIN: Record<string, string> = {
  system: "Checking your computer's settings",
  network: "Checking who can reach your computer",
  files: "Looking for passwords left in files",
  apps: "Checking your apps and browser",
  code: "Checking your code for leaked keys",
  github: "Checking your GitHub account",
  cloud: "Checking your cloud accounts",
};

function Scanning({ s }: { s: State }) {
  const done = LAYERS.filter((l) => s.layerStatus[l.id] === "done").length;
  const now = s.activeChecks.at(-1);
  return (
    <section className="panel hero" aria-live="polite">
      <h1>Checking your computer…</h1>
      <div className="bar big" aria-hidden>
        <span style={{ transform: `scaleX(${Math.max(0.05, done / LAYERS.length)})` }} />
      </div>
      <p className="lede">{now ? PLAIN[now.layer] : "Getting started"}</p>
      <p className="fine">{s.findings.length ? `${s.findings.length} thing${s.findings.length === 1 ? "" : "s"} found so far` : "Nothing found yet"}</p>
    </section>
  );
}

function Found({ s, onFix, seeDetails }: { s: State; onFix: () => void; seeDetails: () => void }) {
  const open = openFindings(s).filter((f) => f.severity !== "info");
  const autoFix = open.filter((f) => !isManual(f));
  const serious = open.filter((f) => f.severity === "critical" || f.severity === "high").length;
  if (!open.length) {
    return (
      <section className="panel hero">
        <SafeMark />
        <h1>You're safe</h1>
        <p className="lede">We didn't find any way in. Lockdown will check again every week.</p>
        <button className="textlink" onClick={seeDetails}>
          See what we checked
        </button>
      </section>
    );
  }
  return (
    <section className="panel hero">
      <h1>
        We found {open.length} way{open.length === 1 ? "" : "s"} someone could get in
      </h1>
      <p className="lede">
        Your safety score is {scoreText(s)} out of 100. {serious ? `${serious} of them ${serious === 1 ? "is" : "are"} serious. ` : ""}
        {autoFix.length === open.length ? "Lockdown can fix all of them for you." : autoFix.length ? `Lockdown fixes ${autoFix.length} by itself. The other ${open.length - autoFix.length} take one click from you, and we'll show you how.` : "Each one takes one click from you, and we'll show you how."}
      </p>
      <button className="btn primary huge" onClick={onFix} autoFocus>
        <Shield /> Fix everything
      </button>
      <p className="fine">Takes about a minute. You can undo anything.</p>
      <button className="textlink" onClick={seeDetails}>
        See the list
      </button>
    </section>
  );
}

function Questions({ questions, picked: saved, setPicked, onBack, onDone }: { questions: Question[]; picked: Record<string, number>; setPicked: (p: Record<string, number>) => void; onBack: () => void; onDone: (approve: string[], keep: string[]) => void }) {
  const [i, setI] = useState(0);
  const picked: Record<string, number> = { ...Object.fromEntries(questions.map((q) => [q.reliance, q.options.findIndex((o) => o.value === q.recommended && !o.unsure)])), ...saved };
  const q = questions[i];
  const last = i === questions.length - 1;
  const value = (x: Question) => x.options[picked[x.reliance]]?.value ?? x.recommended;
  const finish = () => {
    const approve = questions.filter((x) => value(x) === "fix").flatMap((x) => x.findingIds);
    const keep = questions.filter((x) => value(x) === "keep").map((x) => x.reliance);
    onDone(approve, keep);
  };
  return (
    <section className="panel hero" aria-labelledby="q">
      <button className="textlink back" onClick={() => (i > 0 ? setI(i - 1) : onBack())}>
        ← Back
      </button>
      <p className="fine">{questions.length > 1 ? `Quick question ${i + 1} of ${questions.length}` : "One quick question"}</p>
      <h1 id="q">{q.question}</h1>
      <p className="lede">{q.help}</p>
      <div className="choices" role="radiogroup" aria-labelledby="q">
        {q.options.map((o, n) => (
          <button key={n} role="radio" aria-checked={picked[q.reliance] === n} className={`choice ${picked[q.reliance] === n ? "on" : ""} ${o.unsure ? "unsure" : ""}`} onClick={() => setPicked({ ...picked, [q.reliance]: n })}>
            <span>{o.label}</span>
            {o.value === q.recommended && !o.unsure && <span className="rec">Recommended</span>}
            <span className="choice-check" aria-hidden>
              {picked[q.reliance] === n ? <Check /> : null}
            </span>
          </button>
        ))}
      </div>
      <button className="btn primary huge" onClick={() => (last ? finish() : setI(i + 1))} autoFocus>
        {last ? "Fix everything" : "Next"}
      </button>
    </section>
  );
}

function Fixing({ s }: { s: State }) {
  const total = Object.values(s.plan).filter((p) => p.decision === "apply").length || 1;
  const done = Object.values(s.fixes).filter((f) => ["applied", "pr-opened", "failed", "skipped"].includes(f.state)).length;
  return (
    <section className="panel hero" aria-live="polite">
      <h1>Fixing…</h1>
      <div className="bar big" aria-hidden>
        <span style={{ transform: `scaleX(${Math.max(0.05, Math.min(1, done / total))})` }} />
      </div>
      <p className="lede">{s.adminAsking ? "Almost done. The last step needs your OK." : `${Math.min(done, total)} of ${total} done`}</p>
      {s.adminAsking ? <AdminAsk /> : <p className="fine">{PERMISSION}</p>}
    </section>
  );
}

function Done({ s, onOpen, onScan, onFix, seeDetails }: { s: State; onOpen: (t: string) => void; onScan: () => void; onFix: (approve?: string[], only?: string[]) => void; seeDetails: () => void }) {
  // Fixes that didn't run because the admin prompt got No / Cancel.
  const refused = Object.entries(s.fixes)
    .filter(([, f]) => f.state === "failed" && /prompt was cancel/i.test(f.note ?? ""))
    .map(([id]) => id);
  const fixed = s.findings.filter((f) => fixedStates.has(s.fixes[f.id]?.state ?? "")).length;
  const left = openFindings(s).filter((f) => f.severity !== "info");
  const yours = left.filter((f) => actionOf(f));
  const other = left.length - yours.length;
  const safe = !left.length;
  return (
    <section className="panel hero">
      {safe && <SafeMark />}
      <h1>{safe ? "You're safe" : yours.length ? "Almost safe" : "Much safer"}</h1>
      <p className="lede">
        Lockdown fixed {fixed} thing{fixed === 1 ? "" : "s"}.{" "}
        {yours.length ? `${yours.length === 1 ? "One thing needs" : `${yours.length} things need`} a click from you${other ? ` (and ${other} smaller one${other === 1 ? " is" : "s are"} in the list)` : ""}:` : other ? `${other === 1 ? "One smaller thing is" : `${other} smaller things are`} in the list if you want to look.` : "We'll check again every week."}
      </p>
      {refused.length > 0 && <AdminRetry count={refused.length} onRetry={() => onFix(refused, refused)} />}
      {yours.length > 0 && (
        <ul className="todo">
          {yours.map((f) => (
            <li key={f.id}>
              <span>{f.fix!.action}</span>
              <button className="btn primary" onClick={() => onOpen(actionOf(f)!)}>
                {buttonFor(actionOf(f)!)}
              </button>
            </li>
          ))}
        </ul>
      )}
      <p className="fine">If anything stops working, open See what changed and press Undo.</p>
      <div className="row">
        <button className="textlink" onClick={seeDetails}>
          See what changed
        </button>
        <a className="textlink" href={shareLink(s)}>
          Send the list to someone who helps you
        </a>
        <button className="textlink" onClick={onScan}>
          Check again
        </button>
      </div>
    </section>
  );
}

/** Says what the button does: "Update now", not "Do it". */
function buttonFor(target: string): string {
  if (/windowsupdate|Software-Update/i.test(target)) return "Update now";
  if (/deviceencryption|FileVault/i.test(target)) return "Turn it on";
  if (/appsfeatures/i.test(target)) return "Open apps";
  if (/threatsettings/i.test(target)) return "Open settings";
  return "Show me how";
}

/** A plain email someone can forward to whoever set up their site or computer. */
function shareLink(s: State): string {
  const open = openFindings(s).filter((f) => f.severity !== "info");
  const fixed = s.findings.filter((f) => fixedStates.has(s.fixes[f.id]?.state ?? ""));
  const body = [`Lockdown checked my computer and fixed ${fixed.length} things.`, "", "Still open:", ...open.map((f) => `- ${f.title}${f.fix?.manual ? ` (${f.fix.manual})` : ""}`), "", "Fixed:", ...fixed.map((f) => `- ${f.title}`)].join("\n");
  return `mailto:?subject=${encodeURIComponent("My Lockdown security check")}&body=${encodeURIComponent(body)}`;
}

function scoreText(s: State) {
  const W: Record<string, number> = { critical: 20, high: 8, medium: 3, low: 1, info: 0 };
  const c: Record<string, number> = {};
  for (const f of openFindings(s)) c[f.severity] = (c[f.severity] ?? 0) + 1;
  return Math.max(0, Math.round(100 - Object.entries(c).reduce((p, [k, n]) => p + W[k] * Math.sqrt(n), 0)));
}

/** The one button for something only the user can do: a settings page or the provider's page. */
export function actionOf(f: Finding): string | null {
  const p = (f.fix?.params ?? {}) as { uri?: string; url?: string };
  return (f.fix && isManual(f) && (p.uri || p.url)) || null;
}

// ---------- details: the full list, undo, and the technical words ----------
function Details({ s, layer, setLayer, onUndo, back }: Parameters<typeof Panel>[0] & { back: () => void }) {
  const [open, setOpen] = useState<string | null>(null);
  const visible = useMemo(() => s.findings.filter((f) => !layer || f.layer === layer).sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity)), [s.findings, layer]);
  const anyFixed = s.findings.some((f) => fixedStates.has(s.fixes[f.id]?.state ?? ""));
  return (
    <section className="panel results">
      <header className="results-head">
        <button className="textlink back" onClick={back}>
          ← Back
        </button>
        {anyFixed && s.fixRunId && (
          <button className="btn ghost small" onClick={() => onUndo(s.fixRunId!)}>
            Undo everything
          </button>
        )}
      </header>
      <nav className="filters" aria-label="Filter by area">
        <button className={`chip ${!layer ? "on" : ""}`} onClick={() => setLayer(null)}>
          All <span className="mono">{s.findings.length}</span>
        </button>
        {LAYERS.map((l) => {
          const n = s.findings.filter((f) => f.layer === l.id).length;
          return n ? (
            <button key={l.id} className={`chip ${layer === l.id ? "on" : ""}`} onClick={() => setLayer(layer === l.id ? null : l.id)}>
              {l.name} <span className="mono">{n}</span>
            </button>
          ) : null;
        })}
      </nav>
      <ul className="findings">
        {visible.map((f) => (
          <Row key={f.id} f={f} s={s} open={open === f.id} toggle={() => setOpen(open === f.id ? null : f.id)} onUndo={onUndo} />
        ))}
        {!visible.length && <li className="empty">Nothing found here.</li>}
      </ul>
    </section>
  );
}

function Row({ f, s, open, toggle, onUndo }: { f: Finding; s: State; open: boolean; toggle: () => void; onUndo: (id: string) => void }) {
  const fx = s.fixes[f.id];
  const fixed = fixedStates.has(fx?.state ?? "");
  const risks = s.plan[f.id]?.risks?.length ? s.plan[f.id].risks : (f.fix?.risks ?? []);
  return (
    <li className={`finding ${fixed ? "is-fixed" : ""}`}>
      <button className="finding-head" aria-expanded={open} onClick={toggle}>
        {fixed ? (
          <span className="sev sev-fixed">
            <Check />
            <span className="sev-word">Fixed</span>
          </span>
        ) : (
          <SevMark sev={f.severity} />
        )}
        <span className="finding-title">
          {f.title}
          {f.where && <span className="where mono">{f.where}</span>}
        </span>
        <span className="status muted">{fx?.state === "failed" ? "Didn't work" : fx?.state === "undone" ? "Undone" : isManual(f) && !fixed ? "Needs you" : ""}</span>
      </button>
      {open && (
        <div className="finding-body">
          <p>{f.why}</p>
          {f.evidence && <p className="evidence mono">{f.evidence}</p>}
          {f.fix && (
            <p className="fix-line">
              <span className="label">{isManual(f) ? "What to do" : fixed ? "What we did" : "The fix"}</span>
              {f.fix.action}
              {f.fix.manual ? <span className="manual">{f.fix.manual}</span> : null}
            </p>
          )}
          {risks.map((r, i) => (
            <p key={i} className="risk-line">
              {r.says}
            </p>
          ))}
          {fx?.note && <p className="muted small mono">{fx.note}</p>}
          <div className="row-actions">
            {fixed && fx?.changeId && (
              <button className="btn ghost small" onClick={() => onUndo(fx.changeId!)}>
                Undo
              </button>
            )}
            {f.source && <span className="muted small">Found by {f.source}</span>}
          </div>
        </div>
      )}
    </li>
  );
}

export function SevMark({ sev }: { sev: Severity }) {
  const word = sev === "critical" ? "Serious" : sev === "high" ? "Important" : sev === "medium" ? "Worth fixing" : "Minor";
  return (
    <span className={`sev sev-${sev}`} title={SEV_WORD[sev]}>
      <svg width="16" height="16" viewBox="0 0 16 16" aria-hidden>
        {sev === "critical" ? <path d="M8 1.8l6.6 11.6H1.4z" /> : sev === "high" ? <rect x="2.5" y="2.5" width="11" height="11" rx="2" /> : sev === "medium" ? <circle cx="8" cy="8" r="5.5" /> : <circle cx="8" cy="8" r="3.5" />}
      </svg>
      <span className="sev-word">{word}</span>
    </span>
  );
}

function SafeMark() {
  return (
    <span className="safe-mark" aria-hidden>
      <svg width="44" height="44" viewBox="0 0 24 24">
        <path d="M12 3l7 3v6c0 4.5-3 7.8-7 9-4-1.2-7-4.5-7-9V6z" fill="currentColor" />
        <path d="M8.5 12.2l2.4 2.4 4.6-5" fill="none" stroke="var(--panel)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
    </span>
  );
}

const Shield = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" aria-hidden>
    <path d="M12 3l7 3v6c0 4.5-3 7.8-7 9-4-1.2-7-4.5-7-9V6z" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinejoin="round" />
  </svg>
);

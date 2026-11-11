import { useEffect, useReducer, useRef, useState } from "react";
import { type Bridge, connect } from "./bridge";
import { SecurityMap } from "./Map";
import { Panel, type Question } from "./Panel";
import { Unlock } from "./Unlock";
import { initialState, type Layer, openFindings, type Preferences, reduce, scoreOf } from "./state";

export function App() {
  const [s, dispatch] = useReducer(reduce, undefined, initialState);
  const [bridge, setBridge] = useState<Bridge | null>(null);
  const [prefs, setPrefs] = useState<Partial<Preferences> | null | undefined>(undefined);
  const [layer, setLayer] = useState<Layer | null>(null);
  const [canFix, setCanFix] = useState(true);
  const [unlock, setUnlock] = useState<null | { approve?: string[]; only?: string[]; keep?: string[] }>(null);
  const started = useRef(false);

  useEffect(() => {
    if (started.current) return;
    started.current = true;
    connect().then(async (b) => {
      b.onEvent(dispatch);
      setBridge(b);
      const st = await b.state();
      // No setup questions: sensible defaults, saved quietly. Only risky fixes ever ask anything.
      if (!st.prefs) await b.savePrefs({ mode: "safe-auto", code: "pr-automerge", keep: [], rewriteHistory: false, allGithubRepos: true, watch: true });
      setPrefs(st.prefs ?? { mode: "safe-auto" });
      setCanFix(st.canFix !== false);
      if (st.latest) dispatch({ type: "load-latest", result: st.latest });
      if (b.demo && new URLSearchParams(location.search).has("autoplay")) {
        setPrefs(st.prefs ?? { mode: "safe-auto" });
        b.scan();
      }
    });
  }, []);

  // Keyboard: Enter starts a check from the idle screen.
  useEffect(() => {
    const k = (e: KeyboardEvent) => {
      if (e.key === "Escape") setLayer(null);
    };
    addEventListener("keydown", k);
    return () => removeEventListener("keydown", k);
  }, []);

  const score = s.phase === "idle" || s.phase === "scanning" ? null : scoreOf(openFindings(s));

  return (
    <div className="app">
      <div className={`topline ${s.phase === "scanning" || s.phase === "fixing" ? "busy" : ""}`} aria-hidden />
      <header className="topbar">
        <div className="brand">
          <LogoMark />
          <span>Lockdown</span>
          {bridge?.demo && <span className="tag mono">Sample data</span>}
        </div>
        <div className="topbar-right">
          {s.summary && s.phase !== "scanning" && <span className="muted small mono">Last check {new Date().toLocaleDateString(undefined, { month: "short", day: "numeric" })}</span>}
        </div>
      </header>
      <main className="main">
        <div className="map-wrap">
          <SecurityMap s={s} score={score} selected={layer} onSelect={setLayer} />
          <p className="map-caption small muted">
            {s.phase === "idle" ? "Each circle is one part of your computer and accounts." : s.phase === "scanning" ? "Each dot is a way someone could get in." : s.phase === "fixed" ? "Green means fixed." : "Each dot is a way someone could get in."}
          </p>
        </div>
        <div className="side">
          {prefs === undefined ? (
            <div className="panel skeleton" aria-busy="true" />
          ) : (
            <Panel
              s={s}
              layer={layer}
              setLayer={setLayer}
              demo={!!bridge?.demo}
              onScan={() => bridge?.scan()}
              onFix={(approve, only, keep) => (canFix ? bridge?.fix(approve, only, keep) : setUnlock({ approve, only, keep }))}
              onUndo={(t) => bridge?.undo(t)}
              onOpen={(t) => bridge?.openTarget(t)}
              getQuestions={async () => ((await bridge?.questions()) ?? []) as Question[]}
            />
          )}
          {unlock && bridge && (
            <Unlock
              bridge={bridge}
              onClose={() => setUnlock(null)}
              onUnlocked={() => {
                setCanFix(true);
                setUnlock(null);
                bridge.fix(unlock.approve, unlock.only, unlock.keep);
              }}
            />
          )}
          {s.error && <p className="error small">{s.error}</p>}
        </div>
      </main>
    </div>
  );
}

function LogoMark() {
  return (
    <svg width="22" height="22" viewBox="0 0 24 24" aria-hidden>
      <rect x="4" y="10.5" width="16" height="10.5" rx="3" fill="currentColor" />
      <path d="M8 10.5V8a4 4 0 0 1 8 0v2.5" fill="none" stroke="currentColor" strokeWidth="2.2" />
      <circle cx="12" cy="15.5" r="1.6" fill="var(--bg)" />
    </svg>
  );
}

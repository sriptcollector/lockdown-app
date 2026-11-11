// Preferences, asked once: one question at a time, recommended answer first and preselected.
import { useState } from "react";
import type { Preferences } from "./state";

type Q = {
  key: keyof Preferences | "github";
  title: string;
  hint: string;
  multi?: boolean;
  options: { value: any; label: string; detail: string }[];
};

const QUESTIONS: Q[] = [
  {
    key: "mode",
    title: "How should fixes run?",
    hint: "You can change this any time.",
    options: [
      { value: "safe-auto", label: "Fix what's safe, ask about the rest", detail: "Anything that might break something waits for your OK" },
      { value: "all-auto", label: "Fix everything", detail: "Risky fixes run too. Everything can still be undone" },
      { value: "review", label: "Show me first", detail: "Nothing changes until you press Fix on it" },
    ],
  },
  {
    key: "keep",
    title: "Which of these do you use?",
    hint: "Lockdown won't take these away. Pick all that apply, or none.",
    multi: true,
    options: [
      { value: "remote-access", label: "Getting into this computer from another device", detail: "Remote Desktop, SSH, screen sharing, Tailscale" },
      { value: "lan-dev-servers", label: "Opening my dev server on my phone", detail: "Other devices reach apps running on this computer" },
      { value: "public-repos", label: "Open-source repos", detail: "Some of my GitHub repos are public on purpose" },
      { value: "file-sharing", label: "Shared folders", detail: "Other computers open folders on this one" },
      { value: "unsigned-scripts", label: "Running scripts I download", detail: "PowerShell or shell scripts from the web" },
    ],
  },
  {
    key: "code",
    title: "How should code fixes land?",
    hint: "Fixes to your repos always go on their own branch first.",
    options: [
      { value: "pr-automerge", label: "Pull request, merged when checks pass", detail: "Stays open if anything fails" },
      { value: "pr-only", label: "Pull request, I merge it", detail: "You review every code change" },
      { value: "direct", label: "Straight to main", detail: "Fastest. Undo opens a revert" },
    ],
  },
  {
    key: "rewriteHistory",
    title: "Remove leaked keys from git history?",
    hint: "Replacing the key is what actually protects you. Cleaning history is extra.",
    options: [
      { value: false, label: "No, just help me replace the keys", detail: "Nothing about your history changes" },
      { value: true, label: "Yes, rewrite history too", detail: "Everyone with a copy has to clone again" },
    ],
  },
  {
    key: "allGithubRepos",
    title: "Which GitHub repos should it check?",
    hint: "Settings are read through GitHub. Code is only read on this computer.",
    options: [
      { value: true, label: "All of my repos", detail: "Including ones not on this computer" },
      { value: false, label: "Only repos on this computer", detail: "Fewer checks, faster" },
    ],
  },
  {
    key: "watch",
    title: "Check again every week?",
    hint: "New packages get new holes. A weekly check catches them.",
    options: [
      { value: true, label: "Yes, every Monday morning", detail: "Quietly, and only tells you if something's new" },
      { value: false, label: "No, only when I press the button", detail: "" },
    ],
  },
];

export function Onboarding({ initial, onDone }: { initial: Partial<Preferences> | null; onDone: (p: Partial<Preferences>) => void }) {
  const [i, setI] = useState(0);
  const [answers, setAnswers] = useState<Record<string, any>>(() => {
    const a: Record<string, any> = {};
    for (const q of QUESTIONS) a[q.key] = (initial as any)?.[q.key] ?? (q.multi ? [] : q.options[0].value);
    return a;
  });
  const q = QUESTIONS[i];
  const last = i === QUESTIONS.length - 1;
  const next = () => (last ? onDone(answers as Partial<Preferences>) : setI(i + 1));
  const pick = (v: any) => {
    if (q.multi) {
      const cur: any[] = answers[q.key] ?? [];
      setAnswers({ ...answers, [q.key]: cur.includes(v) ? cur.filter((x) => x !== v) : [...cur, v] });
    } else setAnswers({ ...answers, [q.key]: v });
  };

  return (
    <section
      className="onboard"
      aria-labelledby="q-title"
      onKeyDown={(e) => {
        const n = Number(e.key);
        if (n >= 1 && n <= q.options.length) pick(q.options[n - 1].value);
        if (e.key === "Enter" && (e.ctrlKey || e.metaKey || (e.target as HTMLElement).tagName !== "BUTTON")) next();
      }}
    >
      <div className="onboard-progress" aria-hidden>
        <span style={{ transform: `scaleX(${(i + 1) / QUESTIONS.length})` }} />
      </div>
      <p className="onboard-step mono">
        Setup {i + 1} of {QUESTIONS.length}
      </p>
      <h2 id="q-title">{q.title}</h2>
      <p className="hint">{q.hint}</p>
      <div className="options" role={q.multi ? "group" : "radiogroup"} aria-labelledby="q-title">
        {q.options.map((o, n) => {
          const on = q.multi ? (answers[q.key] ?? []).includes(o.value) : answers[q.key] === o.value;
          return (
            <button key={String(o.value)} className={`option ${on ? "on" : ""}`} role={q.multi ? "checkbox" : "radio"} aria-checked={on} onClick={() => pick(o.value)} autoFocus={n === 0}>
              <span className="option-key mono">{n + 1}</span>
              <span className="option-text">
                <span className="option-label">
                  {o.label}
                  {n === 0 && !q.multi && <span className="rec">Recommended</span>}
                </span>
                {o.detail && <span className="option-detail">{o.detail}</span>}
              </span>
              <span className="option-check" aria-hidden>
                {on ? <Check /> : null}
              </span>
            </button>
          );
        })}
      </div>
      <div className="onboard-actions">
        {i > 0 ? (
          <button className="btn ghost" onClick={() => setI(i - 1)}>
            Back
          </button>
        ) : (
          <span />
        )}
        <button className="btn primary" onClick={next}>
          {last ? "Save and continue" : q.multi && !(answers[q.key] ?? []).length ? "None of these" : "Next"}
        </button>
      </div>
    </section>
  );
}

export const Check = () => (
  <svg width="16" height="16" viewBox="0 0 16 16" aria-hidden>
    <path d="M3.5 8.5l3 3 6-7" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
  </svg>
);

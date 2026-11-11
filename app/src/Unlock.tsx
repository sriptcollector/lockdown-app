// Unlocking fixes, inline where you pressed Fix: email → code → plan. No passwords.
import { useEffect, useState } from "react";
import type { Bridge } from "./bridge";

type Step = "email" | "code" | "plan" | "waiting";

export function Unlock({ bridge, onUnlocked, onClose }: { bridge: Bridge; onUnlocked: () => void; onClose: () => void }) {
  const [step, setStep] = useState<Step>("email");
  const [email, setEmail] = useState("");
  const [code, setCode] = useState("");
  const [plan, setPlan] = useState<"yearly" | "monthly">("yearly");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const act = async (fn: () => Promise<void>) => {
    setBusy(true);
    setErr(null);
    try {
      await fn();
    } catch (e: any) {
      setErr(String(e?.message ?? e));
    } finally {
      setBusy(false);
    }
  };

  useEffect(() => {
    if (step !== "waiting") return;
    const t = setInterval(async () => {
      const a = await bridge.account({ action: "refresh" }).catch(() => null);
      if (a?.canFix) {
        clearInterval(t);
        onUnlocked();
      }
    }, 3000);
    return () => clearInterval(t);
  }, [step]);

  return (
    <div className="unlock" role="region" aria-label="Unlock fixing">
      <div className="unlock-head">
        {step !== "email" && (
          <button className="textlink back" onClick={() => { setErr(null); setNote(null); setStep(step === "code" ? "email" : step === "waiting" ? "plan" : "email"); }}>
            ← Back
          </button>
        )}
        <strong>{step === "plan" || step === "waiting" ? "Fix everything with Pro" : "Sign in to fix"}</strong>
        <button className="btn ghost small" onClick={onClose}>
          Not now
        </button>
      </div>
      {step === "email" && (
        <form
          className="unlock-row"
          onSubmit={(e) => {
            e.preventDefault();
            act(async () => {
              await bridge.account({ action: "start", email });
              setStep("code");
            });
          }}
        >
          <input className="input" type="email" required autoFocus placeholder="you@email.com" value={email} onChange={(e) => setEmail(e.target.value)} aria-label="Email" />
          <button className="btn primary" disabled={busy}>
            {busy ? "Sending…" : "Send code"}
          </button>
        </form>
      )}
      {step === "code" && (
        <>
          <p className="small muted">
            We sent a 6-digit code to {email}.{" "}
            {/@gmail\.com$/i.test(email) && (
              <a href="https://mail.google.com/mail/u/0/#search/Lockdown+code" target="_blank" rel="noreferrer">
                Open Gmail
              </a>
            )}
          </p>
          <form
            className="unlock-row"
            onSubmit={(e) => {
              e.preventDefault();
              act(async () => {
                const a = await bridge.account({ action: "verify", email, code });
                if (a.canFix || a.plan === "pro" || a.plan === "owner") onUnlocked();
                else setStep("plan");
              });
            }}
          >
            <input className="input mono-input" inputMode="numeric" autoComplete="one-time-code" maxLength={6} required autoFocus placeholder="123456" value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))} aria-label="Code" />
            <button className="btn primary" disabled={busy || code.length !== 6}>
              {busy ? "Checking…" : "Sign in"}
            </button>
          </form>
        </>
      )}
      {step === "plan" && (
        <>
          <div className="plans" role="radiogroup" aria-label="Plan">
            <button role="radio" aria-checked={plan === "yearly"} className={`plan ${plan === "yearly" ? "on" : ""}`} onClick={() => setPlan("yearly")}>
              <span className="plan-name">
                Yearly <span className="rec">Best value</span>
              </span>
              <span className="plan-price">
                <strong>Free</strong> for 7 days, then $96/year ($8/month)
              </span>
            </button>
            <button role="radio" aria-checked={plan === "monthly"} className={`plan ${plan === "monthly" ? "on" : ""}`} onClick={() => setPlan("monthly")}>
              <span className="plan-name">Monthly</span>
              <span className="plan-price">
                <strong>Free</strong> for 7 days, then $12/month
              </span>
            </button>
          </div>
          <p className="small muted">One-button fixes, undo for every change, and a weekly check. Cancel any time.</p>
          <button
            className="btn primary"
            disabled={busy}
            onClick={() =>
              act(async () => {
                const r = await bridge.account({ action: "checkout", plan });
                if (r.url) {
                  await bridge.open(r.url);
                  setStep("waiting");
                } else setNote(r.error ?? "Checkout didn't open. Please try again.");
              })
            }
          >
            {busy ? "Opening…" : "Start free week"}
          </button>
          {note && <p className="small">{note}</p>}
        </>
      )}
      {step === "waiting" && (
        <p className="small muted">
          <span className="spinner" aria-hidden /> Finish checkout in your browser. Fixing unlocks here as soon as it's done.
        </p>
      )}
      {err && <p className="small error-text">{err}</p>}
    </div>
  );
}

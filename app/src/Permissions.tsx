// Every system popup Lockdown can cause gets a guided step: say what will appear, show which button
// to press, notice the answer, and offer a way back in when someone presses the other button.
import { useEffect, useRef, useState } from "react";
import type { Bridge, Folder } from "./bridge";

const isMac = typeof navigator !== "undefined" && /Mac/i.test(navigator.platform || navigator.userAgent);
const FILES_AND_FOLDERS = "x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension?Privacy_FilesAndFolders";

/** macOS only: ask for each guarded folder before the first check, one popup at a time. */
export function Folders({ bridge, onDone, onBack }: { bridge: Bridge; onDone: () => void; onBack: () => void }) {
  const [folders, setFolders] = useState<Folder[]>([]);
  const [asking, setAsking] = useState<string | null>(null);
  const [started, setStarted] = useState(false);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const live = useRef(true);
  useEffect(() => {
    bridge.permissions().then((p) => setFolders(p.folders));
    return () => {
      live.current = false;
    };
  }, []);

  const refused = folders.filter((f) => f.state === "denied");
  const finished = started && !asking && folders.every((f) => f.state !== "unasked");

  // All allowed: carry straight on to the check.
  useEffect(() => {
    if (finished && !refused.length) {
      const t = setTimeout(onDone, 700);
      return () => clearTimeout(t);
    }
  }, [finished, refused.length]);

  // After "Turn it on in Settings", notice the switch flipping without a popup.
  useEffect(() => {
    if (!settingsOpen || !refused.length) return;
    const t = setInterval(async () => {
      const r = await bridge.recheckFolders().catch(() => null);
      if (r && live.current) setFolders(r.folders);
    }, 1500);
    return () => clearInterval(t);
  }, [settingsOpen, refused.length]);

  const askAll = async () => {
    setStarted(true);
    for (const f of folders.filter((x) => x.state === "unasked")) {
      if (!live.current) return;
      setAsking(f.id);
      const r = await bridge.requestFolder(f.id).catch(() => ({ id: f.id, state: "denied" as const }));
      setFolders((cur) => cur.map((x) => (x.id === r.id ? { ...x, state: r.state } : x)));
    }
    setAsking(null);
  };

  const current = folders.find((f) => f.id === asking);
  return (
    <section className="panel hero ask" aria-labelledby="ask-h">
      <button className="textlink back" onClick={onBack}>
        ← Back
      </button>
      {!finished ? (
        <>
          <h1 id="ask-h">Your Mac will ask about your folders</h1>
          <p className="lede">Lockdown looks in them for passwords and keys left lying around. Your Mac asks once for each folder. Click Allow each time.</p>
          <MacFolderPopup folder={current?.label ?? folders[0]?.label ?? "Documents"} />
        </>
      ) : refused.length ? (
        <>
          <h1 id="ask-h">{refused.length === 1 ? `Lockdown can't look in ${refused[0].label} yet` : `Lockdown can't look in ${refused.length} folders yet`}</h1>
          <p className="lede">
            That's fine. Lockdown will check everything else. To include {refused.length === 1 ? "it" : "them"}, turn {refused.length === 1 ? "it" : "them"} on in Settings.
          </p>
          {settingsOpen && <SettingsGuide folders={refused.map((f) => f.label)} />}
        </>
      ) : (
        <>
          <h1 id="ask-h">All set</h1>
          <p className="lede">Starting the check…</p>
        </>
      )}

      <ul className="folder-list" aria-live="polite">
        {folders.map((f) => (
          <li key={f.id}>
            <span>{f.label}</span>
            <span className={`folder-state ${f.state}`}>
              {asking === f.id ? (
                <>
                  <span className="spinner" aria-hidden /> Waiting for you
                </>
              ) : f.state === "allowed" ? (
                "Allowed"
              ) : f.state === "denied" ? (
                "Not allowed"
              ) : (
                "Not asked yet"
              )}
            </span>
          </li>
        ))}
      </ul>

      {!started ? (
        <button className="btn primary huge" onClick={askAll} autoFocus>
          Continue
        </button>
      ) : finished && refused.length ? (
        <div className="ask-actions">
          <button className="btn primary huge" onClick={onDone}>
            Check my computer
          </button>
          {!settingsOpen && (
            <button
              className="btn ghost"
              onClick={() => {
                bridge.openTarget(FILES_AND_FOLDERS);
                setSettingsOpen(true);
              }}
            >
              Turn it on in Settings
            </button>
          )}
        </div>
      ) : null}
    </section>
  );
}

/** Shown while the system's admin prompt is up during fixing. */
export function AdminAsk() {
  return (
    <div className="ask-card" role="status">
      <strong>{isMac ? "Your Mac is asking for your password" : "Windows is asking for your OK"}</strong>
      <p>{isMac ? "Type the password you use to unlock this Mac, then click OK." : "A box asks “Do you want to allow this app to make changes to your device?” Click Yes."}</p>
      {isMac ? <MacPasswordPopup /> : <WinUacPopup />}
    </div>
  );
}

/** After someone pressed No / Cancel on the admin prompt: nothing changed, offer to ask again. */
export function AdminRetry({ count, onRetry }: { count: number; onRetry: () => void }) {
  return (
    <div className="ask-card" role="alert">
      <strong>
        {count === 1 ? "1 fix" : `${count} fixes`} still need{count === 1 ? "s" : ""} your OK
      </strong>
      <p>{isMac ? "The password box was closed, so nothing was changed for these." : "Windows was told No, so nothing was changed for these."} Try again and {isMac ? "type your Mac password" : "click Yes"}.</p>
      <div>
        <button className="btn primary" onClick={onRetry}>
          Try again
        </button>
      </div>
    </div>
  );
}

// ---- pictures of the popups, drawn small, with the button to press marked ----

function MacFolderPopup({ folder }: { folder: string }) {
  return (
    <figure className="sysdlg mac" aria-label={`Picture of the popup: Lockdown would like to access files in your ${folder} folder. Click Allow.`}>
      <div className="sysdlg-icon" aria-hidden />
      <p className="sysdlg-title">“Lockdown” would like to access files in your {folder} folder.</p>
      <div className="sysdlg-buttons">
        <span className="sysbtn">Don't Allow</span>
        <span className="sysbtn press">Allow</span>
      </div>
      <figcaption className="press-tag">Click Allow</figcaption>
    </figure>
  );
}

function MacPasswordPopup() {
  return (
    <figure className="sysdlg mac" aria-hidden>
      <p className="sysdlg-title">Lockdown wants to make changes.</p>
      <p className="sysdlg-sub">Enter your password to allow this.</p>
      <span className="sysfield">Password</span>
      <div className="sysdlg-buttons">
        <span className="sysbtn">Cancel</span>
        <span className="sysbtn press">OK</span>
      </div>
    </figure>
  );
}

function WinUacPopup() {
  return (
    <figure className="sysdlg win" aria-hidden>
      <p className="sysdlg-head">User Account Control</p>
      <p className="sysdlg-title">Do you want to allow this app to make changes to your device?</p>
      <p className="sysdlg-sub">Lockdown · Publisher: Unknown</p>
      <div className="sysdlg-buttons">
        <span className="sysbtn press">Yes</span>
        <span className="sysbtn">No</span>
      </div>
    </figure>
  );
}

function SettingsGuide({ folders }: { folders: string[] }) {
  return (
    <figure className="sysdlg settings" aria-label={`In the Settings window that opened, find Lockdown and turn on ${folders.join(" and ")}. Lockdown notices by itself.`}>
      <p className="sysdlg-sub">Privacy &amp; Security › Files &amp; Folders</p>
      <p className="sysdlg-title">Lockdown</p>
      {folders.map((f) => (
        <div className="sysrow" key={f}>
          <span>{f} Folder</span>
          <span className="sysswitch press" />
        </div>
      ))}
      <figcaption className="press-tag">Turn {folders.length === 1 ? "this" : "these"} on. Lockdown notices by itself.</figcaption>
    </figure>
  );
}

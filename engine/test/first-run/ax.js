// macOS UI driver (JXA): find a button, switch or text by its label in the given apps' windows and
// press it, the way a person would. Used by the first-run test on a throwaway CI Mac.
//   osascript -l JavaScript ax.js click "Allow" 60 [App names...]
//   osascript -l JavaScript ax.js find  "You're safe" 600 Lockdown
function run(argv) {
  const [action, label, secs, ...apps] = argv;
  const se = Application("System Events");
  const deadline = Date.now() + (Number(secs) || 30) * 1000;
  const roles = new Set(["AXButton", "AXCheckBox", "AXSwitch", "AXStaticText", "AXHeading", "AXLink", "AXRadioButton"]);
  const names = (e) => {
    const out = [];
    for (const f of ["name", "title", "description", "value"]) {
      try {
        const v = e[f]();
        if (v) out.push(String(v));
      } catch (_) {}
    }
    return out;
  };
  while (Date.now() < deadline) {
    const procs = apps.length ? apps.map((a) => se.processes.byName(a)) : se.processes();
    for (const p of procs) {
      let wins = [];
      try {
        wins = p.windows();
      } catch (_) {
        continue;
      }
      for (const w of wins) {
        let els = [];
        try {
          els = w.entireContents();
        } catch (_) {
          continue;
        }
        for (const e of els) {
          let role = "";
          try {
            role = e.role();
          } catch (_) {
            continue;
          }
          if (!roles.has(role)) continue;
          const n = names(e);
          if (!n.some((x) => x === label || (action === "find" && x.includes(label)))) continue;
          if (action === "click") {
            try {
              e.actions.byName("AXPress").perform();
            } catch (_) {
              e.click();
            }
          }
          return `ok ${p.name()} ${role} "${n[0]}"`;
        }
      }
    }
    delay(0.5);
  }
  throw new Error(`timeout waiting for "${label}"`);
}

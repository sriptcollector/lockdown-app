# Lockdown

Lockdown checks your computer, your code, your GitHub and your cloud for the weak spots hackers use, and fixes them in one click. Every change it makes can be undone.

This repository is the desktop app: the scanning and fixing engine (`engine/`) and the Mac and Windows app (`app/`, Tauri). It is open source so you can read exactly what runs on your computer.

- Install: https://lockdown.westwardconsulting.ai/install
- Checking is free. Fixing is Lockdown Pro (7 days free, then $96 a year or $12 a month).

## What it touches

- **Scans are read-only.** Files and code stay on your computer; only your score and counts are sent if you sign in.
- **Fixes** are listed before they run, back up what they change, and can be undone from the app. Admin steps run behind one system prompt.
- **Scanners** are downloaded on first use at pinned versions and checked against SHA-256: gitleaks (MIT), OSV-Scanner (Apache-2.0), Opengrep (LGPL-2.1), Trivy (Apache-2.0).

## Build

Needs [Bun](https://bun.sh) and, for the app, Rust and the [Tauri prerequisites](https://v2.tauri.app/start/prerequisites/).

```sh
bun install
bun engine/src/cli.ts scan      # scan this computer from the command line (read-only)
bun run --cwd app dev            # run the app
```

Engine tests: `cd engine && bun test`. Fix-all and undo are tested on throwaway CI machines (`.github/workflows/vm-fix-test.yml`), never on a real computer.

## Security

Found a problem in Lockdown itself? Email hello@westwardconsulting.ai. Please don't open a public issue for security bugs.

## License

Apache-2.0. Made by Westward.

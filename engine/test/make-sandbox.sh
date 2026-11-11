#!/bin/sh
# Rebuild the sandbox: fake home with planted problems, and reset the throwaway GitHub repo.
# usage: test/make-sandbox.sh <sandboxDir> <owner/repo>
set -e
T="$1"; R="$2"
rm -rf "$T/home" "$T/appdata" "$T/data"; mkdir -p "$T/home/.ssh" "$T/home/Downloads" "$T/appdata/Microsoft/Windows/PowerShell/PSReadLine" "$T/data"
rand() { head -c 400 /dev/urandom | tr -dc 'A-Za-z0-9' | head -c "$1"; }
GH="ghp_$(rand 36)"; SK="sk_live_$(rand 30)"
printf 'git status\n$env:GITHUB_TOKEN="%s"\nnpm run dev\ncurl -H "Authorization: Bearer %s" https://api.stripe.com/v1/charges\nls\n' "$GH" "$SK" > "$T/appdata/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt"
printf 'name,url,username,password\nexample,https://example.com,me,hunter2\n' > "$T/home/Downloads/Chrome Passwords.csv"
ssh-keygen -q -t ed25519 -N "" -f "$T/home/.ssh/id_test" -C sandbox
printf 'https://sandbox-user:%s@github.com\n' "$GH" > "$T/home/.git-credentials"
MSYS_NO_PATHCONV=1 icacls "$(cygpath -w "$T/home/.ssh/id_test")" /grant "*S-1-1-0:R" >/dev/null
powershell.exe -NoProfile -Command "Remove-Item -Path 'HKCU:\Software\LockdownSandbox' -Recurse -Force -ErrorAction SilentlyContinue"
# reset the GitHub test repo
gh api -X PUT "repos/$R/actions/permissions/workflow" -f default_workflow_permissions=write -F can_approve_pull_request_reviews=false
for id in $(gh api "repos/$R/keys" -q '.[].id'); do gh api -X DELETE "repos/$R/keys/$id"; done
rm -f /tmp/deploy_test /tmp/deploy_test.pub; ssh-keygen -q -t ed25519 -N "" -f /tmp/deploy_test -C lockdown-test-deploy
gh api "repos/$R/keys" -f title="test deploy key" -f key="$(cat /tmp/deploy_test.pub)" -F read_only=false >/dev/null
for id in $(gh api "repos/$R/hooks" -q '.[].id'); do gh api -X PATCH "repos/$R/hooks/$id/config" -f insecure_ssl=1 >/dev/null; done
gh api -X DELETE "repos/$R/vulnerability-alerts" >/dev/null 2>&1 || true
for n in $(gh pr list -R "$R" --state open --json number -q '.[].number'); do gh pr close -R "$R" "$n" --delete-branch >/dev/null; done
echo sandbox-ready
# put main back to the planted seed commit (throwaway repo only)
if [ -d "$T/repo/.git" ]; then git -C "$T/repo" checkout -q main && git -C "$T/repo" reset -q --hard seed && git -C "$T/repo" push -q -f origin main; fi
for b in $(git -C "$T/repo" ls-remote --heads origin 'lockdown/*' | awk '{print $2}' | sed 's#refs/heads/##'); do git -C "$T/repo" push -q origin --delete "$b"; done
echo repo-reset

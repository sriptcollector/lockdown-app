# Windows UI driver (UI Automation): find a button by its label, optionally inside one window, and press
# it the way a person would. Used by the first-run test on a throwaway CI machine.
#   powershell -File uia.ps1 click "Check my computer" -Window Lockdown -Timeout 60
#   powershell -File uia.ps1 find "You're safe" -Window Lockdown -Timeout 900
param([string]$Action, [string]$Label, [string]$Window = "", [int]$Timeout = 60)
Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes, System.Windows.Forms
$A = [System.Windows.Automation.AutomationElement]
$T = [System.Windows.Automation.TreeScope]
$root = $A::RootElement
$deadline = (Get-Date).AddSeconds($Timeout)
while ((Get-Date) -lt $deadline) {
  $wins = $root.FindAll($T::Children, [System.Windows.Automation.Condition]::TrueCondition)
  foreach ($w in $wins) {
    if ($Window -and $w.Current.Name -notlike "*$Window*") { continue }
    $all = $w.FindAll($T::Descendants, [System.Windows.Automation.Condition]::TrueCondition)
    foreach ($e in $all) {
      $n = $e.Current.Name
      if (-not $n) { continue }
      $hit = if ($Action -eq "find") { $n -like "*$Label*" } else { $n -eq $Label }
      if (-not $hit) { continue }
      if ($Action -eq "click") {
        $p = $null
        if ($e.TryGetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern, [ref]$p)) { $p.Invoke() }
        else { $e.SetFocus(); [System.Windows.Forms.SendKeys]::SendWait(" ") }
      }
      "ok [$($w.Current.Name)] $($e.Current.ControlType.ProgrammaticName) '$n'"
      exit 0
    }
  }
  Start-Sleep -Milliseconds 500
}
"timeout waiting for '$Label'"
exit 1

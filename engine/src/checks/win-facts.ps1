# Read-only facts about this Windows PC. Never changes anything. Output: one JSON object.
$ErrorActionPreference = 'SilentlyContinue'; $ProgressPreference = 'SilentlyContinue'
$f = [ordered]@{}

function Reg($path, $name) { try { (Get-ItemProperty -Path $path -Name $name -ErrorAction Stop).$name } catch { $null } }

# --- System ---
$os = Get-CimInstance Win32_OperatingSystem
$f.os = @{ caption = $os.Caption; version = $os.Version; build = $os.BuildNumber; lastBoot = $os.LastBootUpTime.ToString('o') }
$f.ubr = Reg 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' 'UBR'
$f.displayVersion = Reg 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' 'DisplayVersion'
$hf = Get-HotFix | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1
$f.lastHotfix = if ($hf) { @{ id = $hf.HotFixID; on = ([datetime]$hf.InstalledOn).ToString('o') } } else { $null }
$f.wuPaused = Reg 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' 'PauseUpdatesExpiryTime'
$f.wuNoAuto = Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' 'NoAutoUpdate'
$f.rebootPending = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')

$mp = Get-MpComputerStatus
if ($mp) {
  $f.defender = @{
    enabled = $mp.AntivirusEnabled; realtime = $mp.RealTimeProtectionEnabled; tamper = $mp.IsTamperProtected
    sigAgeDays = $mp.AntivirusSignatureAge; behavior = $mp.BehaviorMonitorEnabled; ioav = $mp.IOAVProtectionEnabled
    lastQuickScanDays = $mp.QuickScanAge; mode = "$($mp.AMRunningMode)"
  }
  $pref = Get-MpPreference
  if ($pref) { $f.defenderPrefs = @{ pua = $pref.PUAProtection; cloud = $pref.MAPSReporting; network = $pref.EnableNetworkProtection; exclusionsPaths = @($pref.ExclusionPath).Count; exclusionsProcesses = @($pref.ExclusionProcess).Count } }
}
$av = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct
$f.antivirus = @($av | ForEach-Object { @{ name = $_.displayName; state = $_.productState } })

$f.firewall = @(Get-NetFirewallProfile | ForEach-Object { @{ name = "$($_.Name)"; enabled = [bool]($_.Enabled -eq 'True' -or $_.Enabled -eq 1); inbound = "$($_.DefaultInboundAction)" } })
$f.networkCategory = @(Get-NetConnectionProfile | ForEach-Object { @{ name = $_.Name; category = "$($_.NetworkCategory)"; iface = $_.InterfaceAlias } })

# Disk encryption without admin: Shell property 1=on, 2=off, 3=encrypting... 0/null=unsupported
try {
  $sh = New-Object -ComObject Shell.Application
  $f.bitlocker = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object {
    @{ drive = $_.DeviceID; protection = $sh.NameSpace("$($_.DeviceID)\").Self.ExtendedProperty('System.Volume.BitLockerProtection') }
  })
} catch { $f.bitlocker = @() }
$f.deviceEncryptionCapable = Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\BitLocker' 'PreventDeviceEncryption'
$f.edition = (Get-CimInstance Win32_OperatingSystem).OperatingSystemSKU

$f.uac = @{ lua = Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA'; admin = Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'ConsentPromptBehaviorAdmin'; secureDesktop = Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'PromptOnSecureDesktop' }
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$f.user = @{ name = $id.Name; isAdminGroup = [bool](($id.Groups | ForEach-Object { $_.Value }) -contains 'S-1-5-32-544'); elevated = ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }
$f.localUsers = @(Get-LocalUser | ForEach-Object { @{ name = $_.Name; enabled = $_.Enabled; pwRequired = $_.PasswordRequired; sid = "$($_.SID)" } })
$f.autoLogon = Reg 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'AutoAdminLogon'
$f.autoLogonPw = [bool](Reg 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'DefaultPassword')
$f.screenSaver = @{ active = Reg 'HKCU:\Control Panel\Desktop' 'ScreenSaveActive'; secure = Reg 'HKCU:\Control Panel\Desktop' 'ScreenSaverIsSecure'; timeout = Reg 'HKCU:\Control Panel\Desktop' 'ScreenSaveTimeOut' }
$f.inactivityLock = Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'InactivityTimeoutSecs'
$f.smartScreen = @{ explorer = Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' 'SmartScreenEnabled'; policy = Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'EnableSmartScreen'; apps = Reg 'HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost' 'EnableWebContentEvaluation' }
$f.secureBoot = try { Confirm-SecureBootUEFI -ErrorAction Stop } catch { $null }
$f.vbs = try { (Get-CimInstance -Namespace root/Microsoft/Windows/DeviceGuard -ClassName Win32_DeviceGuard).VirtualizationBasedSecurityStatus } catch { $null }
$f.memIntegrity = Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' 'Enabled'
$f.lsaPpl = Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL'
$f.execPolicy = @{ user = "$(Get-ExecutionPolicy -Scope CurrentUser)"; machine = "$(Get-ExecutionPolicy -Scope LocalMachine)" }
$f.autorun = Reg 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun'
$f.showExt = Reg 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' 'HideFileExt'

# --- Network ---
# One CIM query for names and paths (reading .Path off Get-Process opens every process and takes ~35 s).
$procById = @{}; Get-CimInstance Win32_Process -Property ProcessId, Name, ExecutablePath | ForEach-Object { $procById[[int]$_.ProcessId] = [pscustomobject]@{ ProcessName = ($_.Name -replace '\.exe$', ''); Path = $_.ExecutablePath } }
# netstat is far faster than Get-NetTCPConnection
$ns = netstat -ano -p TCP; $ns6 = netstat -ano -p TCPv6
$f.listening = @(); $f.established = @()
foreach ($line in @($ns) + @($ns6)) {
  if ($line -match '^\s*TCP\s+(\S+):(\d+)\s+(\S+):(\d+)\s+(\S+)\s+(\d+)') {
    $la = $Matches[1].Trim('[',']'); $lp = [int]$Matches[2]; $ra = $Matches[3].Trim('[',']'); $st = $Matches[5]; $procId = [int]$Matches[6]
    if ($st -eq 'LISTENING') { $p = $procById[$procId]; $f.listening += @{ addr = $la; port = $lp; pid = $procId; proc = $p.ProcessName; path = $p.Path } }
    elseif ($st -eq 'ESTABLISHED' -and $ra -notmatch '^(127\.|::1$|0\.0\.0\.0)') { $f.established += @{ lport = $lp; remote = $ra; pid = $procId } }
  }
}
# Enabled inbound "allow" firewall rules (netsh is fast; Get-NetFirewallRule is not)
$f.fwAllow = @(); $f.fwBlock = @(); $cur = @{}
foreach ($line in (netsh advfirewall firewall show rule name=all dir=in verbose)) {
  if ($line -match '^Rule Name:\s*(.*)$') { if ($cur.name -and $cur.enabled -eq 'Yes') { if ($cur.action -eq 'Allow') { $f.fwAllow += $cur } elseif ($cur.action -eq 'Block') { $f.fwBlock += $cur } }; $cur = @{ name = $Matches[1].Trim() } }
  elseif ($line -match '^(Enabled|Profiles|Protocol|LocalPort|Program|Action|RemoteIP):\s*(.*)$') { $cur[$Matches[1].ToLower()] = $Matches[2].Trim() }
}
if ($cur.name -and $cur.enabled -eq 'Yes') { if ($cur.action -eq 'Allow') { $f.fwAllow += $cur } elseif ($cur.action -eq 'Block') { $f.fwBlock += $cur } }
$f.rdp = @{ deny = Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections'; nla = Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication' }
$f.rdpSessions = @(Get-CimInstance Win32_LogonSession -Filter 'LogonType=10').Count
$f.smb1 = try { (Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol } catch { $null }
$f.shares = @(Get-SmbShare | Where-Object { $_.Name -notmatch '^\w\$$|^ADMIN\$$|^IPC\$$|^print\$$' } | ForEach-Object { @{ name = $_.Name; path = $_.Path } })
$f.sshd = @(Get-Service sshd, TermService, RemoteRegistry, WinRM, TlntSvr, SNMP, ftpsvc | ForEach-Object { @{ name = $_.Name; status = "$($_.Status)"; start = "$($_.StartType)" } })
$f.wifi = @(netsh wlan show profiles 2>$null | Select-String 'All User Profile\s*:\s*(.+)$' | ForEach-Object { $_.Matches[0].Groups[1].Value.Trim() })
$f.openWifi = @($f.wifi | Where-Object { (netsh wlan show profile name="$_" 2>$null | Select-String 'Authentication\s*:\s*Open') } )
$f.hostsLines = @(Get-Content "$env:SystemRoot\System32\drivers\etc\hosts" | Where-Object { $_ -match '^\s*[0-9a-f:.]+\s+\S' -and $_ -notmatch '^\s*#' } | ForEach-Object { $_.Trim() })
$f.dns = @(Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.ServerAddresses } | ForEach-Object { @{ iface = $_.InterfaceAlias; servers = @($_.ServerAddresses) } })
$f.proxy = @{ enabled = Reg 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' 'ProxyEnable'; server = Reg 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' 'ProxyServer'; pac = Reg 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' 'AutoConfigURL' }

# --- Apps ---
$uninst = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
$f.apps = @(Get-ItemProperty $uninst | Where-Object { $_.DisplayName } | ForEach-Object { @{ name = $_.DisplayName; version = "$($_.DisplayVersion)"; publisher = "$($_.Publisher)" } })
$runKeys = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
$f.startup = @()
foreach ($k in $runKeys) {
  $item = Get-ItemProperty $k
  if ($item) { $item.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object { $f.startup += @{ key = $k; name = $_.Name; cmd = "$($_.Value)" } } }
}
foreach ($d in "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup", "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup") {
  Get-ChildItem $d -File | Where-Object { $_.Name -ne 'desktop.ini' } | ForEach-Object { $f.startup += @{ key = 'folder'; name = $_.Name; cmd = $_.FullName } }
}
# Signature of each startup target (unsigned startup programs are a classic persistence trick)
foreach ($s in $f.startup) {
  $exe = if ($s.cmd -match '^"([^"]+)"') { $Matches[1] } elseif ($s.cmd -match '^(\S+\.(exe|bat|cmd|ps1|vbs|js|lnk))') { $Matches[1] } else { $null }
  $s.exe = $exe
  if ($exe -and (Test-Path $exe)) { $sig = Get-AuthenticodeSignature $exe; $s.signed = "$($sig.Status)"; $s.signer = $sig.SignerCertificate.Subject }
}
$f.tasks = @(Get-ScheduledTask | Where-Object { $_.TaskPath -notmatch '^\\Microsoft\\' -and $_.State -ne 'Disabled' } | ForEach-Object {
  $a = $_.Actions | Select-Object -First 1
  @{ name = $_.TaskName; path = $_.TaskPath; exe = "$($a.Execute)"; args = "$($a.Arguments)"; user = "$($_.Principal.UserId)"; runLevel = "$($_.Principal.RunLevel)" }
})
$f.processes = @($procById.Values | Where-Object { $_.Path } | Select-Object -Unique ProcessName, Path | ForEach-Object { @{ name = $_.ProcessName; path = $_.Path } })

$f | ConvertTo-Json -Depth 6 -Compress

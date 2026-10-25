# Throwaway probe: installs NPS on the CI runner, builds a bypass setup like a real RD Gateway one,
# exports the XML and checks how User-Name regex matching behaves.
$ErrorActionPreference = 'Continue'
$out = Join-Path $PWD 'probe'
New-Item -ItemType Directory -Force $out | Out-Null
function N ([string]$cmd) { Write-Host "> netsh nps $cmd"; $r = cmd /c "netsh nps $cmd" 2>&1; $r | Write-Host; $r }

Install-WindowsFeature NPAS -IncludeManagementTools | Format-List | Out-String | Write-Host
(Get-CimInstance Win32_OperatingSystem).Caption | Write-Host
auditpol /set /subcategory:"Network Policy Server" /success:enable /failure:enable

N 'show crpconditionattributes' | Out-File "$out/crpcond.txt"
N 'show crpprofileattributes' | Out-File "$out/crpprof.txt"
N 'show npprofileattributes' | Out-File "$out/npprof.txt"
N 'show npconditionattributes' | Out-File "$out/npcond.txt"
Export-NpsConfiguration -Path "$out/default.xml"

net user alice 'Pa55word!Test1' /add
$ip = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } | Select-Object -First 1).IPAddress
Write-Host "IP $ip"
N 'add client name=local address=127.0.0.1 sharedsecret=TestSecret123 state=enable'
N "add client name=self address=$ip sharedsecret=TestSecret123 state=enable"
$h = $env:COMPUTERNAME
N "add crp name=Bypass_2 state=enable processingorder=1 policysource=1 conditionid=0x1 conditiondata=`"^((${h}\\)?(alice|carol)|alice@test\.local)$`" profileid=0x1025 profiledata=0x1"
N "add crp name=`"TS GATEWAY AUTHORIZATION POLICY`" state=enable processingorder=2 policysource=1 conditionid=0x1006 conditiondata=`"0 00:00-24:00; 1 00:00-24:00; 2 00:00-24:00; 3 00:00-24:00; 4 00:00-24:00; 5 00:00-24:00; 6 00:00-24:00`" profileid=0x1025 profiledata=0x0"
N 'add np name=AllowAll state=enable processingorder=1 policysource=0 conditionid=0x1006 conditiondata="0 00:00-24:00; 1 00:00-24:00; 2 00:00-24:00; 3 00:00-24:00; 4 00:00-24:00; 5 00:00-24:00; 6 00:00-24:00" profileid=0x100f profiledata=TRUE profileid=0x1009 profiledata=0x1'
N 'show crp' | Out-File "$out/showcrp.txt"
N 'show np' | Out-File "$out/shownp.txt"
Export-NpsConfiguration -Path "$out/setup.xml"
Restart-Service IAS
Start-Sleep 5
netstat -ano -p udp | Select-String '1812|1645' | Out-String | Write-Host

Import-Module (Join-Path $PSScriptRoot 'Radius.psm1') -Force
$names = @('alice', 'ALICE', "$h\alice", "$($h.ToLower())\Alice", 'alice@test.local', 'ALICE@TEST.LOCAL', 'alicex', 'xalice', 'bob', "$h\carol", 'alice@test.localx')
$rows = foreach ($n in $names)
{
    $since = Get-Date
    $code = Send-RadiusPap -UserName $n -Password 'Pa55word!Test1' -Server $ip -Gateway
    Start-Sleep -Milliseconds 800
    $ev = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 6272, 6273, 6274; StartTime = $since.AddSeconds(-1) } -ErrorAction SilentlyContinue | Select-Object -First 1
    $crp = $null; $np = $null; $reason = $null
    if ($ev) { $x = [xml]$ev.ToXml(); $d = @{}; foreach ($e in $x.Event.EventData.Data) { $d[$e.Name] = $e.'#text' }; $crp = $d.ProxyPolicyName; $np = $d.NetworkPolicyName; $reason = $d.Reason }
    [pscustomobject]@{ User = $n; Reply = $code; Event = $ev.Id; Crp = $crp; Np = $np; Reason = $reason }
}
$rows | Format-Table -AutoSize | Out-String -Width 300 | Tee-Object "$out/matching.txt" | Write-Host
Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 6272, 6273, 6274 } -MaxEvents 1 -ErrorAction SilentlyContinue | ForEach-Object { $_.ToXml() } | Out-File "$out/event-sample.xml"

Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'NPS', 'IAS' } -MaxEvents 20 -ErrorAction SilentlyContinue | Format-List TimeCreated, Id, Message | Out-String -Width 300 | Tee-Object "$out/system-nps.txt" | Write-Host
# Import/export round trip
Import-NpsConfiguration -Path "$out/setup.xml"
Export-NpsConfiguration -Path "$out/roundtrip-out.xml"

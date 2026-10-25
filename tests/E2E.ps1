<#
.SYNOPSIS
    End-to-end test on a Windows Server with admin rights (used by CI):
    install NPS, build an RD Gateway style bypass setup, sync with NpsBypassSync.exe and check with real
    RADIUS requests who skips MFA. Users come from a JSON file because CI has no domain.

    How a request is judged: bypass policies authenticate locally, so a wrong password gives Access-Reject.
    The "TS GATEWAY AUTHORIZATION POLICY" stand-in accepts without checking (in real life it forwards to the
    NPS with the MFA extension). Reject = bypass policy matched, Accept = went on to MFA.
#>
param
(
    [Parameter(Mandatory)][string]$Exe,
    [string]$WorkDir = 'C:\e2e'
)

$ErrorActionPreference = 'Stop'
$shots = Join-Path $WorkDir 'shots'
$usersFile = Join-Path $WorkDir 'users.json'
$data = Join-Path $env:ProgramData 'NpsBypassSync'
New-Item -ItemType Directory -Force -Path $WorkDir, $shots | Out-Null
Import-Module (Join-Path $PSScriptRoot 'Radius.psm1') -Force

function Step($t) { Write-Host "`n=== $t" -ForegroundColor Cyan }
function Assert($cond, $msg) { if (-not $cond) { throw "ASSERT FAILED: $msg" } ; Write-Host "  ok: $msg" -ForegroundColor Green }
function N ([string]$cmd) { $r = cmd /c "netsh nps $cmd" 2>&1; if ("$r" -notmatch 'Ok\.') { throw "netsh nps $cmd failed: $r" } }
function Invoke-Tool
{
    param ([string[]]$Arguments)
    $p = Start-Process -FilePath $Exe -ArgumentList $Arguments -Wait -PassThru
    Get-Content (Join-Path $env:TEMP 'NpsBypassSync\launcher.log') -Tail 15 -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "    | $_" }
    return $p.ExitCode
}
function Get-Crps
{
    $f = Join-Path $WorkDir 'check.xml'
    Export-NpsConfiguration -Path $f
    $x = [xml](Get-Content -LiteralPath $f -Raw)
    $nodes = $x.SelectNodes('/Root/Children/Microsoft_Internet_Authentication_Service/Children/Proxy_Policies/Children/*')
    $list = foreach ($n in $nodes)
    {
        $un = @($n.SelectNodes('Properties/msNPConstraint') | Where-Object { $_.InnerText -like 'MATCH("User-Name=*' } | ForEach-Object { $_.InnerText -replace '^MATCH\("User-Name=(.*)"\)$', '$1' })
        $en = $n.SelectSingleNode('Properties/Policy_Enabled')
        [pscustomobject]@{ Name = $n.GetAttribute('name'); Seq = [int]$n.SelectSingleNode('Properties/msNPSequence').InnerText; Pattern = "$($un | Select-Object -First 1)"; Enabled = (-not $en) -or $en.InnerText -eq '1' }
    }
    $secret = $x.SelectSingleNode("//Clients/Children/*[@name='gateway']/Properties/Shared_Secret").InnerText
    return [pscustomobject]@{ Crps = @($list | Sort-Object Seq); Secret = $secret }
}
function Test-Bypass ([string]$User)
{
    # 3 = Access-Reject from local auth (bypass policy), 2 = Access-Accept from the gateway stand-in (MFA path).
    $code = Send-RadiusPap -UserName $User -Password 'wrong-password' -Server $ip -Secret 'GwSecret!42' -Gateway -TimeoutMs 10000
    if ($null -eq $code) { throw "No RADIUS answer for $User" }
    return $code -eq 3
}
function Write-Users ($Users) { $Users | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath $usersFile -Encoding UTF8 }
function Write-Config ($Values)
{
    $cfg = [ordered]@{ BypassGroups = @('MFA-Bypass'); RequireGroups = @('RDS-Users'); PolicyPrefix = 'Bypass_'; FirstNumber = 2; MaxUsers = 100; MaxLength = 250 }
    foreach ($k in $Values.Keys) { $cfg[$k] = $Values[$k] }
    New-Item -ItemType Directory -Force -Path $data | Out-Null
    $cfg | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $data 'config.json') -Encoding UTF8
}

# Users live in the local machine's name, so local auth answers fast (an unknown domain makes NPS wait).
$nb = $env:COMPUTERNAME

Step 'Install NPS'
Install-WindowsFeature NPAS -IncludeManagementTools | Out-Null
$ip = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } | Select-Object -First 1).IPAddress
N "add client name=gateway address=$ip sharedsecret=GwSecret!42 state=enable"
$allDays = '0 00:00-24:00; 1 00:00-24:00; 2 00:00-24:00; 3 00:00-24:00; 4 00:00-24:00; 5 00:00-24:00; 6 00:00-24:00'
N "add crp name=Bypass_Admins_Local state=enable processingorder=1 policysource=1 conditionid=0x1 conditiondata=`"^$nb\\admin1$`" profileid=0x1025 profiledata=0x1"
N "add crp name=Bypass_2 state=enable processingorder=2 policysource=1 conditionid=0x1 conditiondata=`"^$nb\\olduser$|^$nb\\user1$`" profileid=0x1025 profiledata=0x1"
N "add crp name=Bypass_3 state=enable processingorder=3 policysource=1 conditionid=0x1 conditiondata=`"^$nb\\olduser2$`" profileid=0x1025 profiledata=0x1"
N "add crp name=`"TS GATEWAY AUTHORIZATION POLICY`" state=enable processingorder=4 policysource=1 conditionid=0x1006 conditiondata=`"$allDays`" profileid=0x1025 profiledata=0x0"
N "add np name=AllowAll state=enable processingorder=1 policysource=0 conditionid=0x1006 conditiondata=`"$allDays`" profileid=0x100f profiledata=TRUE profileid=0x1009 profiledata=0x1"
Restart-Service IAS
Start-Sleep -Seconds 3
Assert (Test-Bypass "$($nb)\olduser") 'before: olduser bypasses (manual policy)'
Assert (-not (Test-Bypass "$($nb)\user5")) 'before: user5 goes to MFA'

$users = @()
$users += 1..40 | ForEach-Object { [ordered]@{ Sam = "user$_"; Upn = "first.last$_@contoso.com"; DisplayName = "Test User $_"; NetBios = $nb; Groups = @('MFA-Bypass', 'RDS-Users') } }
$users += [ordered]@{ Sam = 'nords'; Upn = 'nords@contoso.com'; DisplayName = 'No RDS'; NetBios = $nb; Groups = @('MFA-Bypass') }
$users += [ordered]@{ Sam = 'gone'; Upn = 'gone@contoso.com'; DisplayName = 'Disabled'; NetBios = $nb; Groups = @('MFA-Bypass', 'RDS-Users'); Disabled = $true }
Write-Users $users
Write-Config @{}

Step 'Preview changes nothing'
$before = Get-Crps
Assert ((Invoke-Tool '-Preview', '-TestUsersFile', $usersFile) -eq 0) 'preview exit code 0'
Assert (((Get-Crps).Crps | ForEach-Object Pattern) -join '|' -eq (($before.Crps | ForEach-Object Pattern) -join '|')) 'NPS unchanged after preview'

Step 'First sync'
Assert ((Invoke-Tool '-Sync', '-TestUsersFile', $usersFile) -eq 0) 'sync exit code 0'
$after = Get-Crps
$managed = @($after.Crps | Where-Object { $_.Name -match '^Bypass_\d+$' })
Write-Host ($after.Crps | Format-Table Seq, Name, Enabled, @{ n = 'Len'; e = { $_.Pattern.Length } } | Out-String)
Assert ($managed.Count -ge 3) "$($managed.Count) managed policies"
Assert (-not @($managed | Where-Object { $_.Pattern.Length -gt 250 }).Count) 'all patterns at most 250 characters'
Assert ($after.Crps[0].Name -eq 'Bypass_Admins_Local' -and $after.Crps[0].Pattern -eq "^$nb\\admin1$") 'Bypass_Admins_Local untouched and first'
Assert ((@($after.Crps | ForEach-Object Name) -join ',') -eq ((@('Bypass_Admins_Local') + @($managed | ForEach-Object Name) + @('TS GATEWAY AUTHORIZATION POLICY', 'Use Windows authentication for all users')) -join ',')) 'order: admins, bypass block, gateway, default'
Assert ((@($managed | ForEach-Object Name) -join ',') -eq ((2..($managed.Count + 1) | ForEach-Object { "Bypass_$_" }) -join ',')) 'names Bypass_2..N in a row'
Assert ($after.Secret -eq 'GwSecret!42') 'RADIUS client secret kept'
Assert (@(Get-ChildItem (Join-Path $data 'backups') -Filter 'nps-*.xml').Count -eq 1) 'one backup made'
Assert ((Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'NPS Bypass Sync'; Id = 1001 } -MaxEvents 1)) 'event 1001 written'
$acl = (Get-Acl $data).Access | ForEach-Object { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } | Sort-Object -Unique
Assert ((($acl) -join ',') -eq 'S-1-5-18,S-1-5-32-544') "data folder only SYSTEM + Administrators ($($acl -join ','))"

Step 'RADIUS: who skips MFA'
foreach ($n in "$($nb)\user1", "$($nb.ToLower())\USER17", 'user23', 'first.last40@contoso.com', 'FIRST.LAST2@CONTOSO.COM', "$($nb)\admin1") { Assert (Test-Bypass $n) "bypass: $n" }
foreach ($n in "$($nb)\olduser", "$($nb)\olduser2", "$($nb)\user41", "$($nb)\user1x", 'xuser1', 'OTHER\user1', 'first.last1@contoso.comx', 'user1@contoso.com', "$($nb)\nords", "$($nb)\gone", "$($nb)\first.last1") { Assert (-not (Test-Bypass $n)) "MFA: $n" }

Step 'Second sync changes nothing'
Assert ((Invoke-Tool '-Sync', '-TestUsersFile', $usersFile) -eq 0) 'sync exit code 0'
Assert (@(Get-ChildItem (Join-Path $data 'backups') -Filter 'nps-*.xml').Count -eq 1) 'no new backup'

Step 'Fewer users'
foreach ($u in $users[0..34]) { $u.Groups = @('RDS-Users') }
Write-Users $users
Assert ((Invoke-Tool '-Sync', '-TestUsersFile', $usersFile) -eq 0) 'sync exit code 0'
$small = @((Get-Crps).Crps | Where-Object { $_.Name -match '^Bypass_\d+$' })
Assert ($small.Count -eq 1 -and $small[0].Name -eq 'Bypass_2') 'shrunk to Bypass_2 only'
Assert (Test-Bypass "$($nb)\user36") 'bypass: user36'
Assert (-not (Test-Bypass "$($nb)\user1")) 'MFA: removed user1'
$state = Get-Content (Join-Path $data 'state.json') -Raw | ConvertFrom-Json
Assert (@($state.Users).Count -eq 5) 'state has 5 users'

Step 'Safety limit'
foreach ($u in $users) { $u.Groups = @('MFA-Bypass', 'RDS-Users') }
Write-Users $users
Write-Config @{ MaxUsers = 10 }
$snap = (Get-Crps).Crps | ForEach-Object { "$($_.Name)=$($_.Pattern)" }
Assert ((Invoke-Tool '-Sync', '-TestUsersFile', $usersFile) -ne 0) 'sync refuses (exit code not 0)'
Assert ((((Get-Crps).Crps | ForEach-Object { "$($_.Name)=$($_.Pattern)" }) -join "`n") -eq ($snap -join "`n")) 'NPS unchanged'
Assert ((Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'NPS Bypass Sync'; Id = 1003 } -MaxEvents 1)) 'event 1003 written'

Step 'Nobody in the group'
Write-Config @{}
foreach ($u in $users) { $u.Groups = @('RDS-Users') }
Write-Users $users
Assert ((Invoke-Tool '-Sync', '-TestUsersFile', $usersFile) -eq 0) 'sync exit code 0'
$empty = @((Get-Crps).Crps | Where-Object { $_.Name -match '^Bypass_\d+$' })
Assert ($empty.Count -eq 1 -and -not $empty[0].Enabled) 'one disabled placeholder policy'
Assert (-not (Test-Bypass "$($nb)\user36")) 'MFA: user36'
Assert (Test-Bypass "$($nb)\admin1") 'bypass: admin1 (own policy)'

Step 'Back to 40 users, different name formats'
foreach ($u in $users) { $u.Groups = @('MFA-Bypass', 'RDS-Users') }
Write-Users $users
Write-Config @{ MatchSam = $false; MatchUpn = $false }
Assert ((Invoke-Tool '-Sync', '-TestUsersFile', $usersFile) -eq 0) 'sync exit code 0'
Assert (Test-Bypass "$($nb)\user9") 'bypass: DOMAIN\user9'
Assert (-not (Test-Bypass 'user9')) 'MFA: user9 without domain'
Assert (-not (Test-Bypass 'first.last9@contoso.com')) 'MFA: UPN when UPN is off'
Write-Config @{}
Assert ((Invoke-Tool '-Sync', '-TestUsersFile', $usersFile) -eq 0) 'sync exit code 0'

Step 'Automatic sync task'
Assert ((Invoke-Tool '-EnableAutoSync', '-IntervalMinutes', '10') -eq 0) 'enable exit code 0'
$task = Get-ScheduledTask -TaskName 'NPS Bypass Sync'
Assert ($task.Principal.UserId -eq 'SYSTEM') 'task runs as SYSTEM'
Assert ($task.Triggers[0].Repetition.Interval -eq 'PT10M') "every 10 minutes ($($task.Triggers[0].Repetition.Interval))"
Assert (Test-Path "$env:ProgramFiles\NPS Bypass Sync\NpsBypassSync.exe") 'exe copied to Program Files'
$snap = (Get-Crps).Crps | ForEach-Object { "$($_.Name)=$($_.Pattern)" }
$started = Get-Date
Start-ScheduledTask -TaskName 'NPS Bypass Sync'
do { Start-Sleep -Seconds 3; $info = Get-ScheduledTaskInfo -TaskName 'NPS Bypass Sync' } while (((Get-ScheduledTask -TaskName 'NPS Bypass Sync').State -eq 'Running' -or $info.LastRunTime -lt $started.AddSeconds(-5)) -and (Get-Date) -lt $started.AddMinutes(5))
$state = Get-Content (Join-Path $data 'state.json') -Raw | ConvertFrom-Json
Write-Host "    task result $($info.LastTaskResult), state: $($state.LastResult)"
# No domain on CI: the SYSTEM run must fail cleanly and leave NPS alone.
Assert ([datetime]$state.LastSync -ge $started.AddSeconds(-5)) 'task ran and wrote its state'
Assert ($state.LastResult -like 'Failed:*Active Directory*' -or $state.LastResult -like 'Failed:*domain*') "fails closed without AD ($($state.LastResult))"
Assert ((((Get-Crps).Crps | ForEach-Object { "$($_.Name)=$($_.Pattern)" }) -join "`n") -eq ($snap -join "`n")) 'NPS unchanged'
Assert ((Invoke-Tool '-DisableAutoSync') -eq 0) 'disable exit code 0'
Assert (-not (Get-ScheduledTask -TaskName 'NPS Bypass Sync' -ErrorAction SilentlyContinue)) 'task removed'
Assert (-not (Test-Path "$env:ProgramFiles\NPS Bypass Sync\NpsBypassSync.exe")) 'copy removed'

Step 'Window'
Write-Config @{ BypassGroups = @('MFA-Bypass'); RequireGroups = @('RDS-Users') }
foreach ($u in $users[0..2]) { $u.Groups = @('RDS-Users') }
$users += [ordered]@{ Sam = 'newbie'; Upn = 'new.bie@contoso.com'; DisplayName = 'New Person'; NetBios = $nb; Groups = @('MFA-Bypass', 'RDS-Users') }
Write-Users $users
[void](Invoke-Tool '-Screenshot', (Join-Path $shots 'main'), '-TestUsersFile', $usersFile)
Assert (Test-Path (Join-Path $shots 'main-ready.png')) 'screenshot saved'

Write-Host "`nAll end-to-end checks passed." -ForegroundColor Green

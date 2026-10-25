# Probe: how does NPS match User-Name patterns (case, alternation order)?
$ErrorActionPreference = 'Stop'
Install-WindowsFeature NPAS -IncludeManagementTools | Out-Null
Import-Module (Join-Path $PSScriptRoot 'Radius.psm1') -Force
$ip = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } | Select-Object -First 1).IPAddress
$nb = $env:COMPUTERNAME
function N ([string]$cmd) { $r = cmd /c "netsh nps $cmd" 2>&1; if ("$r" -notmatch 'Ok\.') { throw "netsh nps $cmd failed: $r" } }
$allDays = '0 00:00-24:00; 1 00:00-24:00; 2 00:00-24:00; 3 00:00-24:00; 4 00:00-24:00; 5 00:00-24:00; 6 00:00-24:00'
N "add client name=gw address=$ip sharedsecret=GwSecret!42 state=enable"
N "add crp name=P state=enable processingorder=1 policysource=1 conditionid=0x1 conditiondata=`"^x$`" profileid=0x1025 profiledata=0x1"
N "add crp name=GW state=enable processingorder=2 policysource=1 conditionid=0x1006 conditiondata=`"$allDays`" profileid=0x1025 profiledata=0x0"
N "add np name=AllowAll state=enable processingorder=1 policysource=0 conditionid=0x1006 conditiondata=`"$allDays`" profileid=0x100f profiledata=TRUE profileid=0x1009 profiledata=0x1"
Restart-Service IAS; Start-Sleep 3
$patterns = [ordered]@{
    V1_current   = "^(($nb\\)?(user1|user10|user17)|(first\.last1)@contoso\.com)$"
    V2_longfirst = "^(($nb\\)?(user17|user10|user1)|(first\.last1)@contoso\.com)$"
    V3_simple    = "^$nb\\user17$"
    V4_lowerdom  = "^$($nb.ToLower())\\user17$"
    V5_upperall  = "^$($nb.ToUpper())\\USER17$"
    V6_flat      = "^$nb\\user1$|^$nb\\user10$|^$nb\\user17$"
    V7_nogroup   = "^($nb\\)?(user1|user17)$"
    V8_samegroup = "^(user1|user17)$"
    V9_samelen   = "^(user18|user17)$"
    V10_ignore   = "(?i)^user17$"
}
$inputs = "$nb\user17", "$($nb.ToLower())\user17", "$($nb.ToUpper())\user17", "$nb\USER17", "user17", "USER17", "$nb\user1", "$nb\user10", "user1", "first.last1@contoso.com"
$rows = foreach ($k in $patterns.Keys)
{
    try { N "set crp name=P conditionid=0x1 conditiondata=`"$($patterns[$k])`" profileid=0x1025 profiledata=0x1" } catch { [pscustomobject]@{ Pattern = $k; Input = 'SET FAILED'; Result = "$_" }; continue }
    Start-Sleep 2
    foreach ($i in $inputs)
    {
        $c = Send-RadiusPap -UserName $i -Password 'wrong' -Server $ip -Secret 'GwSecret!42' -Gateway -TimeoutMs 10000
        [pscustomobject]@{ Pattern = $k; Input = $i; Result = switch ($c) { 3 { 'MATCH' } 2 { 'no' } default { "?$c" } } }
    }
}
"COMPUTERNAME=$nb"
$rows | Format-Table -AutoSize | Out-String -Width 200

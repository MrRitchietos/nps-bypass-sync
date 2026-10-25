# Logic tests without NPS or AD (runs on any OS with PowerShell 7 or Windows PowerShell 5.1).
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'Start-NpsBypassSync.ps1'), [ref]$tokens, [ref]$errors)
if ($errors) { throw "Parse errors: $($errors | Out-String)" }
$assign = $ast.FindAll({ param ($n) $n -is [Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -eq '$WorkerCode' }, $true) | Select-Object -First 1
$work = Join-Path ([IO.Path]::GetTempPath()) ("nbs-unit-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $work | Out-Null
$Ctx = @{ DataDir = $work; StateFile = Join-Path $work 'state.json'; ConfigFile = Join-Path $work 'config.json'; TestUsersFile = Join-Path $work 'users.json'; LogFile = $null }
$Shared = $null
. ([scriptblock]::Create($assign.Right.Extent.Text.Trim().TrimStart('{').TrimEnd('}')))
function Write-Host { }

$script:fails = 0
function Check($cond, $msg) { if ($cond) { Microsoft.PowerShell.Utility\Write-Host "  ok: $msg" -ForegroundColor Green } else { Microsoft.PowerShell.Utility\Write-Host "  FAIL: $msg" -ForegroundColor Red; $script:fails++ } }

$cfg = Get-DefaultConfig
$cfg.BypassGroups = @('MFA-Bypass')
$u = @(
    [pscustomobject]@{ Sam = 'jdoe'; Upn = 'john.doe@contoso.com'; NetBios = 'CONTOSO' }
    [pscustomobject]@{ Sam = 'a.smith'; Upn = 'anna.smith@Contoso.com'; NetBios = 'CONTOSO' }
    [pscustomobject]@{ Sam = 'ext(1)'; Upn = 'ext1@partner.be'; NetBios = 'CONTOSO' }
)
$p = New-UserNamePattern -Users $u -Config $cfg
Microsoft.PowerShell.Utility\Write-Host $p
Check ($p -eq '^((CONTOSO\\)?(jdoe|a\.smith|ext\(1\))|(john\.doe|anna\.smith)@contoso\.com|(ext1)@partner\.be)$') 'pattern shape'
foreach ($ok in 'jdoe', 'CONTOSO\jdoe', 'contoso\JDOE', 'john.doe@contoso.com', 'a.smith', 'ext(1)', 'ext1@partner.be', 'ANNA.SMITH@CONTOSO.COM') { Check (Test-PatternMatch $p $ok) "matches $ok" }
foreach ($no in 'jdoex', 'xjdoe', 'OTHER\jdoe', 'aXsmith', 'john.doe@contoso.comx', 'johnXdoe@contoso.com', 'ext1', 'jdoe@contoso.com', 'CONTOSO\john.doe', '') { Check (-not (Test-PatternMatch $p $no)) "no match $no" }

$cfg2 = Get-DefaultConfig; $cfg2.MatchSam = $false; $cfg2.MatchUpn = $false
Check ((New-UserNamePattern -Users $u[0] -Config $cfg2) -eq '^(CONTOSO\\(jdoe))$') 'domain only'
$cfg3 = Get-DefaultConfig; $cfg3.MatchDomainSam = $false; $cfg3.MatchUpn = $false
Check ((New-UserNamePattern -Users $u[0] -Config $cfg3) -eq '^((jdoe))$') 'sam only'

# Split
$many = 1..120 | ForEach-Object { [pscustomobject]@{ Sam = "user$_"; Upn = "first.last$_@contoso.com"; NetBios = 'CONTOSO' } }
$buckets = Split-UsersToPolicies -Users $many -Config $cfg
Check ($buckets.Count -gt 1) "split into $($buckets.Count) policies"
Check (@($buckets | ForEach-Object { $_.Count } | Measure-Object -Sum).Sum -eq 120) 'all users placed'
Check (-not @($buckets | Where-Object { (New-UserNamePattern -Users $_ -Config $cfg).Length -gt 250 }).Count) 'all under 250'

# Plan against a real NPS export
$users = @()
$users += 1..30 | ForEach-Object { @{ Sam = "user$_"; Upn = "user.$_@contoso.com"; NetBios = 'CONTOSO'; Groups = @('MFA-Bypass', 'RDS-Users') } }
$users += @{ Sam = 'ann'; Upn = 'ann@contoso.com'; NetBios = 'CONTOSO'; Groups = @('MFA-Bypass', 'RDS-Users') }
$users += @{ Sam = 'xann'; Upn = 'xann@contoso.com'; NetBios = 'CONTOSO'; Groups = @('MFA-Bypass', 'RDS-Users') }
$users += @{ Sam = 'nords'; Upn = 'nords@contoso.com'; NetBios = 'CONTOSO'; Groups = @('MFA-Bypass') }
$users += @{ Sam = 'off'; Upn = 'off@contoso.com'; NetBios = 'CONTOSO'; Groups = @('MFA-Bypass', 'RDS-Users'); Disabled = $true }
$users | ConvertTo-Json -Depth 3 | Set-Content -Path $Ctx.TestUsersFile
$cfg.RequireGroups = @('RDS-Users')
$doc = New-Object Xml.XmlDocument; $doc.PreserveWhitespace = $true; $doc.Load((Join-Path $PSScriptRoot 'fixtures/nps-sample.xml'))
$plan = Get-SyncPlan -Config $cfg -Doc $doc
Check ($plan.Count -eq 32) "32 users included ($($plan.Count))"
Check (@($plan.Users | Where-Object Status -eq 'Skipped').Count -eq 2) 'two skipped (no RDS, disabled)'
Check ($plan.Desired[0].Name -eq 'Bypass_2') 'first policy Bypass_2'
Check ($plan.Desired.Count -ge 2) "$($plan.Desired.Count) policies"
Check ($plan.Order[0] -eq 'Bypass_2' -and $plan.Order[-2] -eq 'TS GATEWAY AUTHORIZATION POLICY') "order: $($plan.Order -join ', ')"
Set-PlanOnXml -Plan $plan -Doc $doc -Config $cfg
$problems = Test-NpsMatchesPlan -Plan $plan -Doc $doc -Config $cfg
Check (-not $problems) "xml matches plan $problems"
$crps = @(Get-CrpList -Doc $doc -Config $cfg)
Check (@($crps | Where-Object { $_.Name -like 'Bypass_*' }).Count -eq $plan.Desired.Count) 'policy count in xml'
$prof = Get-ChildByName (Get-NpsSection $doc 'Proxy_Profiles') 'Bypass_3'
Check ($prof -and $prof.SelectSingleNode('Properties/msAuthProviderType').InnerText -eq '1') 'Bypass_3 profile copied (local auth)'
$n3 = Get-ChildByName (Get-NpsSection $doc 'Proxy_Policies') 'Bypass_3'
Check ($n3.SelectSingleNode('Properties/Policy_SourceTag').InnerText -eq '1') 'Bypass_3 source tag copied'
Check ($n3.SelectSingleNode('Properties/msNPAction').InnerText -eq 'Bypass_3') 'msNPAction renamed'

# Second plan on the changed xml: no changes
$plan2 = Get-SyncPlan -Config $cfg -Doc $doc
Check (-not $plan2.HasChanges) 'second plan has no changes'
Check (@($plan2.Users | Where-Object Status -eq 'In NPS').Count -eq 32) 'all users seen as in NPS'

# Fewer users: extra policies deleted
$users[0..29] | ForEach-Object { $_.Groups = @() }
$users | ConvertTo-Json -Depth 3 | Set-Content -Path $Ctx.TestUsersFile
$plan3 = Get-SyncPlan -Config $cfg -Doc $doc
Check ($plan3.Desired.Count -eq 1 -and @($plan3.Policies | Where-Object Action -eq 'Delete').Count -ge 1) 'shrinks and deletes'
Set-PlanOnXml -Plan $plan3 -Doc $doc -Config $cfg
Check (-not (Test-NpsMatchesPlan -Plan $plan3 -Doc $doc -Config $cfg)) 'xml matches plan3'

# Nobody: one disabled placeholder
$users | ForEach-Object { $_.Groups = @() }
$users | ConvertTo-Json -Depth 3 | Set-Content -Path $Ctx.TestUsersFile
$plan4 = Get-SyncPlan -Config $cfg -Doc $doc
Check ($plan4.Desired.Count -eq 1 -and -not $plan4.Desired[0].Enabled) 'empty: one disabled policy'
Check (-not (Test-PatternMatch $plan4.Desired[0].Pattern 'no-users\none')) 'placeholder does not match a normal name'

Remove-Item -Recurse -Force $work
if ($script:fails) { throw "$script:fails check(s) failed" }
Microsoft.PowerShell.Utility\Write-Host 'All unit checks passed.' -ForegroundColor Green

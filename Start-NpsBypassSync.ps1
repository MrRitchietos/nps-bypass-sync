<#
.SYNOPSIS
    NPS Bypass Sync: keeps the MFA bypass connection request policies in NPS in sync with AD groups.

.DESCRIPTION
    Connection request policies in NPS can't check group membership, so an MFA bypass on an RD Gateway is
    normally a list of user names typed into the User Name condition of one or more policies. This tool reads
    the members of the bypass group(s) from Active Directory and writes those lists for you: it creates,
    updates or removes the bypass policies (Bypass_2, Bypass_3, ...) so every list stays under the 256
    character limit of the NPS console.

    Normally started through NpsBypassSync.exe. The window shows what would change; Sync now writes it.
    -Sync runs one sync without a window (used by the scheduled task).

.EXAMPLE
    .\Start-NpsBypassSync.ps1

.EXAMPLE
    .\Start-NpsBypassSync.ps1 -Sync
#>
[CmdletBinding()]
param
(
    # Folder holding assets\. Set by NpsBypassSync.exe.
    [string]$AppRoot,

    # Folder NpsBypassSync.exe was started from.
    [string]$LauncherDir,

    # Callback from NpsBypassSync.exe that closes its splash screen once the window is visible.
    [object]$OnReady,

    # Set by NpsBypassSync.exe: its own version and full path (for the update button and the scheduled task).
    [string]$ToolVersion,
    [string]$LauncherPath,

    # Headless: run one sync (-Sync) or only show what would change (-Preview).
    [switch]$Sync,
    [switch]$Preview,

    # Headless: turn the scheduled task on or off.
    [switch]$EnableAutoSync,
    [switch]$DisableAutoSync,
    [int]$IntervalMinutes,

    # Other data folder (tests).
    [string]$DataDir,

    # Tests only: read users from a JSON file instead of Active Directory.
    [string]$TestUsersFile,

    # GUI self-test: saves <path>-ready.png, then closes the window.
    [string]$Screenshot
)

$IsHeadless = $Sync -or $Preview -or $EnableAutoSync -or $DisableAutoSync

#region Bootstrap (only when started as a .ps1 file)
if ($PSCommandPath)
{
    $principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
    {
        if ($IsHeadless) { throw 'Administrator rights are required. Run this from an elevated PowerShell.' }
        $shell = (Get-Process -Id $PID).Path
        Start-Process -FilePath $shell -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-STA', '-File', "`"$PSCommandPath`"") -Verb RunAs
        return
    }
    if (-not $IsHeadless -and [Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA')
    {
        & (Get-Process -Id $PID).Path -NoProfile -ExecutionPolicy Bypass -STA -File $PSCommandPath
        return
    }
    if (-not $AppRoot) { $AppRoot = $PSScriptRoot }
}
if (-not $AppRoot) { throw 'AppRoot was not provided.' }
#endregion

#region Shared context
if (-not $DataDir) { $DataDir = Join-Path -Path $env:ProgramData -ChildPath 'NpsBypassSync' }
$Ctx = @{
    AppRoot       = $AppRoot
    LauncherDir   = $LauncherDir
    BrandingDir   = Join-Path -Path $AppRoot -ChildPath 'assets\branding'
    DataDir       = $DataDir
    ConfigFile    = Join-Path -Path $DataDir -ChildPath 'config.json'
    StateFile     = Join-Path -Path $DataDir -ChildPath 'state.json'
    BackupDir     = Join-Path -Path $DataDir -ChildPath 'backups'
    WorkDir       = Join-Path -Path $DataDir -ChildPath 'work'
    LogFile       = Join-Path -Path $DataDir -ChildPath ("logs\NpsBypassSync_{0:yyyyMM}.log" -f (Get-Date))
    InstallDir    = Join-Path -Path $env:ProgramFiles -ChildPath 'NPS Bypass Sync'
    TaskName      = 'NPS Bypass Sync'
    EventSource   = 'NPS Bypass Sync'
    UpdateRepo    = 'MrRitchietos/nps-bypass-sync'
    ToolVersion   = $ToolVersion
    LauncherPath  = $LauncherPath
    TestUsersFile = $TestUsersFile
}
$Shared = $null
#endregion

#region Worker code (runs in a background runspace so the window never freezes)
$WorkerCode = {

function Write-Log
{
    param ([string]$Message, [ValidateSet('INFO', 'OK', 'WARN', 'ERROR')][string]$Level = 'INFO')
    $line = '{0:yyyy-MM-dd HH:mm:ss}  {1,-5}  {2}' -f (Get-Date), $Level, $Message
    if ($Shared) { $Shared.Log.Enqueue($line.Substring(11)) } else { Write-Host $line }
    if ($Ctx.LogFile) { try { [IO.File]::AppendAllText($Ctx.LogFile, "$line`r`n") } catch { } }
}

function Set-Step
{
    param ([string]$Text)
    if ($Shared) { $Shared.Step = $Text }
    Write-Log $Text
}

function Invoke-Native
{
    # Runs a program and returns its output; throws on a non-zero exit code.
    param ([string]$FilePath, [string]$Arguments)
    $psi = New-Object Diagnostics.ProcessStartInfo
    $psi.FileName = $FilePath
    $psi.Arguments = $Arguments
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    $p = [Diagnostics.Process]::Start($psi)
    $stdout = $p.StandardOutput.ReadToEndAsync()
    $stderr = $p.StandardError.ReadToEnd()
    $p.WaitForExit()
    $text = ($stdout.Result + $stderr).Trim()
    if ($p.ExitCode -ne 0) { throw "$(Split-Path -Leaf $FilePath) failed ($($p.ExitCode)): $text" }
    return $text
}

#region Data folder, config, state
function Initialize-DataDir
{
    # The data folder holds NPS exports, which contain the RADIUS shared secrets in plain text:
    # only SYSTEM and Administrators get access, nothing is inherited from ProgramData.
    foreach ($dir in @($Ctx.DataDir, $Ctx.BackupDir, $Ctx.WorkDir, (Split-Path -Parent $Ctx.LogFile)))
    {
        if (-not (Test-Path -LiteralPath $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
    }
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in 'S-1-5-18', 'S-1-5-32-544')
    {
        $id = New-Object Security.Principal.SecurityIdentifier $sid
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule $id, 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow'))
    }
    $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier 'S-1-5-32-544'))
    try { Set-Acl -LiteralPath $Ctx.DataDir -AclObject $acl } catch { Write-Log "Could not lock down $($Ctx.DataDir): $($_.Exception.Message)" 'WARN' }
}

function Get-DefaultConfig
{
    [pscustomobject]@{
        BypassGroups    = @()
        RequireGroups   = @()
        PolicyPrefix    = 'Bypass_'
        FirstNumber     = 2
        TemplatePolicy  = ''
        MatchSam        = $true
        MatchDomainSam  = $true
        MatchUpn        = $true
        IncludeDisabled = $false
        MaxUsers        = 100
        MaxLength       = 250
        IntervalMinutes = 15
        BackupDays      = 30
    }
}

function Get-Config
{
    $config = Get-DefaultConfig
    if (Test-Path -LiteralPath $Ctx.ConfigFile)
    {
        $saved = [IO.File]::ReadAllText($Ctx.ConfigFile) | ConvertFrom-Json
        foreach ($prop in $saved.PSObject.Properties) { if ($config.PSObject.Properties[$prop.Name]) { $config.($prop.Name) = $prop.Value } }
    }
    $config.BypassGroups = @($config.BypassGroups | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim() })
    $config.RequireGroups = @($config.RequireGroups | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim() })
    return $config
}

function Test-Config
{
    param ($Config)
    if (-not @($Config.BypassGroups).Count) { throw 'No bypass group is set. Add at least one group under Settings.' }
    if ("$($Config.PolicyPrefix)" -notmatch '^[A-Za-z][A-Za-z0-9_-]{0,40}$') { throw "Policy name '$($Config.PolicyPrefix)' is not valid. Use letters, digits, _ or -, starting with a letter." }
    if ([int]$Config.FirstNumber -lt 1 -or [int]$Config.FirstNumber -gt 999) { throw 'First number must be between 1 and 999.' }
    if ([int]$Config.MaxLength -lt 80 -or [int]$Config.MaxLength -gt 4000) { throw 'Max length must be between 80 and 4000.' }
    if ([int]$Config.MaxUsers -lt 1) { throw 'Max users must be 1 or more.' }
    if (-not ($Config.MatchSam -or $Config.MatchDomainSam -or $Config.MatchUpn)) { throw 'Pick at least one user name format.' }
}

function Save-Config
{
    param ($Config)
    Initialize-DataDir
    Test-Config $Config
    [IO.File]::WriteAllText($Ctx.ConfigFile, ($Config | ConvertTo-Json -Depth 4))
    Write-Log 'Settings saved.' 'OK'
    return [pscustomobject]@{ __Result = $true }
}

function Get-State
{
    try { if (Test-Path -LiteralPath $Ctx.StateFile) { return [IO.File]::ReadAllText($Ctx.StateFile) | ConvertFrom-Json } } catch { }
    return $null
}
#endregion

#region Active Directory
function ConvertTo-LdapFilterValue
{
    param ([string]$Value)
    $sb = New-Object Text.StringBuilder
    foreach ($c in $Value.ToCharArray())
    {
        switch ($c)
        {
            '\' { [void]$sb.Append('\5c') }
            '*' { [void]$sb.Append('\2a') }
            '(' { [void]$sb.Append('\28') }
            ')' { [void]$sb.Append('\29') }
            ([char]0) { [void]$sb.Append('\00') }
            default { [void]$sb.Append($c) }
        }
    }
    return $sb.ToString()
}

function New-Searcher
{
    param ([string]$Root, [string]$Filter, [string[]]$Properties)
    $searcher = New-Object DirectoryServices.DirectorySearcher
    $searcher.SearchRoot = New-Object DirectoryServices.DirectoryEntry "LDAP://$Root"
    $searcher.Filter = $Filter
    $searcher.PageSize = 500
    $searcher.SearchScope = 'Subtree'
    foreach ($p in $Properties) { [void]$searcher.PropertiesToLoad.Add($p) }
    return $searcher
}

function Get-Prop
{
    param ($Result, [string]$Name)
    $v = $Result.Properties[$Name.ToLowerInvariant()]
    if ($v -and $v.Count) { return $v[0] }
    return $null
}

function Get-DomainInfo
{
    Add-Type -AssemblyName System.DirectoryServices
    $domainDn = ''
    $configDn = ''
    try
    {
        $rootDse = New-Object DirectoryServices.DirectoryEntry 'LDAP://RootDSE'
        $domainDn = "$($rootDse.Properties['defaultNamingContext'].Value)"
        $configDn = "$($rootDse.Properties['configurationNamingContext'].Value)"
    }
    catch { Write-Log "RootDSE: $($_.Exception.Message)" 'WARN' }
    if (-not $domainDn -or -not $configDn) { throw 'Active Directory is not reachable from this server. Is it joined to the domain and can it reach a domain controller?' }
    $searcher = New-Searcher -Root "CN=Partitions,$configDn" -Filter "(&(objectClass=crossRef)(nCName=$(ConvertTo-LdapFilterValue $domainDn)))" -Properties 'nETBIOSName', 'dnsRoot'
    $r = $searcher.FindOne()
    $netbios = if ($r) { "$(Get-Prop $r 'nETBIOSName')" } else { '' }
    if (-not $netbios) { $netbios = $env:USERDOMAIN }
    return [pscustomobject]@{ DomainDn = $domainDn; NetBios = $netbios; Dns = if ($r) { "$(Get-Prop $r 'dnsRoot')" } else { '' } }
}

function Resolve-Group
{
    # Accepts a group name (sAMAccountName or CN), DOMAIN\name or a distinguished name.
    param ([string]$Name, $Domain)
    $name = $Name.Trim()
    if ($name -match '^[^\\]+\\(.+)$') { $name = $Matches[1] }
    $value = ConvertTo-LdapFilterValue $name
    $filter = if ($name -match '=') { "(&(objectCategory=group)(distinguishedName=$value))" } else { "(&(objectCategory=group)(|(sAMAccountName=$value)(cn=$value)))" }
    $found = @((New-Searcher -Root $Domain.DomainDn -Filter $filter -Properties 'distinguishedName', 'sAMAccountName').FindAll())
    if ($found.Count -eq 0) { throw "Group '$Name' was not found in $($Domain.Dns)." }
    if ($found.Count -gt 1) { throw "More than one group matches '$Name'. Use the full name (distinguished name)." }
    return "$(Get-Prop $found[0] 'distinguishedName')"
}

function Get-GroupUsers
{
    # All user accounts in the group, also through nested groups (LDAP_MATCHING_RULE_IN_CHAIN, no 5000 member limit).
    param ([string]$GroupDn, $Domain)
    $filter = "(&(objectCategory=person)(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:=$(ConvertTo-LdapFilterValue $GroupDn)))"
    $props = 'distinguishedName', 'sAMAccountName', 'userPrincipalName', 'displayName', 'userAccountControl', 'accountExpires'
    $results = (New-Searcher -Root $Domain.DomainDn -Filter $filter -Properties $props).FindAll()
    try
    {
        foreach ($r in $results)
        {
            $uac = [int](Get-Prop $r 'userAccountControl')
            $expires = Get-Prop $r 'accountExpires'
            $expired = $false
            if ($expires -and [int64]$expires -gt 0 -and [int64]$expires -lt [int64]::MaxValue)
            {
                try { $expired = [DateTime]::FromFileTimeUtc([int64]$expires) -lt [DateTime]::UtcNow } catch { }
            }
            [pscustomobject]@{
                Dn          = "$(Get-Prop $r 'distinguishedName')"
                Sam         = "$(Get-Prop $r 'sAMAccountName')"
                Upn         = "$(Get-Prop $r 'userPrincipalName')"
                DisplayName = "$(Get-Prop $r 'displayName')"
                NetBios     = $Domain.NetBios
                Disabled    = [bool]($uac -band 2)
                Expired     = $expired
            }
        }
    }
    finally { $results.Dispose() }
}

function Get-CandidateUsers
{
    # Returns every user of the bypass groups, each with Include = $true/$false and a Note when left out.
    param ($Config)
    $bypass = @{}
    $required = $null

    if ($Ctx.TestUsersFile)
    {
        # Test source: [{ Sam, Upn, DisplayName, NetBios, Groups: [..], Disabled }]
        $all = @([IO.File]::ReadAllText($Ctx.TestUsersFile) | ConvertFrom-Json | ForEach-Object { $_ })
        foreach ($g in $Config.BypassGroups)
        {
            foreach ($u in $all | Where-Object { @($_.Groups) -contains $g })
            {
                $bypass[$u.Sam] = [pscustomobject]@{ Dn = $u.Sam; Sam = $u.Sam; Upn = "$($u.Upn)"; DisplayName = "$($u.DisplayName)"; NetBios = "$($u.NetBios)"; Disabled = [bool]$u.Disabled; Expired = $false }
            }
        }
        if (@($Config.RequireGroups).Count)
        {
            $required = @{}
            foreach ($u in $all | Where-Object { $g = @($_.Groups); @($Config.RequireGroups | Where-Object { $g -contains $_ }).Count }) { $required[$u.Sam] = $true }
        }
    }
    else
    {
        Set-Step 'Reading Active Directory...'
        $domain = Get-DomainInfo
        foreach ($g in $Config.BypassGroups)
        {
            $dn = Resolve-Group -Name $g -Domain $domain
            $users = @(Get-GroupUsers -GroupDn $dn -Domain $domain)
            Write-Log "Bypass group '$g': $($users.Count) user(s)."
            foreach ($u in $users) { $bypass[$u.Dn] = $u }
        }
        if (@($Config.RequireGroups).Count)
        {
            $required = @{}
            foreach ($g in $Config.RequireGroups)
            {
                $dn = Resolve-Group -Name $g -Domain $domain
                $users = @(Get-GroupUsers -GroupDn $dn -Domain $domain)
                Write-Log "Access group '$g': $($users.Count) user(s)."
                foreach ($u in $users) { $required[$u.Dn] = $true }
            }
        }
    }

    foreach ($u in $bypass.Values | Sort-Object -Property Sam)
    {
        $note = ''
        if ($u.Disabled -and -not $Config.IncludeDisabled) { $note = 'Account disabled' }
        elseif ($u.Expired -and -not $Config.IncludeDisabled) { $note = 'Account expired' }
        elseif ($required -and -not $required.ContainsKey($u.Dn)) { $note = 'Not in an access group' }
        elseif ($u.Sam -match '["]' -or $u.Upn -match '["]') { $note = 'Name has a quote character' }
        elseif (-not @(Get-UserForms -User $u -Config $Config).Count) { $note = 'No user name to match (no UPN?)' }
        $u | Add-Member -NotePropertyName Include -NotePropertyValue (-not $note) -Force
        $u | Add-Member -NotePropertyName Note -NotePropertyValue $note -Force
        $u
    }
}
#endregion

#region User Name patterns
function ConvertTo-RegexLiteral
{
    # Escapes everything NPS treats as special. NPS matching is case-insensitive (checked on a real NPS).
    param ([string]$Text)
    return [regex]::Replace($Text, '[\\^$.|?*+()\[\]{}]', { param ($m) '\' + $m.Value })
}

function Get-UserForms
{
    # The user names one user can log on with, as they arrive at NPS (for the self-check).
    param ($User, $Config)
    $forms = @()
    if ($Config.MatchSam) { $forms += $User.Sam }
    if ($Config.MatchDomainSam -and $User.NetBios) { $forms += "$($User.NetBios)\$($User.Sam)" }
    if ($Config.MatchUpn -and $User.Upn) { $forms += $User.Upn }
    return $forms
}

function New-UserNamePattern
{
    # One anchored pattern for a set of users, grouped to stay short:
    #   ^((CONTOSO\\)?(jdoe|asmith)|(john\.doe|anna\.smith)@contoso\.com)$
    param ([object[]]$Users, $Config)
    $parts = New-Object Collections.Generic.List[string]

    $byDomain = [ordered]@{}
    foreach ($u in $Users)
    {
        $key = if ($Config.MatchDomainSam) { "$($u.NetBios)" } else { '' }
        if (-not $byDomain.Contains($key)) { $byDomain[$key] = New-Object Collections.Generic.List[string] }
        $byDomain[$key].Add((ConvertTo-RegexLiteral $u.Sam))
    }
    foreach ($key in $byDomain.Keys)
    {
        $names = '(' + ($byDomain[$key] -join '|') + ')'
        if ($Config.MatchDomainSam -and $key)
        {
            $prefix = (ConvertTo-RegexLiteral $key) + '\\'
            if ($Config.MatchSam) { $parts.Add("($prefix)?$names") } else { $parts.Add("$prefix$names") }
        }
        elseif ($Config.MatchSam) { $parts.Add($names) }
    }

    if ($Config.MatchUpn)
    {
        $bySuffix = [ordered]@{}
        foreach ($u in $Users | Where-Object { $_.Upn -match '^(.+)@([^@]+)$' })
        {
            $null = $u.Upn -match '^(.+)@([^@]+)$'
            $suffix = $Matches[2].ToLowerInvariant()
            if (-not $bySuffix.Contains($suffix)) { $bySuffix[$suffix] = New-Object Collections.Generic.List[string] }
            $bySuffix[$suffix].Add((ConvertTo-RegexLiteral $Matches[1]))
        }
        foreach ($suffix in $bySuffix.Keys) { $parts.Add('(' + ($bySuffix[$suffix] -join '|') + ')@' + (ConvertTo-RegexLiteral $suffix)) }
    }
    if (-not $parts.Count) { return $null }
    return '^(' + ($parts -join '|') + ')$'
}

function Split-UsersToPolicies
{
    # Fills each policy with as many users as fit in MaxLength characters.
    param ([object[]]$Users, $Config)
    $max = [int]$Config.MaxLength
    $buckets = New-Object Collections.Generic.List[object]
    $current = New-Object Collections.Generic.List[object]
    foreach ($u in $Users)
    {
        $current.Add($u)
        $pattern = New-UserNamePattern -Users $current.ToArray() -Config $Config
        if ($pattern.Length -gt $max)
        {
            $current.RemoveAt($current.Count - 1)
            if (-not $current.Count) { throw "The user name pattern for '$($u.Sam)' alone is longer than $max characters." }
            $buckets.Add($current.ToArray())
            $current = New-Object Collections.Generic.List[object]
            $current.Add($u)
            $alone = New-UserNamePattern -Users $current.ToArray() -Config $Config
            if ($alone.Length -gt $max) { throw "The user name pattern for '$($u.Sam)' alone is longer than $max characters." }
        }
    }
    if ($current.Count) { $buckets.Add($current.ToArray()) }
    return , $buckets.ToArray()
}

function Test-PatternMatch
{
    param ([string]$Pattern, [string]$Name)
    if (-not $Pattern) { return $false }
    try { return [regex]::IsMatch($Name, $Pattern, 'IgnoreCase, CultureInvariant') } catch { return $false }
}
#endregion

#region NPS configuration (export / edit / import)
$EmptyPattern = '^no-users\\\\none$'

function Export-NpsXml
{
    param ([string]$Path)
    if (-not (Get-Service -Name IAS -ErrorAction SilentlyContinue)) { throw 'Network Policy Server (NPS) is not installed on this server.' }
    if (Test-Path -LiteralPath $Path) { Remove-Item -LiteralPath $Path -Force }
    Export-NpsConfiguration -Path $Path
    if (-not (Test-Path -LiteralPath $Path)) { throw 'Export-NpsConfiguration did not write a file.' }
    $doc = New-Object Xml.XmlDocument
    $doc.PreserveWhitespace = $true
    $doc.Load($Path)
    return $doc
}

function Save-NpsXml
{
    param ([Xml.XmlDocument]$Doc, [string]$Path)
    $writer = New-Object IO.StreamWriter ($Path, $false, (New-Object Text.UTF8Encoding $false))
    try { $Doc.Save($writer) } finally { $writer.Dispose() }
}

function Get-NpsSection
{
    param ([Xml.XmlDocument]$Doc, [string]$Name)
    $node = $Doc.SelectSingleNode("/Root/Children/Microsoft_Internet_Authentication_Service/Children/$Name/Children")
    if (-not $node) { throw "The NPS export has no $Name section." }
    return $node
}

function Get-ChildByName
{
    param ($Parent, [string]$Name)
    foreach ($c in $Parent.ChildNodes) { if ($c.NodeType -eq 'Element' -and $c.GetAttribute('name') -eq $Name) { return $c } }
    return $null
}

function Get-PropNode
{
    param ($PolicyNode, [string]$Name)
    return $PolicyNode.SelectSingleNode("Properties/$Name")
}

function Get-UserNameConstraint
{
    param ($PolicyNode)
    foreach ($n in $PolicyNode.SelectNodes('Properties/msNPConstraint'))
    {
        if ($n.InnerText -match '^\s*MATCH\("User-Name=(.*)"\)\s*$') { return $n }
    }
    return $null
}

function Get-CrpList
{
    param ([Xml.XmlDocument]$Doc, $Config)
    $section = Get-NpsSection $Doc 'Proxy_Policies'
    $managed = '^' + [regex]::Escape("$($Config.PolicyPrefix)") + '(\d+)$'
    foreach ($node in @($section.ChildNodes | Where-Object { $_.NodeType -eq 'Element' }))
    {
        $name = $node.GetAttribute('name')
        $seq = Get-PropNode $node 'msNPSequence'
        $enabled = Get-PropNode $node 'Policy_Enabled'
        $un = Get-UserNameConstraint $node
        $number = if ($name -match $managed) { [int]$Matches[1] } else { $null }
        [pscustomobject]@{
            Name     = $name
            Node     = $node
            Sequence = if ($seq) { [int]$seq.InnerText } else { 999999 }
            Enabled  = if ($enabled) { $enabled.InnerText -eq '1' } else { $true }
            Pattern  = if ($un -and $un.InnerText -match '^\s*MATCH\("User-Name=(.*)"\)\s*$') { $Matches[1] } else { $null }
            Number   = $number
            Managed  = $null -ne $number -and $number -ge [int]$Config.FirstNumber
        }
    }
}

function ConvertTo-ElementName
{
    param ([string]$Name)
    $n = [regex]::Replace($Name, '[^A-Za-z0-9_.-]', '_')
    if ($n -notmatch '^[A-Za-z_]') { $n = "_$n" }
    return $n
}

function Set-PropValue
{
    # Sets (or adds) a simple typed property like <Policy_Enabled dt:dt="boolean">1</Policy_Enabled>.
    param ($PolicyNode, [string]$Name, [string]$Type, [string]$Value)
    $node = Get-PropNode $PolicyNode $Name
    if (-not $node)
    {
        $props = $PolicyNode.SelectSingleNode('Properties')
        $doc = $PolicyNode.OwnerDocument
        $node = $doc.CreateElement($Name)
        $attr = $doc.CreateAttribute('dt', 'dt', 'urn:schemas-microsoft-com:datatypes')
        $attr.Value = $Type
        [void]$node.Attributes.Append($attr)
        [void]$props.AppendChild($node)
    }
    $node.InnerText = $Value
}

function Copy-PolicyNode
{
    # Clones a policy (or profile) element under a new name.
    param ($Source, [string]$NewName)
    $doc = $Source.OwnerDocument
    $copy = $doc.CreateElement((ConvertTo-ElementName $NewName))
    $copy.SetAttribute('name', $NewName)
    foreach ($child in $Source.ChildNodes) { [void]$copy.AppendChild($child.CloneNode($true)) }
    return $copy
}

function Get-SyncPlan
{
    # Works out the bypass policies NPS should have and what differs from now. Changes nothing.
    param ($Config, [Xml.XmlDocument]$Doc)
    Test-Config $Config
    $candidates = @(Get-CandidateUsers -Config $Config)
    $users = @($candidates | Where-Object Include)
    $crps = @(Get-CrpList -Doc $Doc -Config $Config)
    $current = @($crps | Where-Object Managed | Sort-Object -Property Number)
    $foreignNoUserName = @($current | Where-Object { -not $_.Pattern })
    if ($foreignNoUserName.Count) { throw "Policy '$($foreignNoUserName[0].Name)' matches the bypass policy names but has no User Name condition. Rename it or change the policy name in Settings." }

    $template = if ($current.Count) { $current[0] } else { $crps | Where-Object { $_.Name -eq "$($Config.TemplatePolicy)" } | Select-Object -First 1 }
    if (-not $template) { throw "There is no '$($Config.PolicyPrefix)$($Config.FirstNumber)' policy yet. Pick a policy to copy the settings from (Template policy in Settings)." }

    $buckets = if ($users.Count) { Split-UsersToPolicies -Users $users -Config $Config } else { @() }
    $desired = New-Object Collections.Generic.List[object]
    $i = 0
    foreach ($bucket in $buckets)
    {
        $desired.Add([pscustomobject]@{ Name = "$($Config.PolicyPrefix)$([int]$Config.FirstNumber + $i)"; Pattern = New-UserNamePattern -Users $bucket -Config $Config; Enabled = $true; Users = @($bucket) })
        $i++
    }
    if (-not $desired.Count)
    {
        # No users: keep one policy, switched off, with a pattern no real logon name can match.
        $desired.Add([pscustomobject]@{ Name = "$($Config.PolicyPrefix)$($Config.FirstNumber)"; Pattern = $EmptyPattern; Enabled = $false; Users = @() })
    }

    # Self-check: every user form must match exactly one new policy, and nothing close to it may match.
    $allForms = @{}
    foreach ($u in $users) { foreach ($form in Get-UserForms -User $u -Config $Config) { $allForms[$form.ToLowerInvariant()] = $true } }
    foreach ($form in @($allForms.Keys))
    {
        $hits = @($desired | Where-Object { Test-PatternMatch $_.Pattern $form })
        if ($hits.Count -ne 1) { throw "Self-check failed: '$form' matches $($hits.Count) policies." }
        foreach ($near in "x$form", "${form}x", "x\$form", $form.Substring(1))
        {
            if ($allForms.ContainsKey($near.ToLowerInvariant())) { continue }
            if (@($desired | Where-Object { Test-PatternMatch $_.Pattern $near }).Count) { throw "Self-check failed: '$near' would also match." }
        }
    }

    $policies = New-Object Collections.Generic.List[object]
    foreach ($d in $desired)
    {
        $now = $current | Where-Object { $_.Name -eq $d.Name } | Select-Object -First 1
        $action = if (-not $now) { 'Create' } elseif ($now.Pattern -ne $d.Pattern -or $now.Enabled -ne $d.Enabled) { 'Update' } else { 'No change' }
        $policies.Add([pscustomobject]@{ Name = $d.Name; Action = $action; Users = $d.Users.Count; Length = $d.Pattern.Length; Enabled = $d.Enabled; Pattern = $d.Pattern; OldPattern = if ($now) { $now.Pattern } else { '' } })
    }
    foreach ($c in $current | Where-Object { $n = $_.Name; -not ($desired | Where-Object { $_.Name -eq $n }) })
    {
        $policies.Add([pscustomobject]@{ Name = $c.Name; Action = 'Delete'; Users = 0; Length = 0; Enabled = $c.Enabled; Pattern = ''; OldPattern = $c.Pattern })
    }

    # Order: the bypass block takes the place of the first bypass policy (or goes to the top), the rest keeps its order.
    $ordered = @($crps | Sort-Object -Property Sequence, Name)
    $first = 0
    for ($i = 0; $i -lt $ordered.Count; $i++) { if ($ordered[$i].Managed) { $first = $i; break } }
    $before = @(); $after = @()
    for ($i = 0; $i -lt $ordered.Count; $i++)
    {
        if ($ordered[$i].Managed) { continue }
        if ($i -lt $first) { $before += $ordered[$i].Name } else { $after += $ordered[$i].Name }
    }
    $order = @($before) + @($desired | ForEach-Object Name) + @($after)
    $orderNow = @($ordered | ForEach-Object Name)
    $orderChanged = ($order -join "`n") -ne ($orderNow -join "`n")

    # Who is new, who stays, who goes.
    $state = Get-State
    $rows = New-Object Collections.Generic.List[object]
    foreach ($u in $candidates)
    {
        $policy = ''
        $status = 'Skipped'
        if ($u.Include)
        {
            $policy = ($desired | Where-Object { @($_.Users | ForEach-Object Sam) -contains $u.Sam } | Select-Object -First 1).Name
            $forms = @(Get-UserForms -User $u -Config $Config)
            $known = @($current | Where-Object { $p = $_.Pattern; $_.Enabled -and @($forms | Where-Object { Test-PatternMatch $p $_ }).Count })
            $status = if ($known.Count) { 'In NPS' } else { 'New' }
        }
        $rows.Add([pscustomobject]@{ Status = $status; Name = if ($u.DisplayName) { $u.DisplayName } else { $u.Sam }; Account = $u.Sam; Upn = $u.Upn; Policy = $policy; Note = $u.Note })
    }
    if ($state -and $state.Users)
    {
        $nowSams = @($users | ForEach-Object { $_.Sam.ToLowerInvariant() })
        foreach ($old in @($state.Users) | Where-Object { $nowSams -notcontains "$_".ToLowerInvariant() })
        {
            $rows.Add([pscustomobject]@{ Status = 'Removed'; Name = "$old"; Account = "$old"; Upn = ''; Policy = ''; Note = 'No longer in a bypass group' })
        }
    }

    $changes = @($policies | Where-Object Action -ne 'No change').Count -or $orderChanged
    return [pscustomobject]@{
        __Result     = $true
        Users        = $rows.ToArray()
        Included     = $users
        Policies     = $policies.ToArray()
        Desired      = $desired.ToArray()
        Template     = $template.Name
        Order        = $order
        OrderChanged = $orderChanged
        HasChanges   = [bool]$changes
        Count        = $users.Count
    }
}

function Set-PlanOnXml
{
    # Applies the plan to the exported XML (policies + their profiles).
    param ($Plan, [Xml.XmlDocument]$Doc, $Config)
    $policySection = Get-NpsSection $Doc 'Proxy_Policies'
    $profileSection = Get-NpsSection $Doc 'Proxy_Profiles'
    $templatePolicy = Get-ChildByName $policySection $Plan.Template
    $templateProfile = Get-ChildByName $profileSection $Plan.Template
    if (-not $templatePolicy -or -not $templateProfile) { throw "Template policy '$($Plan.Template)' was not found in the NPS export." }
    $templatePolicy = $templatePolicy.CloneNode($true)
    $templateProfile = $templateProfile.CloneNode($true)

    foreach ($p in $Plan.Policies | Where-Object Action -eq 'Delete')
    {
        foreach ($section in $policySection, $profileSection)
        {
            $node = Get-ChildByName $section $p.Name
            if ($node) { [void]$section.RemoveChild($node) }
        }
    }
    foreach ($d in $Plan.Desired)
    {
        $node = Get-ChildByName $policySection $d.Name
        if (-not $node)
        {
            $node = Copy-PolicyNode -Source $templatePolicy -NewName $d.Name
            [void]$policySection.AppendChild($node)
            $old = Get-ChildByName $profileSection $d.Name
            if ($old) { [void]$profileSection.RemoveChild($old) }
            [void]$profileSection.AppendChild((Copy-PolicyNode -Source $templateProfile -NewName $d.Name))
        }
        elseif (-not (Get-ChildByName $profileSection $d.Name))
        {
            [void]$profileSection.AppendChild((Copy-PolicyNode -Source $templateProfile -NewName $d.Name))
        }
        Set-PropValue $node 'msNPAction' 'string' $d.Name
        Set-PropValue $node 'Policy_Enabled' 'boolean' $(if ($d.Enabled) { '1' } else { '0' })
        $constraint = Get-UserNameConstraint $node
        $text = 'MATCH("User-Name=' + $d.Pattern + '")'
        if ($constraint) { $constraint.InnerText = $text }
        else
        {
            $props = $node.SelectSingleNode('Properties')
            $c = $Doc.CreateElement('msNPConstraint')
            $attr = $Doc.CreateAttribute('dt', 'dt', 'urn:schemas-microsoft-com:datatypes')
            $attr.Value = 'string'
            [void]$c.Attributes.Append($attr)
            $c.InnerText = $text
            [void]$props.AppendChild($c)
        }
    }
    $seq = 1
    foreach ($name in $Plan.Order)
    {
        $node = Get-ChildByName $policySection $name
        if (-not $node) { throw "Policy '$name' is missing after the changes." }
        Set-PropValue $node 'msNPSequence' 'int' "$seq"
        $seq++
    }
}

function Test-NpsMatchesPlan
{
    # Reads NPS back after the import and compares it with the plan.
    param ($Plan, [Xml.XmlDocument]$Doc, $Config)
    $crps = @(Get-CrpList -Doc $Doc -Config $Config)
    $problems = @()
    foreach ($d in $Plan.Desired)
    {
        $c = $crps | Where-Object { $_.Name -eq $d.Name } | Select-Object -First 1
        if (-not $c) { $problems += "$($d.Name) is missing"; continue }
        if ($c.Pattern -ne $d.Pattern) { $problems += "$($d.Name) has a different User Name condition" }
        if ($c.Enabled -ne $d.Enabled) { $problems += "$($d.Name) has the wrong state" }
    }
    foreach ($c in $crps | Where-Object Managed)
    {
        if (-not ($Plan.Desired | Where-Object { $_.Name -eq $c.Name })) { $problems += "$($c.Name) should have been removed" }
    }
    $order = @($crps | Sort-Object -Property Sequence | ForEach-Object Name)
    if (($order -join "`n") -ne ($Plan.Order -join "`n")) { $problems += 'the processing order is different' }
    return $problems
}

function Write-SyncEvent
{
    param ([int]$Id, [string]$Type, [string]$Message)
    try
    {
        if (-not [Diagnostics.EventLog]::SourceExists($Ctx.EventSource)) { New-EventLog -LogName Application -Source $Ctx.EventSource }
        Write-EventLog -LogName Application -Source $Ctx.EventSource -EventId $Id -EntryType $Type -Message $Message
    }
    catch { Write-Log "Could not write to the event log: $($_.Exception.Message)" 'WARN' }
}

function Remove-OldBackups
{
    param ($Config)
    $files = @(Get-ChildItem -LiteralPath $Ctx.BackupDir -Filter 'nps-*.xml' -ErrorAction SilentlyContinue | Sort-Object -Property LastWriteTime -Descending)
    $limit = (Get-Date).AddDays(-[int]$Config.BackupDays)
    foreach ($f in $files | Select-Object -Skip 10 | Where-Object { $_.LastWriteTime -lt $limit }) { Remove-Item -LiteralPath $f.FullName -Force -ErrorAction SilentlyContinue }
    foreach ($f in Get-ChildItem -LiteralPath (Split-Path -Parent $Ctx.LogFile) -Filter '*.log' -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -lt (Get-Date).AddMonths(-12) }) { Remove-Item -LiteralPath $f.FullName -Force -ErrorAction SilentlyContinue }
}

function Get-Preview
{
    param ($Config)
    Initialize-DataDir
    if (-not $Config) { $Config = Get-Config }
    Set-Step 'Reading the NPS configuration...'
    $doc = Export-NpsXml (Join-Path $Ctx.WorkDir 'current.xml')
    try { return Get-SyncPlan -Config $Config -Doc $doc }
    finally { Remove-Item -LiteralPath (Join-Path $Ctx.WorkDir 'current.xml') -Force -ErrorAction SilentlyContinue }
}

function Invoke-NpsSync
{
    # One sync: read AD + NPS, change NPS only when something differs, check the result, roll back on failure.
    param ($Config)
    $mutex = New-Object Threading.Mutex ($false, 'Global\NpsBypassSync')
    if (-not $mutex.WaitOne([TimeSpan]::FromMinutes(5))) { throw 'Another sync is still running.' }
    $current = Join-Path $Ctx.WorkDir 'current.xml'
    $import = Join-Path $Ctx.WorkDir 'import.xml'
    $check = Join-Path $Ctx.WorkDir 'check.xml'
    try
    {
        Initialize-DataDir
        if (-not $Config) { $Config = Get-Config }
        Set-Step 'Reading the NPS configuration...'
        $doc = Export-NpsXml $current
        $plan = Get-SyncPlan -Config $Config -Doc $doc
        $state = Get-State
        $previousUsers = @(if ($state) { @($state.Users) | ForEach-Object { "$_".ToLowerInvariant() } })
        $nowUsers = @($plan.Included | ForEach-Object { $_.Sam })
        $added = @($nowUsers | Where-Object { $previousUsers -notcontains $_.ToLowerInvariant() })
        $removed = @(if ($state) { @($state.Users) | Where-Object { $nowUsers -notcontains "$_" } })

        if ($plan.Count -gt [int]$Config.MaxUsers)
        {
            throw "The bypass groups hold $($plan.Count) users, more than the limit of $($Config.MaxUsers). Nothing was changed. Check the groups, or raise Max users in Settings."
        }

        $result = [pscustomobject]@{ __Result = $true; Changed = $false; Users = $plan.Count; Policies = @($plan.Desired).Count; Added = $added; Removed = $removed; Backup = ''; Plan = $plan }
        if (-not $plan.HasChanges)
        {
            Write-Log "No changes. $($plan.Count) user(s) in $(@($plan.Desired).Count) policy(ies)." 'OK'
        }
        else
        {
            $backup = Join-Path $Ctx.BackupDir ("nps-{0:yyyyMMdd-HHmmss}.xml" -f (Get-Date))
            Copy-Item -LiteralPath $current -Destination $backup -Force
            $result.Backup = $backup
            Write-Log "Backup of the current NPS configuration: $backup"

            foreach ($p in $plan.Policies | Where-Object Action -ne 'No change') { Write-Log "$($p.Action) $($p.Name) ($($p.Users) users, $($p.Length) characters)" }
            Set-PlanOnXml -Plan $plan -Doc $doc -Config $Config
            Save-NpsXml -Doc $doc -Path $import

            Set-Step 'Writing the NPS configuration...'
            Import-NpsConfiguration -Path $import
            Set-Step 'Checking the result...'
            $problems = @(Test-NpsMatchesPlan -Plan $plan -Doc (Export-NpsXml $check) -Config $Config)
            if ($problems.Count)
            {
                Write-Log "NPS does not match the plan: $($problems -join '; '). Restoring the backup." 'ERROR'
                Import-NpsConfiguration -Path $backup
                throw "The change did not come through correctly ($($problems -join '; ')). The previous NPS configuration was restored from $backup."
            }
            $result.Changed = $true
            $msg = "NPS bypass policies updated: $($plan.Count) user(s) in $(@($plan.Desired).Count) policy(ies)."
            if ($added.Count) { $msg += "`r`nAdded: $($added -join ', ')" }
            if ($removed.Count) { $msg += "`r`nRemoved: $($removed -join ', ')" }
            $msg += "`r`nBackup: $backup"
            $msg += "`r`nNPS uses the new policies within about 30 seconds."
            Write-SyncEvent -Id 1001 -Type Information -Message $msg
            Write-Log ($msg -replace "`r`n", ' | ') 'OK'
        }

        $newState = [pscustomobject]@{
            LastSync   = (Get-Date).ToString('s')
            LastResult = if ($result.Changed) { 'Updated' } else { 'No changes' }
            Users      = $nowUsers
            Policies   = @($plan.Desired | ForEach-Object Name)
        }
        [IO.File]::WriteAllText($Ctx.StateFile, ($newState | ConvertTo-Json -Depth 4))
        Remove-OldBackups -Config $Config
        return $result
    }
    catch
    {
        $message = $_.Exception.Message
        Write-Log $message 'ERROR'
        Write-SyncEvent -Id 1003 -Type Error -Message "NPS bypass sync failed: $message"
        try
        {
            $s = Get-State
            if (-not $s) { $s = [pscustomobject]@{ LastSync = ''; LastResult = ''; Users = @(); Policies = @() } }
            $s.LastSync = (Get-Date).ToString('s')
            $s.LastResult = "Failed: $message"
            [IO.File]::WriteAllText($Ctx.StateFile, ($s | ConvertTo-Json -Depth 4))
        }
        catch { }
        throw
    }
    finally
    {
        foreach ($f in $current, $import, $check) { Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue }
        $mutex.ReleaseMutex()
        $mutex.Dispose()
    }
}
#endregion

function Get-Overview
{
    # Everything the window shows: NPS policy names, the plan (or why there is none) and the automatic sync state.
    param ($Config)
    Initialize-DataDir
    if (-not $Config) { $Config = Get-Config }
    $names = @()
    $plan = $null
    $problem = ''
    $file = Join-Path $Ctx.WorkDir 'overview.xml'
    try
    {
        Set-Step 'Reading the NPS configuration...'
        $doc = Export-NpsXml $file
        $names = @(Get-CrpList -Doc $doc -Config $Config | Sort-Object -Property Sequence, Name | ForEach-Object Name)
        try { $plan = Get-SyncPlan -Config $Config -Doc $doc }
        catch { $problem = $_.Exception.Message; Write-Log $problem 'WARN' }
    }
    catch { $problem = $_.Exception.Message; Write-Log $problem 'ERROR' }
    finally { Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue }
    return [pscustomobject]@{ __Result = $true; Plan = $plan; Problem = $problem; PolicyNames = $names; Auto = Get-AutoSyncStatus }
}

#region Automatic sync (scheduled task)
function Get-InstalledExe { Join-Path $Ctx.InstallDir 'NpsBypassSync.exe' }

function Get-AutoSyncStatus
{
    $task = Get-ScheduledTask -TaskName $Ctx.TaskName -ErrorAction SilentlyContinue
    $exe = Get-InstalledExe
    $installed = ''
    if (Test-Path -LiteralPath $exe) { $installed = (Get-Item -LiteralPath $exe).VersionInfo.ProductVersion -replace '\+.*$', '' }
    $state = Get-State
    $interval = 0
    if ($task)
    {
        $rep = @($task.Triggers | Where-Object { $_.Repetition.Interval } | Select-Object -First 1)
        if ($rep) { try { $interval = [int][Xml.XmlConvert]::ToTimeSpan($rep[0].Repetition.Interval).TotalMinutes } catch { } }
    }
    return [pscustomobject]@{
        __Result         = $true
        Enabled          = [bool]($task -and $task.State -ne 'Disabled')
        Interval         = $interval
        InstalledVersion = $installed
        LastSync         = if ($state) { "$($state.LastSync)" } else { '' }
        LastResult       = if ($state) { "$($state.LastResult)" } else { '' }
    }
}

function Enable-AutoSync
{
    # Copies the exe to Program Files (only admins can change it there) and runs it as SYSTEM every N minutes.
    param ([int]$Minutes = 15)
    if (-not $Ctx.LauncherPath -or -not (Test-Path -LiteralPath $Ctx.LauncherPath)) { throw 'Automatic sync needs NpsBypassSync.exe.' }
    if ($Minutes -lt 5) { $Minutes = 5 }
    Initialize-DataDir
    $exe = Get-InstalledExe
    New-Item -Path $Ctx.InstallDir -ItemType Directory -Force | Out-Null
    if ([IO.Path]::GetFullPath($Ctx.LauncherPath) -ne [IO.Path]::GetFullPath($exe))
    {
        Copy-Item -LiteralPath $Ctx.LauncherPath -Destination $exe -Force
    }
    $action = New-ScheduledTaskAction -Execute $exe -Argument '-Sync' -WorkingDirectory $Ctx.InstallDir
    $repeat = New-ScheduledTaskTrigger -Once -At ((Get-Date).AddMinutes(1)) -RepetitionInterval (New-TimeSpan -Minutes $Minutes)
    $boot = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 30) -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    Register-ScheduledTask -TaskName $Ctx.TaskName -Action $action -Trigger @($repeat, $boot) -Principal $principal -Settings $settings -Description 'Keeps the NPS MFA bypass policies in sync with Active Directory.' -Force | Out-Null
    $config = Get-Config
    $config.IntervalMinutes = $Minutes
    [IO.File]::WriteAllText($Ctx.ConfigFile, ($config | ConvertTo-Json -Depth 4))
    Write-Log "Automatic sync is on: every $Minutes minutes as SYSTEM ($exe)." 'OK'
    return Get-AutoSyncStatus
}

function Disable-AutoSync
{
    if (Get-ScheduledTask -TaskName $Ctx.TaskName -ErrorAction SilentlyContinue)
    {
        Unregister-ScheduledTask -TaskName $Ctx.TaskName -Confirm:$false
    }
    $exe = Get-InstalledExe
    if (Test-Path -LiteralPath $exe) { Remove-Item -LiteralPath $exe -Force -ErrorAction SilentlyContinue }
    if ((Test-Path -LiteralPath $Ctx.InstallDir) -and -not (Get-ChildItem -LiteralPath $Ctx.InstallDir -Force)) { Remove-Item -LiteralPath $Ctx.InstallDir -Force }
    Write-Log 'Automatic sync is off.' 'OK'
    return Get-AutoSyncStatus
}
#endregion

#region App update (GitHub releases)
function ConvertTo-ToolVersion
{
    param ([string]$Text)
    $v = $null
    if ([version]::TryParse(($Text -replace '^v', '' -replace '[-+].*$', ''), [ref]$v)) { return $v }
    return $null
}

function Get-LatestRelease
{
    # Newest non-pre-release on GitHub, compared with the running version.
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$($Ctx.UpdateRepo)/releases/latest" -Headers @{ 'User-Agent' = 'NpsBypassSync' } -TimeoutSec 15
    $asset = @($release.assets) | Where-Object { $_.name -eq 'NpsBypassSync.exe' } | Select-Object -First 1
    $latest = ConvertTo-ToolVersion $release.tag_name
    $current = ConvertTo-ToolVersion $Ctx.ToolVersion
    # Builds with a suffix (1.0.0-ci.5, 1.0.0-beta.1) count as older than the same final version.
    $isPreview = "$($Ctx.ToolVersion)" -match '-'
    $newer = $latest -and $asset -and (-not $current -or $latest -gt $current -or ($latest -eq $current -and $isPreview))
    return [pscustomobject]@{
        __Result = $true
        Tag      = "$($release.tag_name)"
        Url      = if ($asset) { "$($asset.browser_download_url)" } else { '' }
        Newer    = [bool]$newer
        Current  = "$($Ctx.ToolVersion)"
    }
}

function Install-AppUpdate
{
    # Downloads the new exe and swaps it in next to the running one (a running exe can be renamed, not overwritten).
    # When that folder isn't writable the new exe goes to Downloads instead. The automatic sync copy is updated too.
    param ([string]$Url, [string]$Tag)
    $ErrorActionPreference = 'Stop'
    if (-not $Ctx.LauncherPath) { throw 'Updating only works when started from NpsBypassSync.exe.' }
    $exe = $Ctx.LauncherPath
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ("NpsBypassSync-$Tag.exe")
    Set-Step "Downloading $Tag..."
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    $wc = New-Object Net.WebClient
    $wc.Headers['User-Agent'] = 'NpsBypassSync'
    $wc.Proxy = [Net.WebRequest]::GetSystemWebProxy()
    $wc.Proxy.Credentials = [Net.CredentialCache]::DefaultNetworkCredentials
    try { $wc.DownloadFile($Url, $tmp) } finally { $wc.Dispose() }
    if ((Get-Item -LiteralPath $tmp).Length -lt 100KB) { throw 'The download is incomplete.' }

    Set-Step 'Installing the update...'
    $installed = Get-InstalledExe
    if ((Test-Path -LiteralPath $installed) -and [IO.Path]::GetFullPath($installed) -ne [IO.Path]::GetFullPath($exe))
    {
        try { Copy-Item -LiteralPath $tmp -Destination $installed -Force; Write-Log "Automatic sync now uses $Tag." 'OK' }
        catch { Write-Log "Could not update the automatic sync copy: $($_.Exception.Message)" 'WARN' }
    }
    $old = "$exe.old"
    try
    {
        if (Test-Path -LiteralPath $old) { Remove-Item -LiteralPath $old -Force }
        Rename-Item -LiteralPath $exe -NewName (Split-Path -Leaf $old)
        try { Copy-Item -LiteralPath $tmp -Destination $exe -Force }
        catch { Rename-Item -LiteralPath $old -NewName (Split-Path -Leaf $exe); throw }
        Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
        Write-Log "Updated to $Tag." 'OK'
        return [pscustomobject]@{ __Result = $true; Restart = $exe; SavedTo = '' }
    }
    catch
    {
        $downloads = Join-Path ([Environment]::GetFolderPath('UserProfile')) 'Downloads'
        New-Item -Path $downloads -ItemType Directory -Force | Out-Null
        $saved = Join-Path $downloads 'NpsBypassSync.exe'
        Move-Item -LiteralPath $tmp -Destination $saved -Force
        Write-Log "Could not replace $exe ($($_.Exception.Message)). The new version was saved to $saved." 'WARN'
        return [pscustomobject]@{ __Result = $true; Restart = ''; SavedTo = $saved }
    }
}

function Update-InstalledCopy
{
    # Puts the running exe in place of an older automatic sync copy.
    if (-not $Ctx.LauncherPath) { throw 'This only works from NpsBypassSync.exe.' }
    Copy-Item -LiteralPath $Ctx.LauncherPath -Destination (Get-InstalledExe) -Force
    Write-Log "Automatic sync now uses $($Ctx.ToolVersion)." 'OK'
    return Get-AutoSyncStatus
}
#endregion

}
$WorkerCodeText = $WorkerCode.ToString()
. $WorkerCode
#endregion

#region Headless
if ($IsHeadless)
{
    $ErrorActionPreference = 'Stop'
    if ($EnableAutoSync)
    {
        $m = if ($IntervalMinutes) { $IntervalMinutes } else { [int](Get-Config).IntervalMinutes }
        Enable-AutoSync -Minutes $m | Select-Object -Property * -ExcludeProperty __Result | Format-List | Out-String | Write-Host
        return
    }
    if ($DisableAutoSync) { Disable-AutoSync | Out-Null; return }
    if ($Preview)
    {
        $plan = Get-Preview
        $plan.Users | Format-Table Status, Account, Upn, Policy, Note -AutoSize | Out-String -Width 200 | Write-Host
        $plan.Policies | Format-Table Name, Action, Users, Length -AutoSize | Out-String -Width 200 | Write-Host
        return
    }
    $result = Invoke-NpsSync
    Write-Host ("Changed={0} Users={1} Policies={2}" -f $result.Changed, $result.Users, $result.Policies)
    return
}
#endregion

#region Window
Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase

[xml]$xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="NPS Bypass Sync" Width="1220" Height="820" MinWidth="1000" MinHeight="680"
        WindowStartupLocation="CenterScreen" Background="#F3F3F3" Foreground="#1B1B1B"
        FontFamily="Segoe UI Variable Text, Segoe UI" FontSize="13" UseLayoutRounding="True" SnapsToDevicePixels="True">
    <Window.Resources>
        <SolidColorBrush x:Key="Accent" Color="#C80032"/>
        <SolidColorBrush x:Key="Muted" Color="#616161"/>
        <SolidColorBrush x:Key="Line" Color="#E5E5E5"/>

        <Style x:Key="Card" TargetType="Border">
            <Setter Property="Background" Value="White"/>
            <Setter Property="BorderBrush" Value="{StaticResource Line}"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="CornerRadius" Value="8"/>
            <Setter Property="Padding" Value="18"/>
        </Style>
        <Style x:Key="SectionTitle" TargetType="TextBlock">
            <Setter Property="FontSize" Value="14"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="Margin" Value="0,0,0,10"/>
        </Style>
        <Style x:Key="Label" TargetType="TextBlock">
            <Setter Property="Foreground" Value="{StaticResource Muted}"/>
            <Setter Property="FontSize" Value="12"/>
            <Setter Property="Margin" Value="0,0,0,4"/>
            <Setter Property="TextWrapping" Value="Wrap"/>
        </Style>
        <Style TargetType="TextBox">
            <Setter Property="Padding" Value="8,6"/>
            <Setter Property="BorderBrush" Value="#D1D1D1"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="VerticalContentAlignment" Value="Center"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="TextBox">
                        <Border x:Name="Bd" Background="White" BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="{TemplateBinding BorderThickness}" CornerRadius="4">
                            <ScrollViewer x:Name="PART_ContentHost" Margin="{TemplateBinding Padding}" VerticalAlignment="{TemplateBinding VerticalContentAlignment}"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsKeyboardFocused" Value="True">
                                <Setter TargetName="Bd" Property="BorderBrush" Value="#C80032"/>
                            </Trigger>
                            <Trigger Property="IsEnabled" Value="False">
                                <Setter TargetName="Bd" Property="Background" Value="#F7F7F7"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>
        <Style TargetType="Button">
            <Setter Property="Background" Value="White"/>
            <Setter Property="Foreground" Value="#1B1B1B"/>
            <Setter Property="BorderBrush" Value="#D1D1D1"/>
            <Setter Property="Padding" Value="14,7"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border x:Name="Bd" Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="1" CornerRadius="4" Padding="{TemplateBinding Padding}">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="Bd" Property="Background" Value="#F5F5F5"/></Trigger>
                            <Trigger Property="IsPressed" Value="True"><Setter TargetName="Bd" Property="Background" Value="#EBEBEB"/></Trigger>
                            <Trigger Property="IsEnabled" Value="False"><Setter Property="Foreground" Value="#A0A0A0"/></Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>
        <Style x:Key="AccentButton" TargetType="Button">
            <Setter Property="Foreground" Value="White"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="Padding" Value="18,9"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border x:Name="Bd" Background="#C80032" CornerRadius="4" Padding="{TemplateBinding Padding}">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="Bd" Property="Background" Value="#A8002A"/></Trigger>
                            <Trigger Property="IsPressed" Value="True"><Setter TargetName="Bd" Property="Background" Value="#8C0023"/></Trigger>
                            <Trigger Property="IsEnabled" Value="False"><Setter TargetName="Bd" Property="Background" Value="#E6A3B4"/></Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>
        <Style TargetType="CheckBox">
            <Setter Property="Margin" Value="0,0,0,8"/>
            <Setter Property="VerticalContentAlignment" Value="Center"/>
        </Style>
        <Style TargetType="DataGrid">
            <Setter Property="AutoGenerateColumns" Value="False"/>
            <Setter Property="IsReadOnly" Value="True"/>
            <Setter Property="HeadersVisibility" Value="Column"/>
            <Setter Property="GridLinesVisibility" Value="None"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Background" Value="White"/>
            <Setter Property="RowHeight" Value="32"/>
            <Setter Property="SelectionMode" Value="Single"/>
            <Setter Property="CanUserResizeRows" Value="False"/>
        </Style>
        <Style TargetType="DataGridColumnHeader">
            <Setter Property="Background" Value="White"/>
            <Setter Property="Foreground" Value="{StaticResource Muted}"/>
            <Setter Property="FontSize" Value="12"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="Padding" Value="10,8"/>
            <Setter Property="BorderBrush" Value="{StaticResource Line}"/>
            <Setter Property="BorderThickness" Value="0,0,0,1"/>
        </Style>
        <Style TargetType="DataGridRow">
            <Setter Property="Background" Value="White"/>
            <Style.Triggers>
                <Trigger Property="IsMouseOver" Value="True"><Setter Property="Background" Value="#F7F7F7"/></Trigger>
                <Trigger Property="IsSelected" Value="True"><Setter Property="Background" Value="#FBE5EB"/></Trigger>
            </Style.Triggers>
        </Style>
        <Style TargetType="DataGridCell">
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="FocusVisualStyle" Value="{x:Null}"/>
            <Setter Property="Foreground" Value="#1B1B1B"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="DataGridCell">
                        <Border Background="Transparent" Padding="10,0">
                            <ContentPresenter VerticalAlignment="Center"/>
                        </Border>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>
        <DataTemplate x:Key="StatusCell">
            <Border Background="{Binding StatusBack}" CornerRadius="10" Padding="9,2" HorizontalAlignment="Left">
                <TextBlock Text="{Binding Status}" Foreground="{Binding StatusFore}" FontSize="12" FontWeight="SemiBold"/>
            </Border>
        </DataTemplate>
        <DataTemplate x:Key="ActionCell">
            <Border Background="{Binding ActionBack}" CornerRadius="10" Padding="9,2" HorizontalAlignment="Left">
                <TextBlock Text="{Binding Action}" Foreground="{Binding ActionFore}" FontSize="12" FontWeight="SemiBold"/>
            </Border>
        </DataTemplate>
    </Window.Resources>

    <Grid Background="#F3F3F3">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>

        <!-- Header -->
        <Border Grid.Row="0" Background="White" BorderBrush="{StaticResource Line}" BorderThickness="0,0,0,1" Padding="24,14">
            <Grid>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>
                <Image Name="ImgBrand" Height="34" VerticalAlignment="Center" RenderOptions.BitmapScalingMode="HighQuality"/>
                <Border Grid.Column="1" BorderBrush="{StaticResource Line}" BorderThickness="1,0,0,0" Margin="20,2,0,2" Padding="20,0,0,0">
                    <StackPanel VerticalAlignment="Center">
                        <TextBlock Text="NPS Bypass Sync" FontSize="18" FontWeight="SemiBold"/>
                        <TextBlock Text="Keeps the MFA bypass policies in NPS in sync with your AD groups" Foreground="{StaticResource Muted}"/>
                    </StackPanel>
                </Border>
                <StackPanel Grid.Column="2" Orientation="Horizontal" VerticalAlignment="Center">
                    <Button Name="BtnUpdate" Margin="0,0,10,0" ToolTip="Check for a new version">
                        <StackPanel Orientation="Horizontal">
                            <TextBlock Text="&#xE896;" FontFamily="Segoe MDL2 Assets" Margin="0,1,8,0" VerticalAlignment="Center"/>
                            <TextBlock Name="TxtUpdate" Text="Update"/>
                        </StackPanel>
                    </Button>
                    <Button Name="BtnRefresh" ToolTip="Read AD and NPS again">
                        <StackPanel Orientation="Horizontal">
                            <TextBlock Text="&#xE72C;" FontFamily="Segoe MDL2 Assets" Margin="0,1,8,0" VerticalAlignment="Center"/>
                            <TextBlock Text="Refresh"/>
                        </StackPanel>
                    </Button>
                </StackPanel>
            </Grid>
        </Border>

        <Grid Grid.Row="1" Margin="24,20,24,12">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="360"/>
                <ColumnDefinition Width="20"/>
                <ColumnDefinition Width="*"/>
            </Grid.ColumnDefinitions>

            <!-- Settings -->
            <ScrollViewer Grid.Column="0" VerticalScrollBarVisibility="Auto">
                <StackPanel>
                    <Border Style="{StaticResource Card}" Margin="0,0,0,16">
                        <StackPanel>
                            <TextBlock Text="Groups" Style="{StaticResource SectionTitle}"/>
                            <TextBlock Text="Bypass groups, one per line. Members get no MFA prompt." Style="{StaticResource Label}"/>
                            <TextBox Name="TxtBypassGroups" AcceptsReturn="True" Height="64" VerticalContentAlignment="Top" VerticalScrollBarVisibility="Auto" Margin="0,0,0,12"/>
                            <TextBlock Text="Only when also in one of these groups (optional, for example your RDS access group)" Style="{StaticResource Label}"/>
                            <TextBox Name="TxtRequireGroups" AcceptsReturn="True" Height="52" VerticalContentAlignment="Top" VerticalScrollBarVisibility="Auto" Margin="0,0,0,10"/>
                            <CheckBox Name="ChkDisabled" Content="Also include disabled or expired accounts"/>
                        </StackPanel>
                    </Border>
                    <Border Style="{StaticResource Card}" Margin="0,0,0,16">
                        <StackPanel>
                            <TextBlock Text="Policies" Style="{StaticResource SectionTitle}"/>
                            <Grid Margin="0,0,0,12">
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="*"/>
                                    <ColumnDefinition Width="12"/>
                                    <ColumnDefinition Width="96"/>
                                </Grid.ColumnDefinitions>
                                <StackPanel>
                                    <TextBlock Text="Policy name" Style="{StaticResource Label}"/>
                                    <TextBox Name="TxtPrefix"/>
                                </StackPanel>
                                <StackPanel Grid.Column="2">
                                    <TextBlock Text="First number" Style="{StaticResource Label}"/>
                                    <TextBox Name="TxtFirst"/>
                                </StackPanel>
                            </Grid>
                            <TextBlock Name="TxtNameHint" Style="{StaticResource Label}" Margin="0,-6,0,12"/>
                            <TextBlock Text="Copy settings from (only when no bypass policy exists yet)" Style="{StaticResource Label}"/>
                            <ComboBox Name="CmbTemplate" IsEditable="True" Padding="6,5" Margin="0,0,0,12"/>
                            <TextBlock Text="User names to match" Style="{StaticResource Label}"/>
                            <CheckBox Name="ChkDomainSam" Content="DOMAIN\user"/>
                            <CheckBox Name="ChkSam" Content="user"/>
                            <CheckBox Name="ChkUpn" Content="user@domain.com (UPN)"/>
                            <Grid Margin="0,4,0,0">
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="*"/>
                                    <ColumnDefinition Width="12"/>
                                    <ColumnDefinition Width="*"/>
                                </Grid.ColumnDefinitions>
                                <StackPanel>
                                    <TextBlock Text="Max users (safety)" Style="{StaticResource Label}"/>
                                    <TextBox Name="TxtMaxUsers"/>
                                </StackPanel>
                                <StackPanel Grid.Column="2">
                                    <TextBlock Text="Max characters per policy" Style="{StaticResource Label}"/>
                                    <TextBox Name="TxtMaxLength"/>
                                </StackPanel>
                            </Grid>
                        </StackPanel>
                    </Border>
                    <Border Style="{StaticResource Card}">
                        <StackPanel>
                            <TextBlock Text="Automatic sync" Style="{StaticResource SectionTitle}"/>
                            <StackPanel Orientation="Horizontal" Margin="0,0,0,4">
                                <Ellipse Name="DotAuto" Width="9" Height="9" Fill="#A0A0A0" Margin="0,1,8,0" VerticalAlignment="Center"/>
                                <TextBlock Name="TxtAutoStatus" Text="Off" FontWeight="SemiBold"/>
                            </StackPanel>
                            <TextBlock Name="TxtLastSync" Style="{StaticResource Label}" Margin="0,0,0,12"/>
                            <Grid>
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="*"/>
                                    <ColumnDefinition Width="10"/>
                                    <ColumnDefinition Width="Auto"/>
                                </Grid.ColumnDefinitions>
                                <ComboBox Name="CmbInterval" Padding="6,5" VerticalContentAlignment="Center"/>
                                <Button Name="BtnAuto" Grid.Column="2" Content="Turn on"/>
                            </Grid>
                            <Button Name="BtnUpdateCopy" Margin="0,10,0,0" HorizontalAlignment="Left" Visibility="Collapsed"/>
                        </StackPanel>
                    </Border>
                </StackPanel>
            </ScrollViewer>

            <!-- Preview -->
            <Border Grid.Column="2" Style="{StaticResource Card}" Padding="0">
                <Grid>
                    <Grid.RowDefinitions>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="3*"/>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="2*"/>
                        <RowDefinition Height="Auto"/>
                    </Grid.RowDefinitions>
                    <StackPanel Margin="18,16,18,8">
                        <TextBlock Text="Users" Style="{StaticResource SectionTitle}" Margin="0,0,0,2"/>
                        <TextBlock Name="TxtSummary" Foreground="{StaticResource Muted}" TextWrapping="Wrap"/>
                        <Border Name="ProblemBox" Background="#FDF3F4" BorderBrush="#F1C9D2" BorderThickness="1" CornerRadius="6" Padding="12,8" Margin="0,10,0,0" Visibility="Collapsed">
                            <TextBlock Name="TxtProblem" Foreground="#8C0023" TextWrapping="Wrap"/>
                        </Border>
                    </StackPanel>
                    <DataGrid Name="GridUsers" Grid.Row="1" Margin="8,0,8,0">
                        <DataGrid.Columns>
                            <DataGridTemplateColumn Header="Status" CellTemplate="{StaticResource StatusCell}" Width="110" SortMemberPath="Status"/>
                            <DataGridTextColumn Header="Name" Binding="{Binding Name}" Width="1.3*"/>
                            <DataGridTextColumn Header="Account" Binding="{Binding Account}" Width="*"/>
                            <DataGridTextColumn Header="UPN" Binding="{Binding Upn}" Width="1.5*"/>
                            <DataGridTextColumn Header="Policy" Binding="{Binding Policy}" Width="90"/>
                            <DataGridTextColumn Header="Note" Binding="{Binding Note}" Width="1.2*"/>
                        </DataGrid.Columns>
                    </DataGrid>
                    <TextBlock Grid.Row="2" Text="Policies" Style="{StaticResource SectionTitle}" Margin="18,14,18,6"/>
                    <Grid Grid.Row="3" Margin="8,0,18,0">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="1.15*" MinWidth="330"/>
                            <ColumnDefinition Width="*"/>
                        </Grid.ColumnDefinitions>
                        <DataGrid Name="GridPolicies">
                            <DataGrid.Columns>
                                <DataGridTextColumn Header="Policy" Binding="{Binding Name}" Width="*" MinWidth="100"/>
                                <DataGridTemplateColumn Header="Change" CellTemplate="{StaticResource ActionCell}" Width="96"/>
                                <DataGridTextColumn Header="Users" Binding="{Binding Users}" Width="56"/>
                                <DataGridTextColumn Header="Length" Binding="{Binding Length}" Width="62"/>
                            </DataGrid.Columns>
                        </DataGrid>
                        <Grid Grid.Column="1" Margin="10,4,0,0">
                            <Grid.RowDefinitions>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="*" MinHeight="40"/>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="*" MinHeight="40"/>
                            </Grid.RowDefinitions>
                            <TextBlock Text="User Name condition (new)" Style="{StaticResource Label}"/>
                            <TextBox Name="TxtPattern" Grid.Row="1" IsReadOnly="True" TextWrapping="Wrap" FontFamily="Cascadia Mono, Consolas" FontSize="12" VerticalContentAlignment="Top" VerticalScrollBarVisibility="Auto" Margin="0,0,0,8"/>
                            <TextBlock Grid.Row="2" Text="Now in NPS" Style="{StaticResource Label}"/>
                            <TextBox Name="TxtOldPattern" Grid.Row="3" IsReadOnly="True" TextWrapping="Wrap" FontFamily="Cascadia Mono, Consolas" FontSize="12" VerticalContentAlignment="Top" VerticalScrollBarVisibility="Auto"/>
                        </Grid>
                    </Grid>
                    <Border Grid.Row="4" BorderBrush="{StaticResource Line}" BorderThickness="0,1,0,0" Padding="18,12" Margin="0,14,0,0">
                        <Grid>
                            <TextBlock Name="TxtPlan" VerticalAlignment="Center" Foreground="{StaticResource Muted}" TextWrapping="Wrap" Margin="0,0,200,0"/>
                            <StackPanel Orientation="Horizontal" HorizontalAlignment="Right">
                                <Button Name="BtnSave" Content="Save settings" Margin="0,0,10,0"/>
                                <Button Name="BtnSync" Style="{StaticResource AccentButton}" Content="Sync now"/>
                            </StackPanel>
                        </Grid>
                    </Border>
                </Grid>
            </Border>
        </Grid>

        <!-- Activity log -->
        <Border Grid.Row="2" Background="White" BorderBrush="{StaticResource Line}" BorderThickness="0,1,0,0" Padding="24,8,24,10">
            <StackPanel>
                <Grid Margin="0,0,0,4">
                    <TextBlock Text="Activity" Foreground="{StaticResource Muted}" FontSize="12" FontWeight="SemiBold"/>
                    <TextBlock Name="TxtStatus" Foreground="{StaticResource Muted}" FontSize="12" HorizontalAlignment="Right"/>
                </Grid>
                <TextBox Name="TxtLog" IsReadOnly="True" Height="96" FontFamily="Cascadia Mono, Consolas" FontSize="11.5" VerticalScrollBarVisibility="Auto" VerticalContentAlignment="Top" BorderThickness="0" Padding="0"/>
            </StackPanel>
        </Border>

        <!-- Busy overlay -->
        <Grid Name="Overlay" Grid.RowSpan="3" Background="#66000000" Visibility="Collapsed">
            <Border Name="BusyCard" Style="{StaticResource Card}" Width="440" HorizontalAlignment="Center" VerticalAlignment="Center" Padding="26,22">
                <Border.Effect><DropShadowEffect BlurRadius="24" ShadowDepth="4" Opacity="0.15"/></Border.Effect>
                <StackPanel>
                    <TextBlock Name="TxtBusyTitle" FontSize="16" FontWeight="SemiBold" Margin="0,0,0,6"/>
                    <TextBlock Name="TxtBusyStep" Foreground="{StaticResource Muted}" TextWrapping="Wrap" Margin="0,0,0,14"/>
                    <ProgressBar Name="PrgBusy" Height="4" IsIndeterminate="True" Foreground="#C80032" BorderThickness="0" Background="#F1F1F1"/>
                </StackPanel>
            </Border>
        </Grid>
    </Grid>
</Window>
'@

$window = [Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader $xaml))
$ui = @{}
foreach ($node in $xaml.SelectNodes('//*[@Name]')) { $ui[$node.Name] = $window.FindName($node.Name) }

# Raw .NET values for data binding (PowerShell's PSObject wrapper breaks image/brush bindings).
function ConvertTo-Brush
{
    param ([string]$Color)
    $brush = [Windows.Media.Brush](New-Object Windows.Media.BrushConverter).ConvertFromString($Color)
    $brush.Freeze()
    return , $brush
}

function New-Bitmap
{
    param ([string]$Path)
    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return $null }
    $bmp = New-Object Windows.Media.Imaging.BitmapImage
    $bmp.BeginInit()
    $bmp.CacheOption = 'OnLoad'
    $bmp.UriSource = New-Object Uri $Path
    $bmp.EndInit()
    $bmp.Freeze()
    return $bmp
}

$ui.ImgBrand.Source = New-Bitmap (Join-Path $Ctx.BrandingDir 'connectify-icon.png')
$window.Icon = New-Bitmap (Join-Path $Ctx.BrandingDir 'connectify-icon.png')
if ($ToolVersion) { $window.Title = "NPS Bypass Sync $ToolVersion" }

$Colors = @{
    'New'       = @((ConvertTo-Brush '#DFF6DD'), (ConvertTo-Brush '#0E700E'))
    'In NPS'    = @((ConvertTo-Brush '#EEF0F3'), (ConvertTo-Brush '#3B3B3B'))
    'Removed'   = @((ConvertTo-Brush '#FDE7E9'), (ConvertTo-Brush '#A4262C'))
    'Skipped'   = @((ConvertTo-Brush '#FFF4CE'), (ConvertTo-Brush '#7A5B00'))
    'Create'    = @((ConvertTo-Brush '#DFF6DD'), (ConvertTo-Brush '#0E700E'))
    'Update'    = @((ConvertTo-Brush '#E5F1FB'), (ConvertTo-Brush '#0F5A9E'))
    'Delete'    = @((ConvertTo-Brush '#FDE7E9'), (ConvertTo-Brush '#A4262C'))
    'No change' = @((ConvertTo-Brush '#EEF0F3'), (ConvertTo-Brush '#3B3B3B'))
}
foreach ($m in 5, 10, 15, 30, 60) { [void]$ui.CmbInterval.Items.Add("Every $m minutes") }
#endregion

#region Settings <-> window
function Set-ConfigOnWindow
{
    param ($Config)
    $ui.TxtBypassGroups.Text = (@($Config.BypassGroups) -join "`r`n")
    $ui.TxtRequireGroups.Text = (@($Config.RequireGroups) -join "`r`n")
    $ui.ChkDisabled.IsChecked = [bool]$Config.IncludeDisabled
    $ui.TxtPrefix.Text = "$($Config.PolicyPrefix)"
    $ui.TxtFirst.Text = "$($Config.FirstNumber)"
    $ui.CmbTemplate.Text = "$($Config.TemplatePolicy)"
    $ui.ChkDomainSam.IsChecked = [bool]$Config.MatchDomainSam
    $ui.ChkSam.IsChecked = [bool]$Config.MatchSam
    $ui.ChkUpn.IsChecked = [bool]$Config.MatchUpn
    $ui.TxtMaxUsers.Text = "$($Config.MaxUsers)"
    $ui.TxtMaxLength.Text = "$($Config.MaxLength)"
    $minutes = @(5, 10, 15, 30, 60)
    $idx = [array]::IndexOf($minutes, [int]$Config.IntervalMinutes)
    $ui.CmbInterval.SelectedIndex = if ($idx -ge 0) { $idx } else { 2 }
    Update-NameHint
}

function Get-ConfigFromWindow
{
    $config = Get-Config
    $split = { param ($t) @("$t" -split "[\r\n;]+" | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
    $config.BypassGroups = & $split $ui.TxtBypassGroups.Text
    $config.RequireGroups = & $split $ui.TxtRequireGroups.Text
    $config.IncludeDisabled = [bool]$ui.ChkDisabled.IsChecked
    $config.PolicyPrefix = $ui.TxtPrefix.Text.Trim()
    $n = 0
    if (-not [int]::TryParse($ui.TxtFirst.Text.Trim(), [ref]$n)) { throw 'First number must be a number.' }
    $config.FirstNumber = $n
    $config.TemplatePolicy = "$($ui.CmbTemplate.Text)".Trim()
    $config.MatchDomainSam = [bool]$ui.ChkDomainSam.IsChecked
    $config.MatchSam = [bool]$ui.ChkSam.IsChecked
    $config.MatchUpn = [bool]$ui.ChkUpn.IsChecked
    if (-not [int]::TryParse($ui.TxtMaxUsers.Text.Trim(), [ref]$n)) { throw 'Max users must be a number.' }
    $config.MaxUsers = $n
    if (-not [int]::TryParse($ui.TxtMaxLength.Text.Trim(), [ref]$n)) { throw 'Max characters must be a number.' }
    $config.MaxLength = $n
    $config.IntervalMinutes = @(5, 10, 15, 30, 60)[[Math]::Max(0, $ui.CmbInterval.SelectedIndex)]
    return $config
}

function Update-NameHint
{
    $prefix = $ui.TxtPrefix.Text.Trim()
    $n = 0
    if (-not [int]::TryParse($ui.TxtFirst.Text.Trim(), [ref]$n)) { $n = 2 }
    $ui.TxtNameHint.Text = "Managed: $prefix$n, $prefix$($n + 1), ... Other policies are never touched."
}
$ui.TxtPrefix.Add_TextChanged({ Update-NameHint })
$ui.TxtFirst.Add_TextChanged({ Update-NameHint })
#endregion

#region Background jobs
$Shared = [hashtable]::Synchronized(@{
    Log  = New-Object 'System.Collections.Concurrent.ConcurrentQueue[string]'
    Step = ''
})
$Job = $null
$WorkerBootstrap = @'
param ($Code, $Command, $Arguments, $Shared, $Ctx)
$ErrorActionPreference = 'Stop'
. ([scriptblock]::Create($Code))
& $Command @Arguments
'@

function Show-Error
{
    param ($ErrorObject, [string]$Title = 'Something went wrong')
    $msg = if ($ErrorObject -is [Management.Automation.ErrorRecord]) { $ErrorObject.Exception.Message } elseif ($ErrorObject -is [Exception]) { $ErrorObject.Message } else { "$ErrorObject" }
    Write-Log $msg 'ERROR'
    [void][Windows.MessageBox]::Show($window, $msg, $Title, 'OK', 'Error')
}

function Start-Work
{
    param ([string]$Title, [string]$Command, [hashtable]$Arguments = @{}, [scriptblock]$OnDone)
    if ($script:Job) { return }
    $rs = [runspacefactory]::CreateRunspace()
    $rs.ApartmentState = 'STA'
    $rs.ThreadOptions = 'ReuseThread'
    $rs.Open()
    $ps = [powershell]::Create()
    $ps.Runspace = $rs
    [void]$ps.AddScript($WorkerBootstrap).AddArgument($WorkerCodeText).AddArgument($Command).AddArgument($Arguments).AddArgument($Shared).AddArgument($Ctx)
    $Shared.Step = ''
    $ui.TxtBusyTitle.Text = $Title
    $ui.TxtBusyStep.Text = ''
    $ui.Overlay.Visibility = 'Visible'
    $ui.TxtStatus.Text = $Title
    $script:Job = @{ PS = $ps; RS = $rs; Handle = $ps.BeginInvoke(); OnDone = $OnDone }
}

function Complete-Work
{
    $job = $script:Job
    $script:Job = $null
    $value = $null
    $failure = $null
    try
    {
        $output = $job.PS.EndInvoke($job.Handle)
        $value = @($output | Where-Object { $_ -and $_.PSObject.Properties['__Result'] }) | Select-Object -Last 1
        if (-not $value) { $failure = 'The task finished without a result. See the activity log.' }
    }
    catch
    {
        $ex = $_.Exception
        while ($ex.InnerException) { $ex = $ex.InnerException }
        $failure = $ex.Message
    }
    foreach ($e in $job.PS.Streams.Error) { Write-Log "$e" 'WARN' }
    $job.PS.Dispose()
    $job.RS.Dispose()
    $ui.Overlay.Visibility = 'Collapsed'
    $ui.TxtStatus.Text = ''
    & $job.OnDone $value $failure
}

$timer = New-Object Windows.Threading.DispatcherTimer
$timer.Interval = [TimeSpan]::FromMilliseconds(120)
$timer.Add_Tick({
    try
    {
        $line = $null
        $sb = New-Object Text.StringBuilder
        while ($Shared.Log.TryDequeue([ref]$line)) { [void]$sb.AppendLine($line) }
        if ($sb.Length)
        {
            $ui.TxtLog.AppendText($sb.ToString())
            $ui.TxtLog.ScrollToEnd()
        }
        if ($script:UpdateCheck -and $script:UpdateCheck.Handle.IsCompleted) { Complete-UpdateCheck }
        if ($script:Job)
        {
            $ui.TxtBusyStep.Text = $Shared.Step
            if ($script:Job.Handle.IsCompleted) { Complete-Work }
        }
    }
    catch { Show-Error $_ }
})
#endregion

#region Overview
$Plan = $null
$Auto = $null

function Show-AutoStatus
{
    param ($Status)
    $script:Auto = $Status
    if (-not $Status) { return }
    if ($Status.Enabled)
    {
        $ui.TxtAutoStatus.Text = "On, every $($Status.Interval) minutes"
        $idx = [array]::IndexOf(@(5, 10, 15, 30, 60), [int]$Status.Interval)
        if ($idx -ge 0) { $ui.CmbInterval.SelectedIndex = $idx }
        $ui.DotAuto.Fill = [Windows.Media.Brush](ConvertTo-Brush '#107C10')
        $ui.BtnAuto.Content = 'Turn off'
    }
    else
    {
        $ui.TxtAutoStatus.Text = 'Off'
        $ui.DotAuto.Fill = [Windows.Media.Brush](ConvertTo-Brush '#A0A0A0')
        $ui.BtnAuto.Content = 'Turn on'
    }
    $last = ''
    if ($Status.LastSync)
    {
        $when = $Status.LastSync
        try { $when = ([datetime]$Status.LastSync).ToString('g') } catch { }
        $last = "Last sync: $when, $($Status.LastResult)"
    }
    else { $last = 'No sync has run on this server yet.' }
    $ui.TxtLastSync.Text = $last
    $outdated = $Status.InstalledVersion -and $ToolVersion -and $Status.InstalledVersion -ne $ToolVersion
    $ui.BtnUpdateCopy.Visibility = if ($outdated) { 'Visible' } else { 'Collapsed' }
    $ui.BtnUpdateCopy.Content = "Automatic sync uses $($Status.InstalledVersion), switch to $ToolVersion"
}

function Show-Overview
{
    param ($Result)
    $names = @($Result.PolicyNames)
    $typed = $ui.CmbTemplate.Text
    $ui.CmbTemplate.ItemsSource = $names
    $ui.CmbTemplate.Text = $typed
    Show-AutoStatus $Result.Auto
    $script:Plan = $Result.Plan

    if ($Result.Problem)
    {
        $ui.TxtProblem.Text = $Result.Problem
        $ui.ProblemBox.Visibility = 'Visible'
    }
    else { $ui.ProblemBox.Visibility = 'Collapsed' }

    $plan = $Result.Plan
    if (-not $plan)
    {
        $ui.GridUsers.ItemsSource = $null
        $ui.GridPolicies.ItemsSource = $null
        $ui.TxtSummary.Text = 'Set the bypass group(s) and click Save settings.'
        $ui.TxtPlan.Text = ''
        $ui.BtnSync.IsEnabled = $false
        return
    }

    $rows = foreach ($u in $plan.Users)
    {
        $c = $Colors[$u.Status]
        [pscustomobject]@{ Status = $u.Status; StatusBack = [Windows.Media.Brush]$c[0]; StatusFore = [Windows.Media.Brush]$c[1]; Name = $u.Name; Account = $u.Account; Upn = $u.Upn; Policy = $u.Policy; Note = $u.Note }
    }
    $ui.GridUsers.ItemsSource = @($rows | Sort-Object -Property @{ Expression = { @('New', 'Removed', 'Skipped', 'In NPS').IndexOf($_.Status) } }, Account)
    $policyRows = foreach ($p in $plan.Policies)
    {
        $c = $Colors[$p.Action]
        [pscustomobject]@{ Name = $p.Name; Action = $p.Action; ActionBack = [Windows.Media.Brush]$c[0]; ActionFore = [Windows.Media.Brush]$c[1]; Users = $p.Users; Length = $p.Length; Pattern = $p.Pattern; OldPattern = $p.OldPattern }
    }
    $ui.GridPolicies.ItemsSource = @($policyRows)
    if (@($policyRows).Count) { $ui.GridPolicies.SelectedIndex = 0 }

    $count = { param ($s) @($plan.Users | Where-Object Status -eq $s).Count }
    $ui.TxtSummary.Text = "$($plan.Count) user(s) get the bypass: $(& $count 'New') new, $(& $count 'In NPS') already in NPS. $(& $count 'Removed') removed, $(& $count 'Skipped') skipped."
    if ($plan.HasChanges)
    {
        $parts = @()
        foreach ($a in 'Create', 'Update', 'Delete')
        {
            $n = @($plan.Policies | Where-Object Action -eq $a).Count
            if ($n) { $parts += "$n to $($a.ToLower())" }
        }
        if (-not $parts.Count) { $parts += 'processing order to fix' }
        $ui.TxtPlan.Text = "Policies: $($parts -join ', '). A backup is made first."
        $ui.BtnSync.IsEnabled = $true
    }
    else
    {
        $ui.TxtPlan.Text = 'NPS is up to date.'
        $ui.BtnSync.IsEnabled = $true
    }
}

$ui.GridPolicies.Add_SelectionChanged({
    $row = $ui.GridPolicies.SelectedItem
    $ui.TxtPattern.Text = if ($row) { "$($row.Pattern)" } else { '' }
    $ui.TxtOldPattern.Text = if ($row) { "$($row.OldPattern)" } else { '' }
})

function Start-Overview
{
    param ($Config)
    $args2 = @{}
    if ($Config) { $args2.Config = $Config }
    Start-Work -Title 'Reading AD and NPS...' -Command 'Get-Overview' -Arguments $args2 -OnDone {
        param ($result, $failure)
        if ($failure) { Show-Error $failure 'Could not read AD or NPS'; return }
        Show-Overview $result
        if ($Screenshot) { Invoke-ScreenshotReady }
    }
}

$ui.BtnRefresh.Add_Click({ try { Start-Overview -Config (Get-ConfigFromWindow) } catch { Show-Error $_ } })

$ui.BtnSave.Add_Click({
    try
    {
        $config = Get-ConfigFromWindow
        [void](Save-Config $config)
        Start-Overview -Config $config
    }
    catch { Show-Error $_ 'Settings not saved' }
})

$ui.BtnSync.Add_Click({
    try
    {
        $config = Get-ConfigFromWindow
        Test-Config $config
        if ($script:Plan -and $script:Plan.HasChanges)
        {
            $new = @($script:Plan.Users | Where-Object Status -eq 'New' | ForEach-Object Account)
            $gone = @($script:Plan.Users | Where-Object Status -eq 'Removed' | ForEach-Object Account)
            $text = "Write the bypass policies to NPS now?`n`n$($script:Plan.Count) user(s) in $(@($script:Plan.Desired).Count) policy(ies)."
            if ($new.Count) { $text += "`nNew: $(($new | Select-Object -First 15) -join ', ')$(if ($new.Count -gt 15) { ', ...' })" }
            if ($gone.Count) { $text += "`nRemoved: $(($gone | Select-Object -First 15) -join ', ')$(if ($gone.Count -gt 15) { ', ...' })" }
            $text += "`n`nThe settings are saved too. A backup of the NPS configuration is made first."
            if ("$([Windows.MessageBox]::Show($window, $text, 'NPS Bypass Sync', 'YesNo', 'Question'))" -ne 'Yes') { return }
        }
        [void](Save-Config $config)
        Start-Work -Title 'Syncing...' -Command 'Invoke-NpsSync' -Arguments @{ Config = $config } -OnDone {
            param ($result, $failure)
            if ($failure) { Show-Error $failure 'Sync failed'; Start-Overview; return }
            $msg = if ($result.Changed) { "Done. $($result.Users) user(s) in $($result.Policies) policy(ies). NPS uses them within about 30 seconds.`n`nBackup: $($result.Backup)" } else { "Nothing to change. $($result.Users) user(s) in $($result.Policies) policy(ies)." }
            [void][Windows.MessageBox]::Show($window, $msg, 'NPS Bypass Sync', 'OK', 'Information')
            Start-Overview
        }
    }
    catch { Show-Error $_ }
})

$ui.BtnAuto.Add_Click({
    try
    {
        if ($script:Auto -and $script:Auto.Enabled)
        {
            if ("$([Windows.MessageBox]::Show($window, 'Turn off automatic sync? The scheduled task is removed. The bypass policies stay as they are.', 'NPS Bypass Sync', 'YesNo', 'Question'))" -ne 'Yes') { return }
            Start-Work -Title 'Turning off automatic sync...' -Command 'Disable-AutoSync' -OnDone {
                param ($result, $failure)
                if ($failure) { Show-Error $failure; return }
                Show-AutoStatus $result
            }
            return
        }
        if (-not $LauncherPath) { Show-Error 'Automatic sync works from NpsBypassSync.exe, not from the script.'; return }
        $config = Get-ConfigFromWindow
        Test-Config $config
        [void](Save-Config $config)
        $minutes = [int]$config.IntervalMinutes
        $text = "Turn on automatic sync every $minutes minutes?`n`nThe exe is copied to $($Ctx.InstallDir) and a scheduled task '$($Ctx.TaskName)' runs it as SYSTEM. It only changes NPS when the groups changed. Changes and errors go to the Application event log (source '$($Ctx.EventSource)')."
        if ("$([Windows.MessageBox]::Show($window, $text, 'NPS Bypass Sync', 'YesNo', 'Question'))" -ne 'Yes') { return }
        Start-Work -Title 'Turning on automatic sync...' -Command 'Enable-AutoSync' -Arguments @{ Minutes = $minutes } -OnDone {
            param ($result, $failure)
            if ($failure) { Show-Error $failure; return }
            Show-AutoStatus $result
        }
    }
    catch { Show-Error $_ }
})

$ui.CmbInterval.Add_SelectionChanged({
    try
    {
        if (-not ($script:Auto -and $script:Auto.Enabled) -or $script:Job -or -not $window.IsLoaded) { return }
        $minutes = @(5, 10, 15, 30, 60)[[Math]::Max(0, $ui.CmbInterval.SelectedIndex)]
        if ($minutes -eq $script:Auto.Interval) { return }
        Start-Work -Title 'Changing the interval...' -Command 'Enable-AutoSync' -Arguments @{ Minutes = $minutes } -OnDone {
            param ($result, $failure)
            if ($failure) { Show-Error $failure; return }
            Show-AutoStatus $result
        }
    }
    catch { Show-Error $_ }
})

$ui.BtnUpdateCopy.Add_Click({
    Start-Work -Title 'Updating the automatic sync copy...' -Command 'Update-InstalledCopy' -OnDone {
        param ($result, $failure)
        if ($failure) { Show-Error $failure; return }
        Show-AutoStatus $result
    }
})
#endregion

#region App update
$UpdateInfo = $null
$UpdateCheck = $null

function Start-UpdateCheck
{
    # Quiet check in the background at start; only the button text changes.
    if (-not $ToolVersion) { return }
    $ps = [powershell]::Create()
    [void]$ps.AddScript($WorkerBootstrap).AddArgument($WorkerCodeText).AddArgument('Get-LatestRelease').AddArgument(@{}).AddArgument($null).AddArgument($Ctx)
    $script:UpdateCheck = @{ PS = $ps; Handle = $ps.BeginInvoke() }
}

function Complete-UpdateCheck
{
    $check = $script:UpdateCheck
    $script:UpdateCheck = $null
    try
    {
        $info = @($check.PS.EndInvoke($check.Handle)) | Where-Object { $_ -and $_.PSObject.Properties['__Result'] } | Select-Object -Last 1
        if ($info)
        {
            $script:UpdateInfo = $info
            if ($info.Newer)
            {
                $ui.TxtUpdate.Text = "Update to $($info.Tag)"
                $ui.BtnUpdate.BorderBrush = [Windows.Media.Brush](ConvertTo-Brush '#C80032')
                Write-Log "A new version is available: $($info.Tag) (this is $ToolVersion)."
            }
        }
    }
    catch { }
    finally { $check.PS.Dispose() }
}

function Start-AppUpdate
{
    param ($Info)
    $answer = [Windows.MessageBox]::Show($window, "Version $($Info.Tag) is available (you have $($Info.Current)).`n`nUpdate now? NPS Bypass Sync restarts afterwards. The automatic sync copy is updated too.", 'NPS Bypass Sync', 'YesNo', 'Question')
    if ("$answer" -ne 'Yes') { return }
    Start-Work -Title "Updating to $($Info.Tag)..." -Command 'Install-AppUpdate' -Arguments @{ Url = $Info.Url; Tag = $Info.Tag } -OnDone {
        param ($result, $failure)
        if ($failure) { Show-Error $failure 'Update failed'; return }
        if ($result.Restart)
        {
            Start-Process -FilePath $result.Restart
            $window.Close()
            return
        }
        [void][Windows.MessageBox]::Show($window, "The new version could not replace this one here (no write access?).`n`nIt was saved to:`n$($result.SavedTo)`n`nCopy it over the old NpsBypassSync.exe.", 'NPS Bypass Sync', 'OK', 'Information')
    }
}

$ui.BtnUpdate.Add_Click({
    try
    {
        if (-not $ToolVersion)
        {
            [void][Windows.MessageBox]::Show($window, 'Updating works from NpsBypassSync.exe. This copy runs as a script.', 'NPS Bypass Sync', 'OK', 'Information')
            return
        }
        if ($script:UpdateInfo -and $script:UpdateInfo.Newer) { Start-AppUpdate $script:UpdateInfo; return }
        Start-Work -Title 'Checking for updates...' -Command 'Get-LatestRelease' -OnDone {
            param ($result, $failure)
            if ($failure) { Show-Error $failure 'Could not check for updates'; return }
            $script:UpdateInfo = $result
            if ($result.Newer) { Start-AppUpdate $result }
            else { [void][Windows.MessageBox]::Show($window, "You have the latest version ($ToolVersion).", 'NPS Bypass Sync', 'OK', 'Information') }
        }
    }
    catch { Show-Error $_ }
})
#endregion

#region Screenshot self-test
function Save-WindowImage
{
    param ([string]$Path)
    $window.UpdateLayout()
    $source = [Windows.PresentationSource]::FromVisual($window)
    $scale = if ($source) { $source.CompositionTarget.TransformToDevice.M11 } else { 1 }
    $content = $window.Content
    $rtb = [Windows.Media.Imaging.RenderTargetBitmap]::new([int]($content.ActualWidth * $scale), [int]($content.ActualHeight * $scale), [double](96 * $scale), [double](96 * $scale), [Windows.Media.PixelFormats]::Pbgra32)
    $rtb.Render($content)
    $enc = New-Object Windows.Media.Imaging.PngBitmapEncoder
    $enc.Frames.Add([Windows.Media.Imaging.BitmapFrame]::Create($rtb))
    $fs = [IO.File]::Create($Path)
    try { $enc.Save($fs) } finally { $fs.Dispose() }
}

function Invoke-ScreenshotReady
{
    $t = New-Object Windows.Threading.DispatcherTimer
    $t.Interval = [TimeSpan]::FromMilliseconds(800)
    $t.Add_Tick({
        $this.Stop()
        try { Save-WindowImage "$Screenshot-ready.png" } catch { Write-Log "Screenshot failed: $_" 'ERROR' }
        $window.Close()
    })
    $t.Start()
}
#endregion

try { Initialize-DataDir } catch { }
Set-ConfigOnWindow (Get-Config)

$window.Add_ContentRendered({
    try
    {
        if ($OnReady) { try { $OnReady.Invoke() } catch { } }
        $window.Activate() | Out-Null
        $timer.Start()
        Start-Overview
        Start-UpdateCheck
    }
    catch { Show-Error $_ }
})

Write-Log "NPS Bypass Sync started. Running as $([Security.Principal.WindowsIdentity]::GetCurrent().Name)."
[void]$window.ShowDialog()
$timer.Stop()

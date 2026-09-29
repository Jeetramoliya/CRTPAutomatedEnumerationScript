# Setup — what to run BEFORE Invoke-CRTPEnum

> The tool binaries are **not** bundled in this repo (they're licensed/offensive tooling and
> the repo is public). Keep them in your own `D:\CRTP\Tools\` from the course Tools.zip.
> This folder just automates loading them and lists what you need.

## Order of operations

```
1) InviShell           -> D:\CRTP\Tools\InviShell\RunWithRegistryNonAdmin.bat   (AMSI/logging coverage for PS)
2) (optional) bypass   -> Amsi-Byp.txt ; sbloggingbypass.txt                    (only if loading other .ps1)
3) Load prerequisites  -> . .\Setup\Load-CRTPTools.ps1                          (imports the PS modules)
4) Run the enum        -> . .\Invoke-CRTPEnum.ps1
                          Invoke-CRTPEnum -Domain dollarcorp.moneycorp.local -OutDir C:\Users\Public\loot
5) Exploit (later)     -> run the .EXE tools via Loader, using the commands the enum wrote
```

## Required BEFORE the script (loaded by `Load-CRTPTools.ps1`)

| Purpose | File | Needed for |
|--------|------|-----------|
| Run PS un-logged | `InviShell\RunWithRegistryNonAdmin.bat` | AMSI + ScriptBlock-logging coverage (run the shell first) |
| Real AD cmdlets (no RSAT) | `ADModule-master\Microsoft.ActiveDirectory.Management.dll` (+ `ActiveDirectory.psd1`) | richest sections 01–06; else raw-LDAP fallback |
| Domain recon | `PowerView.ps1` | ACLs (07), local-admin (08), shares (12), cross-trust (16), GPO-admin (17) |
| Local privesc | `PowerUp.ps1` | section 13 (`Invoke-PrivescAudit`, cached GPP) |
| Share hunt | `PowerHuntShares.psm1` | alt share hunt |
| Attack-path correlation | `Invoke-SessionHunter.ps1` | section 14 (admin × privileged sessions) |
| EDR/AV recon | `Invoke-EDRChecker.ps1` | section 00b |
| MSSQL crawl | `PowerUpSQL-master\PowerUpSQL.psd1` | section 18 (`-SQLCrawl`) |

> **None are strictly required** — with nothing loaded the script still runs on raw LDAP.
> Loading them just unlocks the extra sections. `Load-CRTPTools.ps1` prints a capability
> check so you can see what's active.

## Needed AFTER the script (exploitation — run via **Loader**, not this script)

These are what the enum's `EXPLOIT_COMMANDS.txt` / `ATTACK_CHAIN.txt` tell you to run. Load
compiled `.exe` assemblies in memory with **Loader** to evade Defender:

| Tool | Used for |
|------|---------|
| `Rubeus.exe` | kerberoast / asreproast / s4u (constrained/RBCD delegation) |
| `SafetyKatz.exe` | **OverPass-the-Hash** (exam-preferred over Rubeus), LSASS, DCSync |
| `SharpHound.exe` | BloodHound collection (`-BloodHound`) — GUI stays on your host |
| `Certify.exe` | AD CS / ESC1 |
| `MS-RPRN.exe` / `WSPCoerce.exe` / `DFSCoerce-andrea.exe` | coercion for unconstrained delegation |
| `Get-RBCD-Threaded.exe` | RBCD |
| `minidumpdotnet.exe` / `FindLSASSPID.exe` | LSASS dump |
| `winPEAS-obfuscated.exe` | deep local triage (`-WinPEASPath`) |

## Two evasion layers (don't mix them up)

```
InviShell  -> the PowerShell script (Invoke-CRTPEnum.ps1)         [needed to run the script quietly]
Loader     -> the compiled .EXE tools you fire afterward          [exam-recommended, evades Defender]
```

Loader loads .NET **assemblies**, not PowerShell scripts — so it's for the `.exe`s, not for this `.ps1`.

## Reminder
The script + these files are a **doing aid**. Your exam **report must be your own words**
explaining *why* each step works — AI-generated report text is rejected.

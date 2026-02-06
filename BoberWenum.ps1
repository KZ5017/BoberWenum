<#
BoberWenum.ps1
Passive Active Directory situational awareness enumerator
Read-only | Stable | AD-aware | Non-offensive
#>
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
# ----------------------------
# Output Transcript (Console + File)
# ----------------------------
$BasePath = Split-Path -Parent $MyInvocation.MyCommand.Path
$LogPath  = Join-Path $BasePath ("BoberWenum_" + (Get-Date -Format "yyyyMMdd_HHmmss") + ".log")

try {
    Start-Transcript -Path $LogPath -Force | Out-Null
    Write-Host "[INFO] Output is being logged to:"
    Write-Host "       $LogPath"
} catch {
    Write-Host "[WARN] Failed to start transcript logging."
}

$ErrorActionPreference = "SilentlyContinue"

$banner = @"

                           #########                                       
                #####   ###         ###    #####                           
              ##     ####              ####    ##                          
              ##  ##                        ##  ##                         
               ##       ###         ###        ##                          
                 ##                         ##                             
                ##      ###         ###      ##                            
               ##       ###         ###       ##                           
               #                                #                          
              #             #######             ##                         
             #             #       ##            #                         
              ##     ##    ##     ##   ###      ##                         
              ##      ##     #####     ##       ##                         
              ##       ###     ##     ##        #      #######             
               #          ##### #####          ##    ##       ###          
                #           # # ###           ##    #    ## ##  ###        
                #           #######           ##   ##      ##     ##       
              ###                              ##  ##  ####  ## ## ##      
             ##                                  ###   ####   ##    #      
            ##                 #                  #   ##  ####  ##  ##     
           ##        ##   ###      ###   ##        ##  ##  ###    # ##     
           #          ####            ###           #   ###   ####  ##     
          ##  ##       ##              ##       ##  ## ## ##  ####  ##     
          #    ##       #             ##       ##   ##     ####    ##      
         ##      ##   ###             ####  ###      #  ## ####   ###      
         ##         ####                ####         #   ###      #        
         ##          #                   ##          #  ## ##   ##         
         ##          #                   ##          #         ##          
          ##         #                   ##         ##      ###            
          ##   #######                   ########   #     ###              
            ###      ##                 ###      #########                 
           ##   ## #  ###################  #  #   ##                       
            ############                ###########                   
    ____        _             __        __                         
    | __ )  ___ | |__   ___ _ _\ \      / /__ _ __  _   _ _ __ ___  
    |  _ \ / _ \| '_ \ / _ \ '__\ \ /\ / / _ \ '_ \| | | | '_ ` _ \ 
    | |_) | (_) | |_) |  __/ |   \ V  V /  __/ | | | |_| | | | | | |
    |____/ \___/|_.__/ \___|_|    \_/\_/ \___|_| |_|\__,_|_| |_| |_|
"@

Write-Host $banner

Write-Host ""
Write-Host "==============================================="
Write-Host " BoberWenum execution started"
Write-Host " Time   : $(Get-Date)"
Write-Host " User   : $(whoami)"
Write-Host " Host   : $env:COMPUTERNAME"
Write-Host "==============================================="
Write-Host ""


# ----------------------------
# Helper: Safe execution block
# ----------------------------

function Write-Phase {
    param([string]$Name)

    Write-Host ""
    Write-Host "##################################################"
    Write-Host "# $Name"
    Write-Host "##################################################"
}

function Invoke-Safe {
    param (
        [string]$Title,
        [scriptblock]$Block
    )
    Write-Host "`n=============================="
    Write-Host "[+] $Title"
    Write-Host "=============================="
    try {
        & $Block
    } catch {
        Write-Host "[!] Failed to enumerate: $Title"
    }
}

Write-Phase "IDENTITY & EXECUTION CONTEXT"

# ----------------------------
# Identity Context
# ----------------------------
Invoke-Safe "Identity Context (Who am I?)" {
    Write-Host ""
    Write-Host "User          : $(whoami)"
    Write-Host "User SID      : $([System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value)"

    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($id)

    Write-Host "Is Admin      : $($principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator))"
    Write-Host "Auth Type     : $($id.AuthenticationType)"
    Write-Host "Token Type    : $($id.ImpersonationLevel)"
    Write-Host ""
    Write-Host "----------------------------------------"
    Write-Host "Group Memberships:"
    Write-Host "----------------------------------------"
    $(whoami /groups)
}

# ----------------------------
# Local Privileges (Extended)
# ----------------------------
Invoke-Safe "Local Privileges" {
    Write-Host ""    

    Write-Host '[*] Raw privilege list (whoami /priv)'
    $(whoami /priv)

    Write-Host ''
    Write-Host '[*] Privilege risk analysis'

    # Dangerous privilege mapping
    $dangerousPrivileges = @{
        'SeDebugPrivilege'              = 'Read/write any process memory (SYSTEM escalation).'
        'SeImpersonatePrivilege'        = 'Token impersonation (Juicy/PrintSpoofer style vectors).'
        'SeAssignPrimaryTokenPrivilege' = 'Spawn processes with arbitrary tokens.'
        'SeBackupPrivilege'             = 'Read any file ignoring ACLs (NTDS, SAM, secrets).'
        'SeRestorePrivilege'            = 'Write any file ignoring ACLs (overwrite system files).'
        'SeTakeOwnershipPrivilege'      = 'Take ownership of objects (privilege takeover).'
        'SeLoadDriverPrivilege'         = 'Load kernel drivers (ring-0 execution).'
        'SeCreateTokenPrivilege'        = 'Create arbitrary tokens (full impersonation).'
        'SeTcbPrivilege'                = 'Act as part of the OS (highest possible trust).'
    }

    # Execute whoami /priv safely and capture output
    try {
        $privOutput = whoami /priv 2>$null
    } catch {
        Write-Host '  [INFO] Unable to enumerate privileges.'
        return
    }

    if (-not $privOutput) {
        Write-Host '  [INFO] No privilege information returned.'
        return
    }

    $found = $false

    foreach ($line in $privOutput) {
        foreach ($priv in $dangerousPrivileges.Keys) {
            if ($line -match $priv -and $line -match 'Enabled') {
                if (-not $found) {
                    Write-Host '  [!] Potentially dangerous privileges enabled:'
                    $found = $true
                }

                Write-Host "    [HIGH] $priv"
                Write-Host "           -> $($dangerousPrivileges[$priv])"
            }
        }
    }

    if (-not $found) {
        Write-Host '  [OK] No dangerous privileges enabled for this user.'
    }
}

Write-Phase "HOST & OPERATING SYSTEM CONTEXT"

# ----------------------------
# Host Context (Low-Priv Safe)
# ----------------------------
Invoke-Safe "Host Context (Where am I?)" {

    Write-Host ""

    # ----------------------------
    # Basic host identity
    # ----------------------------
    Write-Host "Hostname      : $env:COMPUTERNAME"

    # ----------------------------
    # Domain context (registry + env)
    # ----------------------------
    $domainJoined = "Unknown"
    $domainName   = "Unknown"

    try {
        $csReg = Get-ItemProperty `
            'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'

        if ($csReg.Domain -or $csReg.NV_Domain) {
            $domainJoined = $true
            $domainName   = if ($csReg.Domain) { $csReg.Domain } else { $csReg.NV_Domain }
        } else {
            $domainJoined = $false
        }
    } catch {}

    Write-Host "Domain Joined : $domainJoined"
    Write-Host "Domain        : $domainName"

    # ----------------------------
    # OS information (registry)
    # ----------------------------
    try {
        $osReg = Get-ItemProperty `
            'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'

        Write-Host "OS            : $($osReg.ProductName)"
        Write-Host "OS Version    : $($osReg.CurrentBuild)"
    } catch {
        Write-Host "OS            : Unknown"
        Write-Host "OS Version    : Unknown"
    }

    # ----------------------------
    # Architecture (env safe)
    # ----------------------------
    Write-Host "Architecture  : $env:PROCESSOR_ARCHITECTURE"

    Write-Host ""
    Write-Host "----------------------------------------"
    Write-Host "Logged-on users (best effort):"
    Write-Host "----------------------------------------"

    $(query user 2>$null)
}

# ----------------------------
# Operating System & Build Context (Tiered, Passive)
# ----------------------------
Invoke-Safe "Operating System & Build Context (Tiered, Passive)" {
    Write-Host ""    

    $success = $false

    # -------- Tier 1: Get-ComputerInfo --------
    try {
        $reg = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop

        Write-Host "Product Name    : $($reg.ProductName)"
        Write-Host "Release ID      : $($reg.ReleaseId)"
        Write-Host "Current Build   : $($reg.CurrentBuild)"
        Write-Host "Current Version : $($reg.CurrentVersion)"

        if ($reg.InstallDate) {
            $installDate = [DateTimeOffset]::FromUnixTimeSeconds($reg.InstallDate).DateTime
            Write-Host "Install Date    : $installDate"
        }

        if ($reg.InstallTime) {
            $installTime = [DateTime]::FromFileTime($reg.InstallTime)
            Write-Host "Install Time    : $installTime"
        }

        $success = $true
    } catch {}

    if ($success) { return }

    # -------- Tier 2: Registry (extended) --------
    try {

        $ci = Get-ComputerInfo -ErrorAction Stop |
            Select-Object `
                WindowsBuildLabEx,
                WindowsCurrentVersion,
                WindowsEditionId,
                WindowsInstallationType,
                WindowsInstallDateFromRegistry,
                WindowsProductId,
                WindowsProductName,
                WindowsSystemRoot,
                WindowsVersion,
                OSDisplayVersion,
                OsServerLevel,
                TimeZone,
                PowerPlatformRole,
                DeviceGuardSmartStatus

        $ci
        $success = $true
    } catch {}

    if ($success) { return }

    # -------- Tier 3: Registry (minimal) --------
    try {
        Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' |
            Select-Object ProductName, ReleaseId, CurrentBuild, CurrentVersion
    } catch {
        Write-Host "[-] Unable to enumerate OS version information."
    }
}

# ----------------------------
# Local Storage Context
# ----------------------------
Invoke-Safe "Local Storage Context (Drives & Volumes)" {
    Write-Host ""

    Write-Host "[*] Enumerating local and mounted drives"

    $drives = [System.IO.DriveInfo]::GetDrives()

    foreach ($d in $drives) {
        try {
            $sizeGB = if ($d.TotalSize -gt 0) {
                [math]::Round($d.TotalSize / 1GB, 2)
            } else { "N/A" }

            $freeGB = if ($d.TotalFreeSpace -gt 0) {
                [math]::Round($d.TotalFreeSpace / 1GB, 2)
            } else { "N/A" }

            Write-Host "----------------------------------------"
            Write-Host ("Drive Letter : {0}" -f $d.Name)
            Write-Host ("Volume Label : {0}" -f $d.VolumeLabel)
            Write-Host ("File System  : {0}" -f $d.DriveFormat)
            Write-Host ("Drive Type   : {0}" -f $d.DriveType)
            Write-Host ("Size (GB)    : {0}" -f $sizeGB)
            Write-Host ("Free (GB)    : {0}" -f $freeGB)

            if ($d.DriveType -eq "Network") {
                Write-Host " [!] Network-mounted drive"
            }
            elseif ($d.DriveType -eq "Removable") {
                Write-Host " [!] Removable media present"
            }

        } catch {
            Write-Host ("[INFO] Cannot read drive {0}: {1}" -f $d.Name, $_.Exception.Message)
        }
    }

    Write-Host "`n[INFO] Drive enumeration is read-only and passive."
}

Write-Phase "DOMAIN & DIRECTORY REALITY CHECK"

# ----------------------------
# LDAP Reachability
# ----------------------------
Invoke-Safe "LDAP / AD Reachability" {
    Write-Host ""
    try {
        $root = [ADSI]"LDAP://RootDSE"
        Write-Host "LDAP Bind            : OK"
        Write-Host "Default Naming Ctx   : $($root.defaultNamingContext)"
        Write-Host "Configuration Ctx    : $($root.configurationNamingContext)"
    } catch {
        Write-Host "[-] LDAP not reachable."
    }
}

# ----------------------------
# Domain Context (Robust)
# ----------------------------
Invoke-Safe "Domain Context" {

    Write-Host ""

    try {
        $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    } catch {
        Write-Host "[-] Not in a domain or domain not reachable."
        return
    }

    # --- Basic domain info ---
    Write-Host "Domain Name        : $($domain.Name)"

    # --- Domain SID (safe LDAP method) ---
    try {
        $de = $domain.GetDirectoryEntry()
        $sidBytes = $de.Properties["objectSid"][0]
        $domainSid = (New-Object System.Security.Principal.SecurityIdentifier($sidBytes,0)).Value
        Write-Host "Domain SID         : $domainSid"
    } catch {
        Write-Host "Domain SID         : [Unavailable]"
    }

    # --- Forest info ---
    try {
        $forest = $domain.Forest
        Write-Host "Forest             : $($forest.Name)"
        Write-Host "Forest Mode        : $($forest.ForestMode)"
    } catch {
        Write-Host "Forest             : [Unavailable]"
    }

    # --- Domain mode ---
    try {
        Write-Host "Domain Mode        : $($domain.DomainMode)"
    } catch {
        Write-Host "Domain Mode        : [Unavailable]"
    }

    # --- Domain Controllers ---
    Write-Host "`nDomain Controllers:"
    try {
        $domain.DomainControllers | ForEach-Object {
            Write-Host " - $($_.Name)"
        }
    } catch {
        Write-Host " [Unavailable]"
    }
}

# ----------------------------
# Domain Group Memberships
# ----------------------------
Invoke-Safe "Domain Group Memberships (High-value only)" {

    Write-Host ""
    $groups = whoami /groups

    $interesting = @(
        # --- Tier 0 / Critical ---
        "Domain Admins",
        "Enterprise Admins",

        # --- Privileged operators ---
        "Account Operators",
        "Backup Operators",
        "Server Operators",
        "Print Operators",
        "DnsAdmins",

        # --- Local / cross-host impact ---
        "Administrators",
        "Remote Desktop Users",

        # --- Infra / service abuse potential ---
        "Hyper-V Administrators",
        "Event Log Readers",
        "Certificate Service DCOM Access"
    )

    $found = $false

    foreach ($group in $interesting) {
        if ($groups -match [regex]::Escape($group)) {
            Write-Host "[+] Member of: $group"
            $found = $true
        }
    }

    if (-not $found) {
        Write-Host "[OK] No high-value domain or local group memberships detected."
    }
}

# ----------------------------
# Current User AD Attributes
# ----------------------------
Invoke-Safe "Current User AD Attributes (Passive)" {
    Write-Host ""
    try {
        $user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        $sam = $user.Split('\')[-1]

        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $searcher.Filter = "(sAMAccountName=$sam)"
        $result = $searcher.FindOne()

        if ($result) {
            $props = $result.Properties

            Write-Host "sAMAccountName      : $sam"
            Write-Host "Display Name        : $($props.displayname)"
            Write-Host "Password Last Set   : $([DateTime]::FromFileTime($props.pwdlastset[0]))"
            Write-Host "Password Never Expires : $((($props.useraccountcontrol[0] -band 0x10000) -ne 0))"
            Write-Host "PreAuth Required    : $((($props.useraccountcontrol[0] -band 0x400000) -eq 0))"

            if ($props.serviceprincipalname) {
                Write-Host "[!] SPN PRESENT → Kerberos service account"
            }

            if (($props.useraccountcontrol[0] -band 0x80000) -ne 0) {
                Write-Host "[!] TRUSTED FOR DELEGATION (Unconstrained)"
            }
        }
    } catch {
        Write-Host "[-] Unable to query user AD attributes."
    }
}

Write-Phase "LOCAL & NETWORK AWARENESS"

# ----------------------------
# Network Awareness (Passive)
# ----------------------------
Invoke-Safe "Network Awareness (Passive)" {
    Write-Host ""
    Write-Host "----------------------------------------"
    Write-Host "IP Configuration:"
    Write-Host "----------------------------------------"
    $(ipconfig /all)
    Write-Host ""
    Write-Host "----------------------------------------"
    Write-Host "Content of Hosts file:"
    Write-Host "----------------------------------------"
    try {
        Get-Content C:\Windows\System32\drivers\etc\hosts -ErrorAction SilentlyContinue
    }
    catch {
        Write-Host "C:\Windows\System32\drivers\etc\hosts does not exist or not Accessible"
    }
    Write-Host ""
    Write-Host "----------------------------------------"
    Write-Host "Listening TCP ports with owning process:"
    Write-Host "----------------------------------------"

    try {
        $conns = Get-NetTCPConnection -State Listen -ErrorAction Stop

        foreach ($c in $conns) {
            $pid_ = $c.OwningProcess
            $proc = Get-Process -Id $pid_ -ErrorAction SilentlyContinue

            $pname = if ($proc) { $proc.ProcessName } else { "Unknown" }

            "{0,-6} {1,-22} PID:{2,-6} {3}" -f `
                $c.LocalPort, $c.LocalAddress, $pid_, $pname
        }
    } catch {
        Write-Host "Fallback to netstat..."
        $(netstat -ano | findstr LISTEN)
    }
}

# ----------------------------
# Running Processes (High Signal)
# ----------------------------
# ----------------------------
# Running Processes (High Signal)
# ----------------------------
Invoke-Safe "Running Processes (High Signal)" {

    Write-Host ""

    $success = $true

    # ========================================
    # Tier 1: WMI (preferred)
    # ========================================
    try {
        $procs = Get-WmiObject Win32_Process -ErrorAction Stop

        foreach ($p in $procs) {

            $owner = "N/A"
            try {
                $o = $p.GetOwner()
                if ($o.ReturnValue -eq 0) {
                    $owner = "$($o.Domain)\$($o.User)"
                }
            } catch {}

            $interesting = $false
            if ($owner -match "SYSTEM|Administrator") { $interesting = $true }
            if ($p.ExecutablePath -and $p.ExecutablePath -notmatch "Windows") { $interesting = $true }

            if ($interesting) {
                Write-Host "PID:$($p.ProcessId)  $($p.Name)"
                Write-Host " Owner : $owner"
                Write-Host " Path  : $($p.ExecutablePath)"
                Write-Host ""
            }
        }

    } catch {
        $success = $false
    }

    # ========================================
    # Tier 2: Native fallback (tasklist)
    # ========================================
    if (-not $success) {

        Write-Host "[INFO] WMI process enumeration not permitted."
        Write-Host "[INFO] Falling back to native tasklist output."
        Write-Host ""

        try {
            $tasks = tasklist /v 2>$null
        } catch {
            $tasks = $null
        }

        if (-not $tasks) {
            Write-Host "[INFO] Unable to retrieve process list."
            Write-Host "[INFO] Process inspection requires higher privileges."
            return
        }

        Write-Host "Process snapshot (limited context):"
        Write-Host "----------------------------------------"

        foreach ($line in $tasks) {

            # Skip headers
            if ($line -match "^Image Name|^===") { continue }

            # Heuristic signal:
            # - SYSTEM
            # - Administrator
            # - non-standard session
            if ($line -match "SYSTEM|Administrator") {
                Write-Host "  $line"
            }
        }

        Write-Host ""
        Write-Host "[INFO] Owner and executable path resolution is limited."
        Write-Host "[INFO] Re-run after privilege escalation for full visibility."
    }
}

# ----------------------------
# Services (Details + Control Rights)
# ----------------------------
Invoke-Safe "Services (Details + Control Rights)" {

    Write-Host ""

    # ----------------------------------------
    # StartType translation map
    # ----------------------------------------
    $ServiceStartTypeMap = @{
        0 = "Boot - very early driver"
        1 = "System - kernel init"
        2 = "Automatic - on boot"
        3 = "Manual - on demand"
        4 = "Disabled"
    }

    $success = $true

    # ========================================
    # Tier 1: WMI (preferred, high signal)
    # ========================================
    try {
        $services = Get-WmiObject Win32_Service -ErrorAction Stop

        foreach ($s in $services) {

            $canControl = $false

            try {
                $sd = sc.exe sdshow $s.Name 2>$null
                if ($sd -match "RPWP|WP") {
                    $canControl = $true
                }
            } catch {}

            if ($canControl -or $s.StartName -notmatch "LocalSystem") {

                Write-Host "Service      : $($s.Name)"
                Write-Host " Display     : $($s.DisplayName)"
                Write-Host " State       : $($s.State)"
                Write-Host " Run As      : $($s.StartName)"
                Write-Host " Binary Path : $($s.PathName)"

                if ($canControl) {
                    Write-Host " [!] You MAY have service control rights"
                }

                Write-Host ""
            }
        }

    } catch {
        $success = $false
    }

    # ========================================
    # Tier 2: Registry fallback (low-priv safe)
    # ========================================
    if (-not $success) {

        Write-Host "[INFO] WMI service enumeration not permitted."
        Write-Host "[INFO] Falling back to registry-based service discovery."
        Write-Host ""

        $servicesRoot = "HKLM:\SYSTEM\CurrentControlSet\Services"

        try {
            $serviceKeys = Get-ChildItem $servicesRoot -ErrorAction Stop
        } catch {
            Write-Host "[INFO] Unable to enumerate services via registry."
            return
        }

        foreach ($svc in $serviceKeys) {

            try {
                $props = Get-ItemProperty $svc.PSPath

                $name      = $svc.PSChildName
                $imagePath = $props.ImagePath
                $startName = $props.ObjectName
                $startRaw  = $props.Start

                if ($ServiceStartTypeMap.ContainsKey($startRaw)) {
                    $startType = "$startRaw ($($ServiceStartTypeMap[$startRaw]))"
                } else {
                    $startType = "$startRaw (Unknown)"
                }

                # Filter: show only interesting entries
                if ($startName -and $startName -notmatch "LocalSystem") {

                    Write-Host "Service      : $name"
                    Write-Host " Run As      : $startName"
                    Write-Host " Image Path  : $imagePath"
                    Write-Host " Start Type  : $startType"

                    # ---- Extra signal ----
                    if ($startRaw -eq 2 -and $startName -notmatch "LocalSystem") {
                        Write-Host " [!] Auto-start service running as non-SYSTEM"
                    }

                    Write-Host " [INFO] Registry-derived data (control rights unknown)"
                    Write-Host ""
                }

            } catch {
                continue
            }
        }

        Write-Host "[INFO] Full service enumeration requires higher privileges."
        Write-Host "[INFO] Consider manual service ACL review if privilege level increases."
    }
}

# ----------------------------
# Network Shares Enumeration
# ----------------------------
Invoke-Safe "Network Shares Enumeration (ACL + Effective Access)" {
    Write-Host ""

    # Global share roots storage (used by later modules)
    if (-not $global:BoberDiscoveredShareRoots) {
        $global:BoberDiscoveredShareRoots = @()
    }

    Write-Host "[*] Enumerating domain computers and accessible shares (passive)"

    # --------------------------------------------------
    # Current identity context
    # --------------------------------------------------
    $currentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $currentUser     = $currentIdentity.Name

    try {
        $userGroups = $currentIdentity.Groups.Translate(
            [System.Security.Principal.NTAccount]
        ) | ForEach-Object { $_.Value }
    } catch {
        $userGroups = @()
    }

    # --------------------------------------------------
    # ACE normalizer (deduplication & readability)
    # --------------------------------------------------
    function Convert-Ace {
        param($Ace)

        $identity = $Ace.IdentityReference.ToString()
        $rights   = $Ace.FileSystemRights.ToString()
        $type     = $Ace.AccessControlType.ToString()

        if ([string]::IsNullOrWhiteSpace($identity)) { return $null }
        if ([string]::IsNullOrWhiteSpace($rights))   { return $null }
        if ($rights -match '^-?\d+$')                 { return $null }

        return @{
            Identity = $identity
            Rights   = $rights
            Type     = $type
            Key      = "$identity|$rights|$type"
        }
    }

    # --------------------------------------------------
    # Discover computers via LDAP (best effort)
    # --------------------------------------------------
    try {
        $domain = ([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).Name

        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $searcher.SearchRoot = "LDAP://$domain"
        $searcher.Filter = "(objectCategory=computer)"
        $searcher.PropertiesToLoad.Add("name") | Out-Null
        $searcher.PageSize = 1000

        $computers = $searcher.FindAll() | ForEach-Object {
            $_.Properties["name"][0]
        }
    } catch {
        Write-Host "[INFO] Unable to enumerate computers via LDAP."
        return
    }

    if (-not $computers -or $computers.Count -eq 0) {
        Write-Host "[INFO] No computers found."
        return
    }

    # --------------------------------------------------
    # Enumerate shares per computer
    # --------------------------------------------------
    foreach ($computer in $computers) {

        $net = net view \\$computer /all 2>$null
        if (-not $net) { continue }

        $shareLines = $net | Select-String -SimpleMatch "Disk"
        if (-not $shareLines) { continue }

        foreach ($line in $shareLines) {

            $parts = $line.ToString().Trim() -split "\s+"
            if ($parts.Count -lt 1) { continue }

            $shareName = $parts[0]
            $unc = "\\$computer\$shareName"

            try {
                $acl = Get-Acl $unc -ErrorAction Stop
            } catch {
                continue
            }

            Write-Host "----------------------------------------"            
            Write-Host "Computer : $computer"
            Write-Host "Share    : $shareName"
            Write-Host "UNC Path : $unc"
            Write-Host ""

            # After successful Get-Acl
            if ($global:BoberDiscoveredShareRoots -notcontains $unc) {
                $global:BoberDiscoveredShareRoots += $unc
            }

            # ------------------------------------------
            # Deduplicated ACL
            # ------------------------------------------
            Write-Host "ACL (deduplicated):"

            $seen = @{}

            foreach ($ace in $acl.Access) {
                $norm = Convert-Ace $ace
                if (-not $norm) { continue }

                if ($seen.ContainsKey($norm.Key)) { continue }
                $seen[$norm.Key] = $true

                Write-Host "  - $($norm.Identity) | $($norm.Rights) | $($norm.Type)"
            }

            # ------------------------------------------
            # Effective permissions (current user)
            # ------------------------------------------
            Write-Host ""
            Write-Host "Effective permissions for current user ($currentUser):"

            $seenUser = @{}
            $found = $false

            foreach ($ace in $acl.Access) {

                $identity = $ace.IdentityReference.ToString()
                if ($identity -ne $currentUser -and $userGroups -notcontains $identity) {
                    continue
                }

                $norm = Convert-Ace $ace
                if (-not $norm) { continue }

                if ($seenUser.ContainsKey($norm.Key)) { continue }
                $seenUser[$norm.Key] = $true

                Write-Host "  - $($norm.Identity) | $($norm.Rights) | $($norm.Type)"
                $found = $true
            }

            if (-not $found) {
                Write-Host "  - No explicit matching ACE"
            }

            Write-Host ""
        }
    }

    Write-Host "[INFO] Share enumeration completed (no modification performed)."
}

Write-Phase "ACTIVE DIRECTORY ATTACK SURFACE (PASSIVE)"

# ----------------------------
# AD ACL Escalation-Risk Audit
# ----------------------------
Invoke-Safe "AD ACL Escalation-Risk Audit" {
    Write-Host ""
    Write-Host '[*] Active Directory ACL escalation-risk audit (no RSAT)'

    # --------------------------------------------------
    # Bind to RootDSE / domain
    # --------------------------------------------------
    try {
        $rootDse   = New-Object System.DirectoryServices.DirectoryEntry('LDAP://RootDSE')
        $defaultNC = $rootDse.defaultNamingContext
        $domainDE  = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$defaultNC")
    } catch {
        Write-Host '  [INFO] Unable to bind to LDAP RootDSE.'
        return
    }

    # --------------------------------------------------
    # Current identity SIDs
    # --------------------------------------------------
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $userSid  = $identity.User.Value
    $groupSids = @()
    foreach ($g in $identity.Groups) {
        $groupSids += $g.Value
    }
    $allSids = $groupSids + $userSid

    # --------------------------------------------------
    # Dangerous rights
    # --------------------------------------------------
    $dangerousRights = @{
        'GenericAll'   = 'Full control over the object (complete takeover).'
        'GenericWrite' = 'Can modify sensitive attributes.'
        'WriteDacl'    = 'Can modify permissions (self-assign full control).'
        'WriteOwner'   = 'Can take ownership, then rewrite ACLs.'
    }

    # Extended rights of interest
    $dangerousExtendedRights = @{
        '00299570-246d-11d0-a768-00aa006e0529' = 'Force password reset (account takeover).'
        '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' = 'Directory replication (DCSync).'
        '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' = 'Full directory replication (DCSync).'
        '89e95b76-444d-4c62-991a-0facbeda640c' = 'Filtered replication (DCSync).'
    }

    # --------------------------------------------------
    # LDAP search
    # --------------------------------------------------
    Write-Host '[*] Enumerating users, groups, computers and OUs'

    $searcher = New-Object System.DirectoryServices.DirectorySearcher
    $searcher.SearchRoot = $domainDE
    $searcher.Filter = '(|(objectClass=user)(objectClass=group)(objectClass=computer)(objectClass=organizationalUnit))'
    $searcher.PageSize = 1000
    $searcher.PropertiesToLoad.Add('distinguishedName') | Out-Null
    $searcher.PropertiesToLoad.Add('objectClass')       | Out-Null

    try {
        $results = $searcher.FindAll()
    } catch {
        Write-Host '  [INFO] LDAP enumeration failed.'
        return
    }

    if (-not $results -or $results.Count -eq 0) {
        Write-Host '  [INFO] No AD objects returned.'
        return
    }

    $findings = @()

    foreach ($r in $results) {
        $de = $r.GetDirectoryEntry()
        if (-not $de) { continue }

        try {
            $sd = $de.ObjectSecurity
        } catch {
            continue
        }

        $dn = $de.distinguishedName
        $classes = @($de.Properties['objectClass'])
        $objType = if ($classes.Count -gt 0) { $classes[-1] } else { 'unknown' }

        $rules = $sd.GetAccessRules($true,$true,[System.Security.Principal.SecurityIdentifier])

        foreach ($ace in $rules) {

            if ($ace.AccessControlType -ne 'Allow') { continue }

            if ($allSids -notcontains $ace.IdentityReference.Value) { continue }

            $rights = $ace.ActiveDirectoryRights.ToString().Split(',').Trim()

            foreach ($rName in $dangerousRights.Keys) {
                if ($rights -contains $rName) {
                    $findings += [PSCustomObject]@{
                        ObjectDN   = $dn
                        ObjectType = $objType
                        Right      = $rName
                        Identity   = $ace.IdentityReference.Value
                        Hint       = $dangerousRights[$rName]
                    }
                }
            }

            if ($rights -contains 'ExtendedRight') {
                $guid = $ace.ObjectType.Guid
                if ($dangerousExtendedRights.ContainsKey($guid)) {
                    $findings += [PSCustomObject]@{
                        ObjectDN   = $dn
                        ObjectType = $objType
                        Right      = 'ExtendedRight'
                        Identity   = $ace.IdentityReference.Value
                        Hint       = $dangerousExtendedRights[$guid]
                    }
                }
            }
        }
    }

    # --------------------------------------------------
    # Reporting
    # --------------------------------------------------
    if (-not $findings -or $findings.Count -eq 0) {
        Write-Host '  [OK] No dangerous AD ACL rights detected.'
        return
    }

    Write-Host ''
    Write-Host '[!] Potential AD ACL escalation paths detected:'
    Write-Host ''

    foreach ($f in $findings) {
        Write-Host "  [HIGH] $($f.Right) on $($f.ObjectType)"
        Write-Host "         Object   : $($f.ObjectDN)"
        Write-Host "         Identity : $($f.Identity)"
        Write-Host "         Hint     : $($f.Hint)"
        Write-Host ''
    }
}

# ==================================================
# Active Directory – Delegation Enumeration
# ==================================================
Invoke-Safe "Active Directory Delegation Enumeration" {
    Write-Host ""

    Write-Host "[+] Active Directory Delegation checks"

    function Info($msg)       { Write-Host "  [INFO]        $msg" }
    function Ok($msg)         { Write-Host "  [OK]          $msg" }
    function Suspicious($msg) { Write-Host "  [SUSPICIOUS]  $msg" }
    function High($msg)       { Write-Host "  [HIGH]        $msg" }

    # --------------------------------------------------
    # 1) Unconstrained Delegation
    # --------------------------------------------------
    Write-Host "`n[*] Unconstrained Delegation"

    $unconstrainedComputers = Get-ADComputer -Filter { TrustedForDelegation -eq $true } -Properties TrustedForDelegation
    $unconstrainedUsers     = Get-ADUser     -Filter { TrustedForDelegation -eq $true } -Properties TrustedForDelegation

    if (-not $unconstrainedComputers -and -not $unconstrainedUsers) {
        Ok "No objects with Unconstrained Delegation found."
    } else {
        High "Unconstrained Delegation present ticket forwarding possible."

        foreach ($c in $unconstrainedComputers) {
            Write-Host "    Computer: $($c.Name)"
        }

        foreach ($u in $unconstrainedUsers) {
            Write-Host "    User:     $($u.SamAccountName)"
        }
    }

    # --------------------------------------------------
    # 2) Constrained Delegation (KCD)
    # --------------------------------------------------
    Write-Host "`n[*] Constrained Delegation (KCD)"

    $kcdObjects = Get-ADObject -LDAPFilter "(msDS-AllowedToDelegateTo=*)" `
        -Properties msDS-AllowedToDelegateTo,ObjectClass

    if (-not $kcdObjects) {
        Ok "No Constrained Delegation entries found."
    } else {
        foreach ($obj in $kcdObjects) {
            $targets = $obj.'msDS-AllowedToDelegateTo'
            Info "Object: $($obj.Name) ($($obj.ObjectClass))"

            if ($targets.Count -gt 5) {
                Suspicious "Many delegation targets ($($targets.Count))"
            }

            foreach ($t in $targets) {
                if ($t -match "cifs|ldap|host") {
                    Suspicious "Sensitive service delegation: $t"
                } else {
                    Write-Host "      -> $t"
                }
            }
        }
    }

    # --------------------------------------------------
    # 3) Resource-Based Constrained Delegation (RBCD)
    # --------------------------------------------------
    Write-Host "`n[*] Resource-Based Constrained Delegation (RBCD)"

    $rbcdObjects = Get-ADObject -LDAPFilter "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)" `
        -Properties msDS-AllowedToActOnBehalfOfOtherIdentity

    if (-not $rbcdObjects) {
        Ok "No RBCD entries found."
    } else {
        foreach ($obj in $rbcdObjects) {
            Info "Target object: $($obj.Name)"

            $sd = New-Object System.DirectoryServices.ActiveDirectorySecurity
            $sd.SetSecurityDescriptorBinaryForm(
                $obj.'msDS-AllowedToActOnBehalfOfOtherIdentity'
            )

            $rules = $sd.GetAccessRules($true,$true,[System.Security.Principal.NTAccount])

            foreach ($r in $rules) {
                if ($r.IdentityReference -match "Domain Computers") {
                    High "RBCD allows ALL domain computers!"
                } else {
                    Suspicious "Delegation allowed for: $($r.IdentityReference)"
                }
            }
        }
    }

    # --------------------------------------------------
    # 4) SPN sanity checks (delegation related)
    # --------------------------------------------------
    Write-Host "`n[*] SPN checks"

    $spnObjects = Get-ADObject -LDAPFilter "(servicePrincipalName=*)" `
        -Properties servicePrincipalName,ObjectClass

    if (-not $spnObjects) {
        Ok "No SPNs found."
    } else {
        foreach ($obj in $spnObjects) {
            foreach ($spn in $obj.servicePrincipalName) {
                if ($obj.ObjectClass -eq "user" -and $spn -match "^HOST/") {
                    High "User account with HOST SPN: $($obj.Name)"
                }
            }
        }
    }

    Info "Delegation checks completed."

}

# ----------------------------
# GPO ACL Privilege Escalation
# ----------------------------
Invoke-Safe "GPO ACL Escalation Risks" {
    Write-Host ""

    # --- Domain check ---
    try {
        $rootDse = New-Object System.DirectoryServices.DirectoryEntry("LDAP://RootDSE")
        $defaultNC = $rootDse.defaultNamingContext
    } catch {
        Write-Host "  [INFO] Not domain-joined or LDAP unavailable."
        return
    }

    # --- Current identity ---
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $userSid  = $identity.User.Value
    $groupSids = $identity.Groups | ForEach-Object { $_.Value }
    $allSids = $groupSids + $userSid

    # --- Dangerous ACL rights ---
    $dangerousRights = @{
        "GenericAll"   = "Full control over the GPO (complete takeover possible)."
        "GenericWrite" = "Can modify GPO attributes (policy manipulation)."
        "WriteDacl"    = "Can modify ACLs (grant full control)."
        "WriteOwner"   = "Can take ownership (ACL takeover)."
    }

    # --- LDAP searcher ---
    try {
        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry(
            "LDAP://CN=Policies,CN=System,$defaultNC"
        )
        $searcher.Filter   = "(objectClass=groupPolicyContainer)"
        $searcher.PageSize = 1000
        $searcher.PropertiesToLoad.AddRange(@(
            "displayName",
            "distinguishedName"
        )) | Out-Null

        $results = $searcher.FindAll()
    } catch {
        Write-Host "  [ERROR] Failed to enumerate GPOs via LDAP."
        return
    }

    if (-not $results -or $results.Count -eq 0) {
        Write-Host "  [INFO] No GPO objects found."
        return
    }

    $findings = @()

    foreach ($r in $results) {
        try {
            $de = $r.GetDirectoryEntry()
            $sd = $de.ObjectSecurity
        } catch {
            continue
        }

        $gpoName = $de.Properties["displayName"][0]
        $gpoDn   = $de.Properties["distinguishedName"][0]

        $rules = $sd.GetAccessRules(
            $true,
            $true,
            [System.Security.Principal.SecurityIdentifier]
        )

        foreach ($ace in $rules) {
            if ($allSids -notcontains $ace.IdentityReference.Value) {
                continue
            }

            $rights = $ace.ActiveDirectoryRights.ToString() -split ",\s*"

            foreach ($rName in $dangerousRights.Keys) {
                if ($rights -contains $rName) {
                    $findings += "$rName|$gpoName|$gpoDn|$($ace.IdentityReference)"
                }
            }
        }
    }

    $findings = $findings | Sort-Object -Unique

    if (-not $findings -or $findings.Count -eq 0) {
        Write-Host "  [OK] No dangerous GPO ACL rights detected."
        return
    }

    Write-Host "  [!] Dangerous GPO ACL permissions detected:`n"

    foreach ($f in $findings) {
        $parts = $f -split "\|"
        $right = $parts[0]
        $name  = $parts[1]
        $dn    = $parts[2]
        $id    = $parts[3]

        Write-Host "  [HIGH] $right on GPO '$name'"
        Write-Host "         Identity : $id"
        Write-Host "         DN       : $dn"
        Write-Host "         Hint     : $($dangerousRights[$right])"
        Write-Host ""
    }
}

# ----------------------------
# GPO SYSVOL File-Level ACLs
# ----------------------------
Invoke-Safe "GPO SYSVOL File-Level Escalation Risks" {
    Write-Host ""

    # --- Domain check ---
    try {
        $rootDse   = New-Object System.DirectoryServices.DirectoryEntry("LDAP://RootDSE")
        $defaultNC = $rootDse.defaultNamingContext
    } catch {
        Write-Host "  [INFO] Not domain-joined or LDAP unavailable."
        return
    }

    # --- Build domain FQDN ---
    $domainFqdn = ($defaultNC -split ",") -replace "^DC=","" -join "."
    $sysvolPath = "\\$domainFqdn\SYSVOL\$domainFqdn\Policies"

    Write-Host "  [*] SYSVOL path: $sysvolPath"

    if (-not (Test-Path $sysvolPath)) {
        Write-Host "  [INFO] SYSVOL not accessible."
        return
    }

    # --- Current identity ---
    $identity  = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $userSid  = $identity.User.Value
    $groupSids = $identity.Groups | ForEach-Object { $_.Value }
    $allSids  = $groupSids + $userSid

    # --- Dangerous FS rights ---
    $dangerousFsRights = @{
        "FullControl"       = "Full control over GPO files (arbitrary policy injection)."
        "Modify"            = "Can modify GPO files (policy tampering)."
        "Write"             = "Can write to GPO files (policy tampering)."
        "ChangePermissions" = "Can modify ACLs (grant full control)."
        "TakeOwnership"     = "Can take ownership (ACL takeover)."
    }

    # --- Enumerate GPO folders ---
    try {
        $gpoFolders = Get-ChildItem -Path $sysvolPath -Directory -ErrorAction Stop
    } catch {
        Write-Host "  [ERROR] Failed to enumerate SYSVOL GPO folders."
        return
    }

    if (-not $gpoFolders -or $gpoFolders.Count -eq 0) {
        Write-Host "  [INFO] No GPO folders found."
        return
    }

    $findings = @()

    foreach ($folder in $gpoFolders) {
        try {
            $acl = Get-Acl -Path $folder.FullName
        } catch {
            continue
        }

        foreach ($ace in $acl.Access) {
            try {
                $aceSid = $ace.IdentityReference.Translate(
                    [System.Security.Principal.SecurityIdentifier]
                ).Value
            } catch {
                continue
            }

            if ($allSids -notcontains $aceSid) {
                continue
            }

            $rights = $ace.FileSystemRights.ToString() -split ",\s*"

            foreach ($rName in $dangerousFsRights.Keys) {
                if ($rights -contains $rName) {
                    $findings += "$rName|$($folder.Name)|$($folder.FullName)|$($ace.IdentityReference)"
                }
            }
        }
    }

    $findings = $findings | Sort-Object -Unique

    if (-not $findings -or $findings.Count -eq 0) {
        Write-Host "  [OK] No dangerous SYSVOL GPO file-level permissions detected."
        return
    }

    Write-Host "  [!] Dangerous SYSVOL GPO permissions detected:`n"

    foreach ($f in $findings) {
        $p = $f -split "\|"

        Write-Host "  [HIGH] $($p[0]) on GPO folder '$($p[1])'"
        Write-Host "         Path     : $($p[2])"
        Write-Host "         Identity : $($p[3])"
        Write-Host "         Hint     : $($dangerousFsRights[$p[0]])"
        Write-Host ""
    }
}

# ----------------------------
# ADCS Certificate Services
# ----------------------------
Invoke-Safe "ADCS Certificate Template & CA Escalation Risks" {
    Write-Host ""

    # --- LDAP Root ---
    try {
        $rootDse  = New-Object System.DirectoryServices.DirectoryEntry("LDAP://RootDSE")
        $configNC = $rootDse.configurationNamingContext
    } catch {
        Write-Host "  [INFO] LDAP unavailable or not domain-joined."
        return
    }

    # --- Identity ---
    $id        = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $userSid   = $id.User.Value
    $groupSids = $id.Groups | ForEach-Object { $_.Value }
    $allSids   = $groupSids + $userSid

    # --- Dangerous ACL rights ---
    $dangerousRights = @{
        "GenericAll"   = "Full control (template or CA takeover)."
        "GenericWrite" = "Can modify configuration (escalation possible)."
        "WriteDacl"    = "Can change ACLs (grant full control)."
        "WriteOwner"   = "Can take ownership (ACL takeover)."
    }

    # --- EKU OIDs ---
    $ekuAuth = @(
        "1.3.6.1.5.5.7.3.2",          # ClientAuth
        "1.3.6.1.4.1.311.20.2.2",     # SmartcardLogon
        "1.3.6.1.5.2.3.4"             # PKINIT
    )
    $ekuAnyPurpose = "2.5.29.37.0"

    # --- Flags ---
    $CT_ENROLLEE_SUPPLIES_SUBJECT = 0x1
    $CT_PEND_ALL                 = 0x2
    $PRIVATE_KEY_EXPORTABLE      = 0x10

    # --- Helpers ---
    function Get-YearsFromPeriod {
        param([byte[]]$Bytes)
        if (-not $Bytes -or $Bytes.Count -ne 8) { return $null }
        $ticks = [BitConverter]::ToInt64($Bytes,0)
        if ($ticks -ge 0) { return $null }
        return [math]::Round((-$ticks / 1e7) / (60*60*24*365),2)
    }

    $findings = @()

    # ==========================================================
    # Certificate Templates
    # ==========================================================
    $tplPath = "LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"

    try {
        $searcher = New-Object DirectoryServices.DirectorySearcher(
            (New-Object DirectoryServices.DirectoryEntry($tplPath))
        )
        $searcher.Filter = "(objectClass=pKICertificateTemplate)"
        $searcher.PageSize = 1000
        $results = $searcher.FindAll()
    } catch {
        Write-Host "  [ERROR] Failed to enumerate certificate templates."
        return
    }

    foreach ($r in $results) {
        $de = $r.GetDirectoryEntry()
        if (-not $de) { continue }

        $name = $de.displayName
        if (-not $name) { $name = $de.cn }

        $eku = @($de.Properties["pKIExtendedKeyUsage"])
        $enrollFlags = [int]($de.Properties["msPKI-Enrollment-Flag"][0] 2>$null)
        $privFlags   = [int]($de.Properties["msPKI-Private-Key-Flag"][0] 2>$null)
        $validYears  = Get-YearsFromPeriod $de.Properties["pKIExpirationPeriod"][0]

        $isAuth = ($eku | Where-Object { $ekuAuth -contains $_ }).Count -gt 0

        # ESC1
        if ($isAuth -and
            ($enrollFlags -band $CT_ENROLLEE_SUPPLIES_SUBJECT) -and
            -not ($enrollFlags -band $CT_PEND_ALL)) {

            $findings += "[ESC1]|$name|Auth template allows subject supply without approval"
        }

        # ESC2 / broad usage
        if ($eku -contains $ekuAnyPurpose -or $eku.Count -eq 0) {
            $findings += "[ESC2]|$name|AnyPurpose or no EKU defined"
        }

        # Exportable key
        if ($privFlags -band $PRIVATE_KEY_EXPORTABLE) {
            $findings += "[WEAK]|$name|Private key exportable"
        }

        # Long-lived auth cert
        if ($isAuth -and $validYears -and $validYears -gt 5) {
            $findings += "[WEAK]|$name|Long-lived authentication certificate ($validYears years)"
        }

        # --- Template ACL ---
        try {
            $sd = $de.ObjectSecurity
            $aces = $sd.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])
        } catch { continue }

        foreach ($ace in $aces) {
            if ($allSids -notcontains $ace.IdentityReference.Value) { continue }

            $rights = $ace.ActiveDirectoryRights.ToString() -split ",\s*"
            foreach ($rName in $dangerousRights.Keys) {
                if ($rights -contains $rName) {
                    $findings += "[ACL]|$name|$rName granted to $($ace.IdentityReference)"
                }
            }
        }
    }

    # ==========================================================
    # CA Objects (Enrollment Services)
    # ==========================================================
    $caPath = "LDAP://CN=Enrollment Services,CN=Public Key Services,CN=Services,$configNC"

    try {
        $caSearcher = New-Object DirectoryServices.DirectorySearcher(
            (New-Object DirectoryServices.DirectoryEntry($caPath))
        )
        $caSearcher.Filter = "(objectClass=pKIEnrollmentService)"
        $cas = $caSearcher.FindAll()
    } catch {
        $cas = @()
    }

    foreach ($ca in $cas) {
        $de = $ca.GetDirectoryEntry()
        if (-not $de) { continue }

        try {
            $sd = $de.ObjectSecurity
            $aces = $sd.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])
        } catch { continue }

        foreach ($ace in $aces) {
            if ($allSids -notcontains $ace.IdentityReference.Value) { continue }

            $rights = $ace.ActiveDirectoryRights.ToString() -split ",\s*"
            foreach ($rName in $dangerousRights.Keys) {
                if ($rights -contains $rName) {
                    $findings += "[CA]|$($de.cn)|$rName on Certification Authority"
                }
            }
        }
    }

    # ==========================================================
    # Output
    # ==========================================================
    $findings = $findings | Sort-Object -Unique

    if (-not $findings -or $findings.Count -eq 0) {
        Write-Host "  [OK] No obvious ADCS escalation paths detected."
        return
    }

    Write-Host "  [!] Potential ADCS escalation risks detected:`n"
    foreach ($f in $findings) {
        Write-Host "  $f"
    }
}

# ----------------------------
# BadSuccessor / dMSA Attack Surface (Passive Assessment)
# ----------------------------
Invoke-Safe "BadSuccessor / dMSA Attack Surface (Passive Assessment)" {
    Write-Host ""

    $isInteresting = $false

    # --- OS / Build Check ---
    Write-Host "[*] Operating System Check"
    try {
        $reg = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
        Write-Host " Product Name : $($reg.ProductName)"
        Write-Host " Release ID   : $($reg.ReleaseId)"
        Write-Host " Build        : $($reg.CurrentBuild)"
        Write-Host " Version      : $($reg.CurrentVersion)"

        if ($reg.CurrentBuild -ge 26000) {
            Write-Host " [!] New-generation Windows build detected"
            $isInteresting = $true
        }
    } catch {
        Write-Host " [-] Unable to query OS build"
    }

    # --- Domain Presence ---
    try {
        $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        Write-Host "`n[*] Domain Context: $($domain.Name)"
    } catch {
        Write-Host "`n[-] Not in a domain context"
        return
    }

    # --- Writable OU Check ---
    Write-Host "`n[*] Checking for writable Organizational Units"

    $foundWritableOU = $false

    # Tier 1: AD Module
    try {
        if (Get-Command Get-ADOrganizationalUnit -ErrorAction Stop) {

            $u = [System.Security.Principal.WindowsIdentity]::GetCurrent()
            $ids = @($u.User.Value)
            $ids += $u.Groups | ForEach-Object { $_.Value }

            $ous = Get-ADOrganizationalUnit -Filter *

            foreach ($ou in $ous) {
                $acl = Get-Acl ("AD:\" + $ou.DistinguishedName)

                foreach ($ace in $acl.Access) {
                    if (-not $ace.IsInherited -and
                        $ids -contains $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -and
                        ($ace.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::CreateChild)) {

                        Write-Host " [!] Writable OU detected:"
                        Write-Host "     $($ou.DistinguishedName)"
                        $foundWritableOU = $true
                        $isInteresting = $true
                    }
                }
            }
        }
    } catch {}

    # Tier 2: LDAP / ADSI fallback
    if (-not $foundWritableOU) {
        try {
            Write-Host " [-] AD module not available or no writable OU found via AD module"
            Write-Host " [*] LDAP fallback not implemented for ACL parsing (by design)"
        } catch {}
    }

    # --- Summary ---
    Write-Host "`n[*] Assessment Summary"

    if ($isInteresting -and $foundWritableOU) {
        Write-Host " [!] Environment MAY be interesting for BadSuccessor / dMSA research"
        Write-Host "     Preconditions appear to be present"
    }
    elseif ($isInteresting) {
        Write-Host " [?] OS / Domain conditions met, but no writable OU detected"
        Write-Host "     Further ACL review may be required"
    }
    else {
        Write-Host " [-] Environment unlikely to be affected based on passive checks"
    }

    Write-Host "`n[INFO] This check is based on public research only."
    Write-Host "[INFO] No exploitation or modification was performed."
}

Write-Phase "HISTORICAL & SENSITIVE ARTEFACTS"

# -------------------------------------------------------
# Deleted Active Directory Objects (Tombstones - Passive)
# -------------------------------------------------------
Invoke-Safe "Deleted Active Directory Objects (Tombstones - Passive)" {
    Write-Host ""
    $success = $false

    # -------- Tier 1: Get-ADObject (if available) --------
    try {
        if (Get-Command Get-ADObject -ErrorAction Stop) {

            $deleted = Get-ADObject `
                -Filter 'isDeleted -eq $true' `
                -IncludeDeletedObjects `
                -Properties `
                    samAccountName,
                    objectClass,
                    whenCreated,
                    whenChanged,
                    lastKnownParent,
                    msDS-LastKnownRDN,
                    objectGUID

            foreach ($obj in $deleted) {
                if ($obj.objectClass -in @("user","group","computer","organizationalUnit")) {

                    Write-Host "Object Class : $($obj.objectClass)"
                    Write-Host "Name         : $($obj.samAccountName)"
                    Write-Host "Last RDN     : $($obj.'msDS-LastKnownRDN')"
                    Write-Host "Last Parent  : $($obj.lastKnownParent)"
                    Write-Host "GUID         : $($obj.objectGUID)"
                    Write-Host "Created      : $($obj.whenCreated)"
                    Write-Host "Changed      : $($obj.whenChanged)"
                    Write-Host ""
                }
            }

            $success = $true
        }
    } catch {}

    if ($success) { return }

    # -------- Tier 2: Native LDAP Tombstone Search --------
    try {
        $root = [ADSI]"LDAP://RootDSE"
        $baseDN = $root.defaultNamingContext

        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $searcher.SearchRoot = "LDAP://$baseDN"
        $searcher.Filter = "(isDeleted=TRUE)"
        $searcher.Tombstone = $true
        $searcher.PageSize = 200

        $props = @(
            "samAccountName",
            "objectClass",
            "whenCreated",
            "whenChanged",
            "lastKnownParent",
            "msDS-LastKnownRDN",
            "objectGUID"
        )

        foreach ($p in $props) { $searcher.PropertiesToLoad.Add($p) }

        $results = $searcher.FindAll()

        foreach ($r in $results) {
            $cls = $r.Properties["objectclass"] | Select-Object -Last 1

            if ($cls -in @("user","group","computer","organizationalUnit")) {

                Write-Host "Object Class : $cls"
                Write-Host "Name         : $($r.Properties["samaccountname"])"
                Write-Host "Last RDN     : $($r.Properties["msds-lastknownrdn"])"
                Write-Host "Last Parent  : $($r.Properties["lastknownparent"])"
                Write-Host "GUID         : $([guid]$r.Properties["objectguid"][0])"
                Write-Host "Created      : $($r.Properties["whencreated"])"
                Write-Host "Changed      : $($r.Properties["whenchanged"])"
                Write-Host ""
            }
        }

    } catch {
        Write-Host "[-] Unable to query deleted AD objects."
    }
}

# ----------------------------------------
# DPAPI Artefacts (Passive, Presence Only)
# ----------------------------------------
Invoke-Safe "DPAPI Artefacts (Passive, Presence Only)" {
    $usersRoot = "C:\Users"

    $users = Get-ChildItem $usersRoot -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notin @("Public","Default","All Users","Default User") }

    foreach ($u in $users) {
        Write-Host ""
        Write-Host "----------------------------------------"
        Write-Host " User: $($u.Name) "
        Write-Host "----------------------------------------"
        $base = $u.FullName

        # --- Master Keys ---
        $mkPath = Join-Path $base "AppData\Roaming\Microsoft\Protect"
        if (Test-Path $mkPath) {
            Write-Host "[+] DPAPI MasterKeys present"
            Write-Host "    Path: $mkPath"            
            Get-ChildItem $mkPath -Directory -ErrorAction SilentlyContinue |
                ForEach-Object {
                    Write-Host "    SID: $($_.Name)"
                }
        } else {
            Write-Host "[-] No DPAPI MasterKeys found"
        }

        # --- Credential Files ---
        $credPath = Join-Path $base "AppData\Roaming\Microsoft\Credentials"
        if (Test-Path $credPath) {
            Write-Host "[+] Windows Credentials present"
            Write-Host "    Path: $credPath"
            Get-ChildItem $credPath -File -ErrorAction SilentlyContinue |
                ForEach-Object {
                    Write-Host "    $($_.Name)"
                }
        }

        # --- Vaults ---
        $vaultPath = Join-Path $base "AppData\Local\Microsoft\Vault"
        if (Test-Path $vaultPath) {
            Write-Host "[+] Vault data present"
            Write-Host "    Path: $vaultPath"            
            Get-ChildItem $vaultPath -Directory -ErrorAction SilentlyContinue |
                ForEach-Object {
                    Write-Host "    Vault: $($_.Name)"
                }
        }

        # --- Chrome Login Data ---
        $chromeLogin = Join-Path $base "AppData\Local\Google\Chrome\User Data\Default\Login Data"
        if (Test-Path $chromeLogin) {
            Write-Host "[+] Chrome Login Data present"
            Write-Host "    Path: $chromeLogin"
        }
    }

    Write-Host "`n[INFO] Presence of DPAPI artefacts does NOT imply access."
    Write-Host "[INFO] This section performs NO decryption and NO modification."
}

Write-Phase "TARGETED ENUMERATION & COLLECTION"

# ----------------------------
# Targeted File Enumeration (Fast Mode)
# ----------------------------
Invoke-Safe "Targeted File Enumeration (Fast Mode, Deduplicated)" {
    Write-Host ""

    # --------------------------------------------------
    # Extension whitelist
    # --------------------------------------------------
    $TargetExtensions = @(
        ".txt", ".doc", ".docx", ".xls", ".xlsx", ".pdf",
        ".odt", ".ods", ".odp",
        ".ini", ".conf", ".cfg", ".xml", ".json", ".yml", ".yaml",
        ".kdbx", ".pfx", ".p12", ".pem", ".key", ".ppk",
        ".bak", ".old", ".backup", ".bkp", "~",
        ".zip", ".7z", ".rar"
    )

    # --------------------------------------------------
    # Base root paths (local)
    # --------------------------------------------------
    $RootPaths = @(
        "C:\Users",
        "C:\ProgramData",
        "C:\inetpub",
        "C:\Windows\Temp"
    )

    # --------------------------------------------------
    # Scope banner
    # --------------------------------------------------
    Write-Host "[*] Target extensions:"
    Write-Host "    $($TargetExtensions -join ', ')"
    Write-Host ""
    Write-Host "[*] Target root paths:"
    Write-Host "    $($RootPaths -join ', ')"
    Write-Host ""

    # --------------------------------------------------
    # Merge discovered network shares (if any)
    # --------------------------------------------------
    if ($global:BoberDiscoveredShareRoots -and
        $global:BoberDiscoveredShareRoots.Count -gt 0) {

        Write-Host "[*] Adding discovered network shares to scan scope"

        foreach ($share in $global:BoberDiscoveredShareRoots) {
            if ($RootPaths -notcontains $share) {
                $RootPaths += $share
                Write-Host "    + $share"
            }
        }
    } else {
        Write-Host "[INFO] No previously discovered network shares to include"
        Write-Host ""
    }
    # --------------------------------------------------
    # Deduplication storage
    # --------------------------------------------------
    $SeenFileIds = @{}

    # --------------------------------------------------
    # Safe child enumeration
    # --------------------------------------------------
    function Get-SafeChildItems {
        param ([string]$Path)
        try {
            Get-ChildItem -LiteralPath $Path -Force -ErrorAction Stop
        } catch {
            #Write-Host "[SKIP][ACL] $Path"
            return @()
        }
    }

    # --------------------------------------------------
    # File ID (best effort)
    # --------------------------------------------------
    function Get-FileId {
        param ([string]$Path)
        try {
            $fs = [System.IO.File]::Open(
                $Path,
                [System.IO.FileMode]::Open,
                [System.IO.FileAccess]::Read,
                [System.IO.FileShare]::ReadWrite
            )
            $id = $fs.SafeFileHandle.DangerousGetHandle().ToInt64()
            $fs.Close()
            return $id
        } catch {
            return $null
        }
    }

    # --------------------------------------------------
    # Recursive traversal
    # --------------------------------------------------
    function Search-Path {
        param ([string]$StartPath)

        foreach ($item in Get-SafeChildItems -Path $StartPath) {

            if ($item.PSIsContainer) {
                Search-Path -StartPath $item.FullName
                continue
            }

            try {
                $ext = $item.Extension.ToLower()
                if (-not ($TargetExtensions -contains $ext)) { continue }

                $fid = Get-FileId -Path $item.FullName
                if ($fid -and $SeenFileIds.ContainsKey($fid)) { continue }
                if ($fid) { $SeenFileIds[$fid] = $true }

                Write-Host "[HIT][$ext] $($item.FullName)"
            } catch {}
        }
    }

    # --------------------------------------------------
    # Execution
    # --------------------------------------------------
    foreach ($root in $RootPaths) {
        Write-Host ""
        Write-Host "----------------------------------------"
        Write-Host "[*] Scanning: $root"
        Write-Host "----------------------------------------"

        if (-not (Test-Path -LiteralPath $root)) {
            Write-Host "[MISS] Path does not exist"
            continue
        }

        Search-Path -StartPath $root
    }

    Write-Host ""
    Write-Host "[INFO] Targeted file enumeration completed"
}

# ----------------------------
# Security Artefact Collection
# ----------------------------
Invoke-Safe "Security Artefact Collection (Local, User & Policy Evidence)" {
    Write-Host ""
    Write-Host "[INFO] Security artefact collection started."
    Write-Host "[INFO] This section performs READ operations and file collection only."
    Write-Host ""

    # --------------------------------------------------
    # Output base
    # --------------------------------------------------
    try {
        $scriptRoot = Split-Path -Parent $PSCommandPath
    } catch {
        $scriptRoot = Get-Location
    }

    $outRoot = Join-Path $scriptRoot "Security_Artifacts_Results"
    New-Item -ItemType Directory -Force -Path $outRoot | Out-Null

    # ==================================================
    # EVENT LOGS
    # ==================================================
    Write-Host "[*] Exporting event logs"

    $logOut = Join-Path $outRoot "EventLogs"
    New-Item -ItemType Directory -Force -Path $logOut | Out-Null

    $logs = @(
        @{ Name = "Security";  File = "Security.evtx" },
        @{ Name = "System";    File = "System.evtx" },
        @{ Name = "Application"; File = "Application.evtx" },
        @{ Name = "Microsoft-Windows-PowerShell/Operational"; File = "PowerShell_Operational.evtx" }
    )

    $eventLogTotal   = 0
    $eventLogSuccess = 0

    foreach ($log in $logs) {
        $eventLogTotal++

        $target = Join-Path $logOut $log.File
        cmd /c "wevtutil epl `"$($log.Name)`" `"$target`" 2>nul" | Out-Null

        if (Test-Path $target) {
            $eventLogSuccess++
            Write-Host "  [OK] $($log.Name) exported"
        } else {
            Write-Host "  [SKIP] $($log.Name) not accessible"
        }
    }

    Write-Host ""

    # ==================================================
    # GPO RESULT
    # ==================================================
    Write-Host "[*] Exporting GPO result"

    $gpoOut = Join-Path $outRoot "GPO_Result.html"
    cmd /c "gpresult /h `"$gpoOut`" 2>nul" | Out-Null

    $gpoStatus = $false
    if (Test-Path $gpoOut) {
        Write-Host "  [OK] GPO report created"
        $gpoStatus = $true
    } else {
        Write-Host "  [SKIP] GPO report not available"
    }

    Write-Host ""

    # ==================================================
    # USER PROFILE ENUMERATION & COLLECTION
    # ==================================================
    Write-Host "[*] Enumerating local user profiles"

    $usersOut = Join-Path $outRoot "Users"
    New-Item -ItemType Directory -Force -Path $usersOut | Out-Null

    $userDirs = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notin @("Public","Default","Default User","All Users") }

    $userCount = 0

    foreach ($u in $userDirs) {

        $userCount++
        $userName = $u.Name
        $userPath = $u.FullName
        $userOut  = Join-Path $usersOut $userName

        New-Item -ItemType Directory -Force -Path $userOut | Out-Null

        Write-Host "User : $userName"
        Write-Host "Path : $userPath"

        # ---------------------------
        # PSReadLine history
        # ---------------------------
        $psHist = Join-Path $userPath "AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine"

        if (Test-Path $psHist) {

            $psFiles = Get-ChildItem -Path $psHist -Filter *.txt -File -ErrorAction SilentlyContinue

            if ($psFiles) {
                foreach ($f in $psFiles) {

                    if (-not (Test-Path $f.FullName)) {
                        Write-Host "  [SKIP] PSReadLine file vanished: $($f.FullName)"
                        continue
                    }

                    $dest = Join-Path $userOut ("PSReadLine_" + $f.Name)

                    try {
                        Copy-Item -LiteralPath $f.FullName -Destination $dest -Force -ErrorAction Stop
                        Write-Host "  [OK] PSReadLine history copied"
                        Write-Host "       Source: $($f.FullName)"
                        Write-Host "       Target: $dest"
                    } catch {
                        Write-Host "  [FAIL] PSReadLine copy failed"
                        Write-Host "        Source: $($f.FullName)"
                    }
                }
            } else {
                Write-Host "  [SKIP] PSReadLine directory exists, no history files"
            }

        } else {
            Write-Host "  [SKIP] No PSReadLine history directory"
        }

        # ---------------------------
        # Browser history (Chromium)
        # ---------------------------
        $browserOut = Join-Path $userOut "Browser_History"
        New-Item -ItemType Directory -Force -Path $browserOut | Out-Null

        $chromium = @{
            "Chrome" = "AppData\Local\Google\Chrome\User Data\Default\History"
            "Edge"   = "AppData\Local\Microsoft\Edge\User Data\Default\History"
            "Brave"  = "AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\History"
        }

        foreach ($b in $chromium.Keys) {

            $src = Join-Path $userPath $chromium[$b]

            if (-not (Test-Path $src)) {
                Write-Host "  [SKIP] No $b history"
                continue
            }

            $dest = Join-Path $browserOut ($b + "_History.db")

            try {
                Copy-Item -LiteralPath $src -Destination $dest -Force -ErrorAction Stop
                Write-Host "  [OK] $b history copied"
                Write-Host "       Source: $src"
                Write-Host "       Target: $dest"
            } catch {
                Write-Host "  [FAIL] $b history copy failed"
                Write-Host "        Source: $src"
            }
        }

        # ---------------------------
        # Firefox history
        # ---------------------------
        $ffRoot = Join-Path $userPath "AppData\Roaming\Mozilla\Firefox\Profiles"

        if (Test-Path $ffRoot) {

            $profiles = Get-ChildItem -Path $ffRoot -Directory -ErrorAction SilentlyContinue

            if ($profiles) {
                foreach ($p in $profiles) {

                    $places = Join-Path $p.FullName "places.sqlite"

                    if (-not (Test-Path $places)) {
                        Write-Host "  [SKIP] No Firefox history ($($p.Name))"
                        continue
                    }

                    $dest = Join-Path $browserOut ("Firefox_" + $p.Name + "_places.db")

                    try {
                        Copy-Item -LiteralPath $places -Destination $dest -Force -ErrorAction Stop
                        Write-Host "  [OK] Firefox history copied"
                        Write-Host "       Profile: $($p.Name)"
                        Write-Host "       Source : $places"
                        Write-Host "       Target : $dest"
                    } catch {
                        Write-Host "  [FAIL] Firefox history copy failed ($($p.Name))"
                        Write-Host "        Source: $places"
                    }
                }
            } else {
                Write-Host "  [SKIP] Firefox profiles directory empty"
            }

        } else {
            Write-Host "  [SKIP] No Firefox profiles directory"
        }

        Write-Host ""
    }


    # ==================================================
    # ZIP PACKAGING
    # ==================================================
    Write-Host "[*] Creating archive"

    $zipPath = Join-Path $scriptRoot "Security_Artifacts_Results.zip"
    Remove-Item $zipPath -Force -ErrorAction SilentlyContinue

    if (Get-Command Compress-Archive -ErrorAction SilentlyContinue) {
        Compress-Archive -Path $outRoot -DestinationPath $zipPath -Force -ErrorAction SilentlyContinue
    }

    $zipStatus = Test-Path $zipPath

    if ($zipStatus) {
        Write-Host "  [OK] Archive created: $zipPath"
    } else {
        Write-Host "  [FAIL] Archive creation failed"
    }

    # ==================================================
    # SUMMARY
    # ==================================================
    Write-Host ""
    Write-Host "[*] Collection summary"
    Write-Host "  Event logs : $eventLogSuccess / $eventLogTotal"
    Write-Host "  GPO report : $(if ($gpoStatus) { 'OK' } else { 'SKIPPED' })"
    Write-Host "  Users processed : $userCount"
    Write-Host "  Archive : $(if ($zipStatus) { 'OK' } else { 'FAIL' })"

    Write-Host ""
    Write-Host "[INFO] Security artefact collection completed."
}

Write-Phase "MENTAL MODEL & NEXT STEPS"

# ----------------------------
# Summary Hint
# ----------------------------
Invoke-Safe "Mental Checklist (What does this tell you?)" {
    Write-Host ""
    Write-Host @"
Ask yourself:
- Am I a domain user or something more?
- Is this a workstation, server or jump host?
- Do I have visibility into LDAP / DCs?
- Do I have special group memberships?
- Is this account interesting for Kerberos paths?
- Is lateral movement even possible from here?

This script does NOT exploit.
It tells you what kind of chessboard you are standing on.
"@
}

# ----------------------------
# Stop Transcript
# ----------------------------
try {
    Stop-Transcript | Out-Null
} catch {}

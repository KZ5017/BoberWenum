<#
BoberWenum.ps1
Passive Active Directory situational awareness enumerator
Read-only | Stable | AD-aware | Non-offensive
#>

$ErrorActionPreference = "SilentlyContinue"

# ----------------------------
# Helper: Safe execution block
# ----------------------------
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

# ----------------------------
# Identity Context
# ----------------------------
Invoke-Safe "Identity Context (Who am I?)" {
    Write-Host "User          : $(whoami)"
    Write-Host "User SID      : $([System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value)"

    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($id)

    Write-Host "Is Admin      : $($principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator))"
    Write-Host "Auth Type     : $($id.AuthenticationType)"
    Write-Host "Token Type    : $($id.ImpersonationLevel)"

    Write-Host "`nGroup Memberships:"
    whoami /groups
}

# ----------------------------
# Host Context
# ----------------------------
Invoke-Safe "Host Context (Where am I?)" {
    $cs = Get-WmiObject Win32_ComputerSystem
    $os = Get-WmiObject Win32_OperatingSystem

    Write-Host "Hostname      : $env:COMPUTERNAME"
    Write-Host "Domain Joined : $($cs.PartOfDomain)"
    Write-Host "Domain        : $($cs.Domain)"
    Write-Host "OS            : $($os.Caption)"
    Write-Host "OS Version    : $($os.Version)"
    Write-Host "Architecture  : $($os.OSArchitecture)"

    Write-Host "`nLogged-on users (best effort):"
    query user 2>$null
}

Invoke-Safe "Operating System & Build Context (Tiered, Passive)" {

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
# Local Privileges (Extended)
# ----------------------------
Invoke-Safe "Local Privileges" {

    Write-Host '[*] Raw privilege list (whoami /priv)'
    whoami /priv

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

# ----------------------------
# Domain Context
# ----------------------------
Invoke-Safe "Domain Context" {
    try {
        $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        $forest = $domain.Forest

        Write-Host "Domain Name        : $($domain.Name)"
        Write-Host "Domain SID         : $(([System.Security.Principal.NTAccount]$domain.Name).Translate([System.Security.Principal.SecurityIdentifier]).Value)"
        Write-Host "Forest             : $($forest.Name)"
        Write-Host "Domain Mode        : $($domain.DomainMode)"
        Write-Host "Forest Mode        : $($forest.ForestMode)"

        Write-Host "`nDomain Controllers:"
        $domain.DomainControllers | ForEach-Object {
            Write-Host " - $($_.Name)"
        }
    } catch {
        Write-Host "[-] Not in a domain or domain not reachable."
    }
}

# ----------------------------
# Domain Group Memberships
# ----------------------------
Invoke-Safe "Domain Group Memberships (High-value only)" {
    $groups = whoami /groups

    $interesting = @(
        "Domain Admins",
        "Enterprise Admins",
        "Account Operators",
        "Backup Operators",
        "Server Operators",
        "DnsAdmins",
        "Administrators"
    )

    foreach ($group in $interesting) {
        if ($groups -match $group) {
            Write-Host "[+] Member of: $group"
        }
    }
}

# ----------------------------
# LDAP Reachability
# ----------------------------
Invoke-Safe "LDAP / AD Reachability" {
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
# Current User AD Attributes
# ----------------------------
Invoke-Safe "Current User AD Attributes (Passive)" {
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

# ----------------------------
# Network Awareness (Passive)
# ----------------------------
Invoke-Safe "Network Awareness (Passive)" {
    Write-Host "IP Configuration:"
    ipconfig /all | findstr /I "IPv4 DNS DHCP"

    Write-Host "Listening TCP ports with owning process:`n"

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
        netstat -ano | findstr LISTEN
    }
}

Invoke-Safe "Running Processes (High Signal)" {

    $procs = Get-WmiObject Win32_Process

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
}

Invoke-Safe "Services (Details + Control Rights)" {

    $services = Get-WmiObject Win32_Service

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
}

# -------------------------------------------------------
# Deleted Active Directory Objects (Tombstones - Passive)
# -------------------------------------------------------
Invoke-Safe "Deleted Active Directory Objects (Tombstones - Passive)" {

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

        Write-Host "`n--- User: $($u.Name) ---"

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

# ----------------------------
# AD ACL Escalation-Risk Audit
# ----------------------------
Invoke-Safe "AD ACL Escalation-Risk Audit" {

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

    Write-Host "`n[+] Active Directory Delegation checks"

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

# ----------------------------
# Summary Hint
# ----------------------------
Invoke-Safe "Mental Checklist (What does this tell you?)" {
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

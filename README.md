# BoberWenum

**BoberWenum.ps1** is a passive Active Directory situational awareness enumerator designed for security assessments, internal audits, and controlled penetration testing scenarios.

It focuses on **read-only enumeration**, stability, and signal over noise.  
No exploitation. No modification. No assumptions.

---

## What is this?

BoberWenum is a **PowerShell-based enumeration script** that helps you understand:

- **Who you are** in a Windows / AD environment  
- **Where you are** (workstation, server, domain context)
- **What privileges, rights, and exposures** your current identity may have
- **Which escalation paths might exist**, purely from a configuration and permission perspective

It is intentionally **non-offensive** and **passive** by design.

---

## What is it for?

This tool is useful when you want to:

- Quickly build **situational awareness** after initial access
- Support **manual privilege escalation analysis**
- Validate **Active Directory hardening assumptions**
- Assist blue team, purple team, or red team workflows
- Use as a **mental map**, not an autopilot

Think of it as answering:

> *“What kind of chessboard am I standing on?”*

---

## How to use

Run it from a PowerShell prompt:

```powershell
powershell -ExecutionPolicy Bypass -File BoberWenum.ps1
```
No parameters are required.

---

## What does it enumerate?

### Identity & Host Context

- Current user, SID, token type, admin status
    
- Group memberships (local and domain)
    
- Hostname, OS version, architecture
    
- Domain join status and logged-on users
    

### Local Privileges

- Full `whoami /priv` output
    
- Highlighting of **dangerous enabled privileges** (e.g. SeDebug, SeImpersonate, SeBackup, etc.)
    

### Active Directory Context

- Domain and forest information
    
- Domain controllers
    
- LDAP reachability
    
- Current user AD attributes
    
- High-value domain group memberships
    

### Network Awareness (Passive)

- IP configuration summary
    
- Listening TCP ports with owning process and PID
    
- Safe fallback when modern cmdlets are unavailable
    

### Processes & Services

- Interesting running processes (owner, path, privilege context)
    
- Services with:
    
    - Non-SYSTEM run accounts
        
    - Potential service control permissions
        
    - Binary paths and states
        

### Active Directory Security & Escalation Surface

- AD object ACLs (users, groups, computers, OUs)
    
- Dangerous rights (GenericAll, WriteDACL, WriteOwner, etc.)
    
- Extended rights (DCSync-related GUIDs)
    
- Delegation types:
    
    - Unconstrained
        
    - Constrained (KCD)
        
    - Resource-Based Constrained Delegation (RBCD)
        
- SPN sanity checks
    

### Group Policy Risks

- GPO object ACL escalation risks
    
- SYSVOL file-level ACL misconfigurations
    
- Identification of writable or takeover-capable GPOs
    

### AD CS (Certificate Services)

- Certificate template misconfigurations (ESC-style risks)
    
- Template and CA ACL takeover paths
    
- Weak or dangerous enrollment properties
    

### DPAPI Artefacts (Presence Only)

- Master key locations
    
- Credential and vault artefacts
    
- Chrome login database presence  
    _(No decryption, no access attempts)_
    

### Miscellaneous

- Deleted AD object (tombstone) visibility
    
- BadSuccessor / dMSA **passive precondition assessment**
    
- Final mental checklist to help interpret findings
    

---

## What this tool is NOT

- ❌ It does **not exploit** anything
    
- ❌ It does **not modify** the system or AD
    
- ❌ It does **not replace** manual analysis
    
- ❌ It is **not** an automated privilege escalation framework
    

---

## Important note

BoberWenum is meant to be a **supporting tool**, not a substitute for expertise.

It helps surface _interesting conditions_, _risky configurations_, and _questions worth asking_ —  
but **context, experience, and careful verification are still essential**.

Treat its output as **leads**, not conclusions.

---

## Design principles

- Passive by default
    
- Read-only enumeration
    
- Stable and failure-tolerant
    
- Minimal dependencies
    
- Works with or without RSAT where possible
    
- Signal over noise
    

---

## Disclaimer

Use only on systems and environments you own or are explicitly authorized to assess.

---

## Author

Built for practitioners who prefer understanding the environment  
before touching it.

## 📜 License

MIT
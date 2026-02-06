```
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
```

# BoberWenum 🦫

**BoberWenum** is a passive, low-privilege–aware Windows enumeration script designed for post-compromise and internal assessment scenarios.  
Its goal is to provide a structured, reliable overview of the local system, domain context, and Active Directory attack surface **without exploitation or modification**.

The script is intentionally defensive in execution: every enumeration block is isolated, error-tolerant, and designed to degrade gracefully when privileges are insufficient.

---

## Design Goals

- **Low-priv friendly**  
  Works in restricted environments (e.g. WinRM shells, service accounts, limited domain users).
- **Passive by default**  
  No exploitation, no state changes, no privilege escalation attempts.
- **High signal, low noise**  
  Focuses on information that actually matters during triage.
- **Modular and extensible**  
  Independent execution blocks with clear scope and purpose.
- **Honest output**  
  Distinguishes between *“not present”* and *“not accessible”*.

---

## How to use

Run it from a PowerShell prompt:

```powershell
powershell -ExecutionPolicy Bypass -File BoberWenum.ps1
```
No parameters are required.

---

## High-Level Structure

The script is organized into logical phases, each representing a different layer of situational awareness:

1. **Identity & Execution Context**
2. **Host & Operating System Context**
3. **Domain & Directory Reality Check**
4. **Local & Network Awareness**
5. **Active Directory Attack Surface (Passive)**
6. **Historical & Sensitive Artefacts**
7. **Targeted Enumeration & Collection**
8. **Mental Model & Next Steps**

Each section is visually separated and executed via a safe wrapper to prevent partial failures from breaking the run.

---

## Key Capabilities

### Identity & Token Context
- Current user identity and SID
- Group memberships
- Token type and authentication context
- Local privilege analysis with risk classification

### Host & OS Enumeration (Low-Priv Safe)
- Hostname, architecture
- Domain join status (registry + environment based)
- OS version and build (tiered fallback logic)
- Logged-on user snapshot

### Domain & Active Directory Awareness
- LDAP reachability check
- Domain and forest metadata
- Domain controllers
- High-value domain and local group memberships
- Current user AD attributes (passive lookup)

### Network Awareness
- IP configuration
- Hosts file inspection
- Listening TCP ports with owning processes
- Graceful fallback to native tools when needed

### Process & Service Inspection
- High-signal running process detection
- Tiered process enumeration (WMI → native fallback)
- Service discovery with:
  - Run-as account analysis
  - Start type interpretation
  - Auto-start non-SYSTEM detection
  - Registry-based fallback when WMI is blocked

### Active Directory Attack Surface (Passive)
- AD ACL escalation risk analysis
- Delegation enumeration:
  - Unconstrained
  - Constrained (KCD)
  - Resource-based constrained delegation (RBCD)
- GPO ACL escalation risks
- SYSVOL file-level permission risks
- ADCS certificate template and CA misconfiguration checks
- BadSuccessor / dMSA environmental assessment (passive)

### Historical & Sensitive Artefacts
- Deleted AD object (tombstone) enumeration
- DPAPI artefact presence checks (no decryption)

### Targeted File Enumeration
- Fast, deduplicated file search
- Focused extension whitelist
- Local paths + dynamically discovered network shares
- Read-only, ACL-aware traversal

### Security Artefact Collection
- Event log export (where permitted)
- GPO result report
- User artefact collection:
  - PowerShell history
  - Browser history (Chromium & Firefox)
- Optional ZIP packaging
- Explicit reporting of what was collected vs skipped

---

## Output Characteristics

- Console output is structured and readable.
- Where supported, output can be captured via PowerShell transcript.
- Native command limitations are handled explicitly.
- Errors are contextualized, not silent.

---

## What This Script Is **Not**

- ❌ Not an exploitation framework  
- ❌ Not an auto-escalation tool  
- ❌ Not stealth-optimized malware  

This script answers one question:

> **“What kind of environment am I standing in, and what attack paths might exist?”**

---

## Intended Use Cases

- Internal penetration testing
- Red team post-compromise triage
- CTF and lab environments
- Incident response context discovery
- Learning and research

---

## Disclaimer

This tool performs **read-only enumeration only**.  
It does not modify system state, abuse permissions, or exploit vulnerabilities.

Use responsibly and only on systems you are authorized to assess.

---

## Author Notes

BoberWenum is intentionally conservative in execution and explicit in reporting.  
If something cannot be enumerated due to privilege or access limitations, the script will say so.

That behavior is by design.

---

## 📜 License

MIT
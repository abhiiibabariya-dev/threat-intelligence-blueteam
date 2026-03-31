# CrowdStrike Falcon Detection Rules & Policies

Comprehensive Indicators of Attack (IOA), Indicators of Compromise (IOC), prevention policies, and threat hunting queries for CrowdStrike Falcon across **Windows, Linux, and macOS** platforms.

## Contents

### Custom IOA Rules
| File | Platform | Rules | Description |
|------|----------|-------|-------------|
| `custom-ioa/process-based-detections.yml` | Windows | 8 | PowerShell, LSASS, LOLBins, ransomware, fileless, injection, Cobalt Strike, Mimikatz |
| `custom-ioa/network-detections.yml` | All | 5 | C2 beaconing, DNS exfil, SMB lateral movement, TLS abuse, Tor/proxy |
| `custom-ioa/credential-theft-detections.yml` | Windows | 8 | LSASS, Comsvcs, Mimikatz, SAM/SYSTEM, DCSync, Kerberoasting, vaults, NTDS.dit |
| `custom-ioa/persistence-detections.yml` | Windows | 6 | Registry run keys, scheduled tasks, WMI, services, DLL hijacking, startup folder |
| `custom-ioa/defense-evasion-detections.yml` | Windows | 7 | Injection, masquerading, AMSI bypass, ETW patching, log clearing, Defender disable |
| `custom-ioa/linux-process-detections.yml` | Linux | 8 | Reverse shells, SUID/SGID privesc, container escape, cryptomining, cred theft, persistence, defense evasion, lateral movement |
| `custom-ioa/macos-process-detections.yml` | macOS | 7 | Reverse shells, persistence (LaunchAgent/Daemon), keychain theft, Gatekeeper bypass, privesc, lateral movement, malware families |

### IOC Definitions
| File | Platform | Description |
|------|----------|-------------|
| `custom-ioa/ioc-definitions.yml` | All | Hash IOCs, network IOCs (IPs/domains/URLs), file IOCs, behavioral IOCs, API integration, feed management |

### Prevention Policies
| File | Platform | Policies | Description |
|------|----------|----------|-------------|
| `custom-ioa/prevention-policies.yml` | All | 9 | Windows (Workstation, Server, DC), Linux (Server, Container, Critical), macOS (Standard, VIP, Developer) |

### Hunting Queries
| File | Platform | Queries | Description |
|------|----------|---------|-------------|
| `hunting-queries/falcon-lql-queries.md` | All | 37 | LQL queries: 13 Windows + 12 Linux + 12 macOS |

### Training & Reference
| File | Description |
|------|-------------|
| `training/zero-to-hero-crowdstrike.md` | Complete CrowdStrike training guide |

## Platform Coverage Summary

| Category | Windows | Linux | macOS |
|----------|---------|-------|-------|
| Process IOA Rules | 8 | 8 | 7 |
| Network IOA Rules | 5 (shared) | 5 (shared) | 5 (shared) |
| Credential Theft Rules | 8 | Included | Included |
| Persistence Rules | 6 | Included | Included |
| Defense Evasion Rules | 7 | Included | Included |
| IOC Definitions | Hash, Network, File, Behavioral | Hash, Network, File, Behavioral | Hash, Network, File, Behavioral |
| Prevention Policies | 3 (Workstation, Server, DC) | 3 (Server, Container, Critical) | 3 (Standard, VIP, Developer) |
| Hunting Queries (LQL) | 13 | 12 | 12 |
| **Total Rules** | **47+** | **30+** | **27+** |

## Deployment

### Quick Start
1. Navigate to **Falcon Console > Custom IOA Rule Groups**
2. Create rule groups per category (process, network, credential, etc.)
3. Add rules using the detection logic from YAML files
4. Assign rule groups to appropriate **Host Groups**
5. Set rules to **Detect** mode initially; promote to **Prevent** after tuning

### Prevention Policy Deployment
1. Navigate to **Falcon Console > Prevention Policies**
2. Create policies per platform using `prevention-policies.yml`
3. Assign to Host Groups (defined in the policies file)
4. Follow the 4-stage deployment: **Monitor → Detect → Prevent → Aggressive**

### IOC Management
1. Upload hash/network/file IOCs via **Falcon Console > IOC Management** or API
2. Configure threat intel feed integration (Falcon X, MISP, OTX, Abuse.ch)
3. Set IOC expiration policies per type (hashes: 180d, IPs: 30d, domains: 90d)
4. Review and tune IOCs monthly

### Host Groups
| Group | Platform | Policy |
|-------|----------|--------|
| Windows Workstations | Windows | WIN-WKS-STD-001 |
| Windows Servers | Windows | WIN-SRV-STD-001 |
| Domain Controllers | Windows | WIN-DC-001 |
| Linux Servers | Linux | LNX-SRV-STD-001 |
| Container Hosts | Linux | LNX-CTR-001 |
| Critical Linux Infra | Linux | LNX-CRIT-001 |
| macOS Workstations | macOS | MAC-WKS-STD-001 |
| macOS Executives/VIP | macOS | MAC-VIP-001 |
| macOS Developers | macOS | MAC-DEV-001 |

## Tuning Guidance

### Windows
- Exclude known SCCM/ConfigMgr from PowerShell detections
- Whitelist legitimate LSASS access from security tooling
- Baseline normal DNS query volumes before DNS exfiltration rules
- Test LOLBin rules against software deployment tooling

### Linux
- Exclude container runtimes (dockerd, containerd, kubelet) from process rules
- Whitelist legitimate cron jobs and systemd services
- Tune SSH tunneling rules for admin jump hosts
- Exclude backup tools from file integrity monitoring

### macOS
- Exclude Xcode and developer tools from unsigned binary detection
- Whitelist Homebrew paths for developer machines
- Tune keychain access monitoring for legitimate apps
- Exclude IT management tools from ARD abuse detection

## MITRE ATT&CK Coverage

All rules are mapped to MITRE ATT&CK v14.1. Coverage spans:
- **Initial Access**: Phishing detection, drive-by compromise
- **Execution**: PowerShell, scripting, LOLBins, osascript, container exec
- **Persistence**: Registry, scheduled tasks, cron, systemd, Launch Agents/Daemons
- **Privilege Escalation**: SUID/SGID, sudo, dylib injection, container escape
- **Defense Evasion**: AMSI bypass, Gatekeeper bypass, log tampering, timestomping
- **Credential Access**: LSASS, Mimikatz, Keychain, shadow file, browser creds
- **Discovery**: Network scanning, system enumeration
- **Lateral Movement**: SSH, SMB, PsExec, ARD
- **Command & Control**: Beaconing, DNS tunneling, Tor, encrypted channels
- **Exfiltration**: DNS exfil, data staging, cloud upload
- **Impact**: Ransomware, cryptomining, resource hijacking

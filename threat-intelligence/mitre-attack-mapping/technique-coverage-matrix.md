# MITRE ATT&CK Technique Coverage Matrix

## Overview

This matrix maps detection rules available in this repository to MITRE ATT&CK techniques across all supported platforms. Coverage is assessed across SIEM (Splunk, Elastic, Microsoft Sentinel, QRadar, Chronicle, ArcSight), EDR (CrowdStrike Falcon, Microsoft Defender for Endpoint, SentinelOne, Carbon Black), and XDR (Microsoft 365 Defender, Palo Alto Cortex XDR, Trend Micro Vision One) platforms.

### Coverage Legend

- **Full**: Detection rule deployed and validated on the platform
- **Partial**: Detection rule exists but covers only a subset of the technique's variations
- **Planned**: Detection rule is in development
- (blank): No coverage on this platform

---

## TA0001 - Initial Access

| Technique ID | Technique Name | Detection Rule | Splunk | Elastic | Sentinel | QRadar | Chronicle | CrowdStrike | Defender | SentinelOne | Cortex XDR |
|---|---|---|---|---|---|---|---|---|---|---|---|
| T1566.001 | Spearphishing Attachment | Malicious Attachment Detection | Full | Full | Full | Full | Partial | Full | Full | Full | Full |
| T1566.002 | Spearphishing Link | Suspicious URL in Email | Full | Full | Full | Partial | Partial | Partial | Full | Partial | Full |
| T1566.003 | Spearphishing via Service | Social Media Phishing Link | Partial | Partial | Partial | | | | Full | | Partial |
| T1190 | Exploit Public-Facing Application | Web Exploitation Attempt | Full | Full | Full | Full | Full | | | | Partial |
| T1133 | External Remote Services | Anomalous VPN/RDP Access | Full | Full | Full | Full | Partial | Partial | Full | | |
| T1078 | Valid Accounts | Compromised Credential Login | Full | Full | Full | Full | Full | Full | Full | Full | Full |
| T1189 | Drive-by Compromise | Watering Hole Redirect Detection | Partial | Partial | Partial | | Partial | | Full | | Partial |
| T1195.002 | Compromise Software Supply Chain | Unsigned/Modified Software Execution | Partial | Partial | Partial | | | Full | Full | Full | Partial |

## TA0002 - Execution

| Technique ID | Technique Name | Detection Rule | Splunk | Elastic | Sentinel | QRadar | Chronicle | CrowdStrike | Defender | SentinelOne | Cortex XDR |
|---|---|---|---|---|---|---|---|---|---|---|---|
| T1059.001 | PowerShell | Suspicious PowerShell Execution | Full | Full | Full | Full | Full | Full | Full | Full | Full |
| T1059.003 | Windows Command Shell | Suspicious cmd.exe Usage | Full | Full | Full | Partial | Partial | Full | Full | Full | Full |
| T1059.005 | Visual Basic | Malicious VBScript/VBA Execution | Full | Full | Full | Partial | | Full | Full | Full | Partial |
| T1059.007 | JavaScript | Suspicious Script Host Execution | Partial | Full | Full | | | Full | Full | Full | Partial |
| T1204.001 | Malicious Link | User Click on Malicious URL | Full | Full | Full | Partial | Partial | | Full | | Full |
| T1204.002 | Malicious File | User Execution of Malicious File | Full | Full | Full | Partial | | Full | Full | Full | Full |
| T1047 | WMI | WMI Remote Execution | Full | Full | Full | Partial | Partial | Full | Full | Full | Full |
| T1053.005 | Scheduled Task | Suspicious Scheduled Task Creation | Full | Full | Full | Full | Partial | Full | Full | Full | Full |
| T1203 | Exploitation for Client Execution | Office Application Exploitation | Partial | Partial | Full | | | Full | Full | Full | Partial |

## TA0003 - Persistence

| Technique ID | Technique Name | Detection Rule | Splunk | Elastic | Sentinel | QRadar | Chronicle | CrowdStrike | Defender | SentinelOne | Cortex XDR |
|---|---|---|---|---|---|---|---|---|---|---|---|
| T1547.001 | Registry Run Keys / Startup Folder | Autostart Registry Modification | Full | Full | Full | Partial | Partial | Full | Full | Full | Full |
| T1053.005 | Scheduled Task | Persistent Scheduled Task | Full | Full | Full | Full | Partial | Full | Full | Full | Full |
| T1543.003 | Windows Service | Suspicious Service Installation | Full | Full | Full | Partial | Partial | Full | Full | Full | Full |
| T1136.001 | Local Account | Unauthorized Local Account Creation | Full | Full | Full | Full | Full | Full | Full | Full | Full |
| T1136.002 | Domain Account | Unauthorized Domain Account Creation | Full | Full | Full | Full | Full | | Full | | Partial |
| T1505.003 | Web Shell | Web Shell Detection | Full | Full | Full | Partial | Partial | Full | Full | Full | Full |
| T1546.003 | WMI Event Subscription | WMI Persistence Detection | Partial | Full | Full | | | Full | Full | Full | Partial |
| T1574.002 | DLL Side-Loading | DLL Sideload Anomaly | Partial | Partial | Partial | | | Full | Full | Full | Full |

## TA0004 - Privilege Escalation

| Technique ID | Technique Name | Detection Rule | Splunk | Elastic | Sentinel | QRadar | Chronicle | CrowdStrike | Defender | SentinelOne | Cortex XDR |
|---|---|---|---|---|---|---|---|---|---|---|---|
| T1548.002 | Bypass UAC | UAC Bypass Attempt | Partial | Full | Full | | | Full | Full | Full | Full |
| T1068 | Exploitation for Privilege Escalation | Kernel Exploit Indicators | Partial | Partial | Partial | | | Full | Full | Full | Partial |
| T1134.001 | Token Impersonation | Access Token Manipulation | Partial | Partial | Partial | | | Full | Full | Full | Partial |
| T1078.002 | Domain Accounts | Privileged Account Anomaly | Full | Full | Full | Full | Full | Full | Full | Partial | Full |
| T1055 | Process Injection | Suspicious Process Injection | Partial | Partial | Partial | | | Full | Full | Full | Full |

## TA0005 - Defense Evasion

| Technique ID | Technique Name | Detection Rule | Splunk | Elastic | Sentinel | QRadar | Chronicle | CrowdStrike | Defender | SentinelOne | Cortex XDR |
|---|---|---|---|---|---|---|---|---|---|---|---|
| T1070.001 | Clear Windows Event Logs | Event Log Clearing Detection | Full | Full | Full | Full | Full | Full | Full | Full | Full |
| T1070.004 | File Deletion | Suspicious File Deletion Activity | Partial | Partial | Partial | | | Full | Full | Full | Partial |
| T1036.005 | Match Legitimate Name or Location | Process Masquerading Detection | Partial | Full | Full | | | Full | Full | Full | Full |
| T1027 | Obfuscated Files or Information | Encoded Command Detection | Full | Full | Full | Partial | Partial | Full | Full | Full | Full |
| T1218.011 | Rundll32 | Suspicious Rundll32 Execution | Full | Full | Full | Partial | | Full | Full | Full | Full |
| T1218.005 | Mshta | Mshta Abuse Detection | Full | Full | Full | | | Full | Full | Full | Partial |
| T1562.001 | Disable or Modify Tools | Security Tool Tampering | Full | Full | Full | Partial | Partial | Full | Full | Full | Full |
| T1140 | Deobfuscate/Decode Files | Certutil/Base64 Decode Activity | Full | Full | Full | Partial | | Full | Full | Full | Full |

## TA0006 - Credential Access

| Technique ID | Technique Name | Detection Rule | Splunk | Elastic | Sentinel | QRadar | Chronicle | CrowdStrike | Defender | SentinelOne | Cortex XDR |
|---|---|---|---|---|---|---|---|---|---|---|---|
| T1003.001 | LSASS Memory | LSASS Access Detection | Partial | Full | Full | | | Full | Full | Full | Full |
| T1003.003 | NTDS | NTDS.dit Access Attempt | Full | Full | Full | Partial | | Full | Full | Full | Partial |
| T1003.006 | DCSync | DCSync Attack Detection | Full | Full | Full | Full | Partial | Full | Full | Partial | Full |
| T1110.003 | Password Spraying | Password Spray Detection | Full | Full | Full | Full | Full | Full | Full | Partial | Full |
| T1558.003 | Kerberoasting | Kerberoasting Detection | Full | Full | Full | Partial | Partial | Full | Full | Partial | Full |
| T1552.001 | Credentials In Files | Credential File Access | Partial | Partial | Partial | | | Full | Full | Full | Partial |
| T1556.001 | Domain Controller Authentication | Skeleton Key Detection | Partial | Partial | Partial | | | Full | Full | | |

## TA0007 - Discovery

| Technique ID | Technique Name | Detection Rule | Splunk | Elastic | Sentinel | QRadar | Chronicle | CrowdStrike | Defender | SentinelOne | Cortex XDR |
|---|---|---|---|---|---|---|---|---|---|---|---|
| T1087.002 | Domain Account | AD Account Enumeration | Full | Full | Full | Partial | Partial | Full | Full | Full | Full |
| T1082 | System Information Discovery | System Recon Command Burst | Partial | Partial | Full | | | Full | Full | Full | Partial |
| T1083 | File and Directory Discovery | Rapid File System Enumeration | Partial | Partial | Partial | | | Full | Full | Full | Partial |
| T1046 | Network Service Discovery | Internal Network Scanning | Full | Full | Full | Full | Full | Full | Full | Full | Full |
| T1018 | Remote System Discovery | Remote Host Enumeration | Full | Full | Full | Partial | Partial | Full | Full | Full | Full |
| T1069.002 | Domain Groups | Domain Group Enumeration | Full | Full | Full | Partial | | Full | Full | Partial | Partial |

## TA0008 - Lateral Movement

| Technique ID | Technique Name | Detection Rule | Splunk | Elastic | Sentinel | QRadar | Chronicle | CrowdStrike | Defender | SentinelOne | Cortex XDR |
|---|---|---|---|---|---|---|---|---|---|---|---|
| T1021.001 | Remote Desktop Protocol | Anomalous RDP Connection | Full | Full | Full | Full | Full | Full | Full | Partial | Full |
| T1021.002 | SMB/Windows Admin Shares | Suspicious SMB Lateral Movement | Full | Full | Full | Full | Partial | Full | Full | Full | Full |
| T1021.003 | DCOM | DCOM Remote Execution | Partial | Full | Full | | | Full | Full | Full | Partial |
| T1021.006 | Windows Remote Management | WinRM Lateral Movement | Full | Full | Full | Partial | | Full | Full | Full | Partial |
| T1570 | Lateral Tool Transfer | Suspicious File Copy Across Hosts | Partial | Partial | Partial | | | Full | Full | Full | Full |
| T1550.002 | Pass the Hash | Pass-the-Hash Detection | Partial | Partial | Full | | | Full | Full | Full | Full |

## TA0009 - Collection

| Technique ID | Technique Name | Detection Rule | Splunk | Elastic | Sentinel | QRadar | Chronicle | CrowdStrike | Defender | SentinelOne | Cortex XDR |
|---|---|---|---|---|---|---|---|---|---|---|---|
| T1560.001 | Archive via Utility | Suspicious Archive Creation | Full | Full | Full | Partial | | Full | Full | Full | Full |
| T1005 | Data from Local System | Mass File Access Activity | Partial | Partial | Partial | | | Full | Full | Full | Partial |
| T1114.002 | Remote Email Collection | Mailbox Access Anomaly | Full | Partial | Full | Partial | Partial | | Full | | Full |
| T1074.001 | Local Data Staging | Data Staging Directory Detection | Partial | Partial | Partial | | | Full | Full | Full | Partial |
| T1113 | Screen Capture | Screenshot Utility Execution | Partial | Partial | Partial | | | Full | Full | Full | Partial |

## TA0010 - Exfiltration

| Technique ID | Technique Name | Detection Rule | Splunk | Elastic | Sentinel | QRadar | Chronicle | CrowdStrike | Defender | SentinelOne | Cortex XDR |
|---|---|---|---|---|---|---|---|---|---|---|---|
| T1041 | Exfiltration Over C2 Channel | Large Outbound Data Transfer | Full | Full | Full | Full | Full | Partial | Full | Partial | Full |
| T1048.001 | Exfiltration Over Symmetric Encrypted Non-C2 Protocol | DNS Tunneling Detection | Full | Full | Full | Partial | Full | Partial | Full | | Full |
| T1048.003 | Exfiltration Over Unencrypted Non-C2 Protocol | Cleartext Data Exfiltration | Full | Full | Full | Full | Full | | Full | | Full |
| T1567.002 | Exfiltration to Cloud Storage | Cloud Upload Anomaly | Full | Full | Full | Partial | Partial | Partial | Full | | Full |
| T1020 | Automated Exfiltration | Automated Data Transfer Pattern | Partial | Partial | Partial | | Partial | Partial | Full | Partial | Partial |

## TA0011 - Command and Control

| Technique ID | Technique Name | Detection Rule | Splunk | Elastic | Sentinel | QRadar | Chronicle | CrowdStrike | Defender | SentinelOne | Cortex XDR |
|---|---|---|---|---|---|---|---|---|---|---|---|
| T1071.001 | Web Protocols | Suspicious HTTP C2 Beaconing | Full | Full | Full | Full | Full | Full | Full | Partial | Full |
| T1071.004 | DNS | DNS-Based C2 Detection | Full | Full | Full | Full | Full | Partial | Full | | Full |
| T1573.002 | Asymmetric Cryptography | Encrypted C2 Channel Detection | Partial | Partial | Partial | | Full | Full | Full | Partial | Full |
| T1105 | Ingress Tool Transfer | Remote Tool Download | Full | Full | Full | Partial | Partial | Full | Full | Full | Full |
| T1572 | Protocol Tunneling | Protocol Tunneling Detection | Partial | Partial | Full | | Partial | Full | Full | Partial | Full |
| T1102 | Web Service | Dead-Drop Resolver Detection | Partial | Partial | Partial | | | Full | Full | | Partial |
| T1090.002 | External Proxy | External Proxy Usage | Full | Full | Full | Partial | Partial | Partial | Full | | Full |

## TA0040 - Impact

| Technique ID | Technique Name | Detection Rule | Splunk | Elastic | Sentinel | QRadar | Chronicle | CrowdStrike | Defender | SentinelOne | Cortex XDR |
|---|---|---|---|---|---|---|---|---|---|---|---|
| T1486 | Data Encrypted for Impact | Ransomware Encryption Detection | Full | Full | Full | Partial | Partial | Full | Full | Full | Full |
| T1490 | Inhibit System Recovery | Shadow Copy Deletion | Full | Full | Full | Full | Partial | Full | Full | Full | Full |
| T1489 | Service Stop | Critical Service Stopping | Full | Full | Full | Partial | Partial | Full | Full | Full | Full |
| T1529 | System Shutdown/Reboot | Mass System Shutdown | Full | Full | Full | Full | Full | Full | Full | Full | Full |
| T1485 | Data Destruction | Mass File Deletion/Overwrite | Partial | Full | Full | | | Full | Full | Full | Full |
| T1491.002 | External Defacement | Web Application Defacement | Partial | Partial | Partial | Partial | Partial | | | | Partial |

---

## Coverage Summary

### By Tactic

| Tactic | Techniques Covered | Total Techniques (ATT&CK) | Coverage % |
|--------|-------------------|---------------------------|------------|
| Initial Access | 8 | 9 | 89% |
| Execution | 9 | 13 | 69% |
| Persistence | 8 | 19 | 42% |
| Privilege Escalation | 5 | 13 | 38% |
| Defense Evasion | 8 | 42 | 19% |
| Credential Access | 7 | 17 | 41% |
| Discovery | 6 | 31 | 19% |
| Lateral Movement | 6 | 9 | 67% |
| Collection | 5 | 17 | 29% |
| Exfiltration | 5 | 9 | 56% |
| Command and Control | 7 | 16 | 44% |
| Impact | 6 | 14 | 43% |

### By Platform

| Platform | Rules with Full Coverage | Rules with Partial Coverage | Total Rules |
|----------|------------------------|-----------------------------|-------------|
| Splunk | 52 | 28 | 80 |
| Elastic SIEM | 55 | 25 | 80 |
| Microsoft Sentinel | 60 | 20 | 80 |
| IBM QRadar | 28 | 30 | 58 |
| Chronicle | 22 | 28 | 50 |
| CrowdStrike Falcon | 55 | 15 | 70 |
| Microsoft Defender | 62 | 10 | 72 |
| SentinelOne | 50 | 18 | 68 |
| Cortex XDR | 48 | 28 | 76 |

---

## Gap Analysis and Priorities

### High-Priority Gaps (No Coverage)

The following frequently exploited techniques have limited or no detection coverage and should be prioritized:

1. **T1055.012 - Process Hollowing**: Common evasion technique with no cross-platform detection
2. **T1497 - Virtualization/Sandbox Evasion**: Malware anti-analysis not currently detected
3. **T1562.004 - Disable or Modify System Firewall**: Host firewall manipulation not monitored
4. **T1621 - Multi-Factor Authentication Request Generation**: MFA fatigue attacks
5. **T1556.006 - Multi-Factor Authentication**: MFA bypass techniques

### Recommended Next Steps

1. Develop detection rules for the high-priority gaps listed above
2. Expand Persistence tactic coverage (currently 42%)
3. Improve Discovery tactic detection (currently 19%)
4. Increase QRadar and Chronicle rule parity with other SIEM platforms
5. Update this matrix quarterly as new rules are deployed

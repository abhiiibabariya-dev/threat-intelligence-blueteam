# EDR Detection Rules

This directory contains production-ready detection rules, hunting queries, and custom indicators of attack (IOA) for major Endpoint Detection and Response (EDR) platforms.

## Platforms Covered

| Platform | Directory | Content |
|---|---|---|
| CrowdStrike Falcon | `crowdstrike-falcon/` | Custom IOA rules for process-based and network-based detections |
| Microsoft Defender for Endpoint | `microsoft-defender-endpoint/` | KQL advanced hunting queries and custom detection rules |
| SentinelOne | `sentinelone/` | Deep Visibility queries in JSON format |
| VMware Carbon Black | `carbon-black/` | Watchlist definitions and investigation queries |

## MITRE ATT&CK Coverage

All rules are mapped to the MITRE ATT&CK framework (v14). Primary technique coverage includes:

- **Initial Access** - Phishing payloads, drive-by compromise indicators
- **Execution** - PowerShell abuse, scripting engines, LOLBins
- **Persistence** - Registry run keys, scheduled tasks, services
- **Privilege Escalation** - Token manipulation, process injection
- **Defense Evasion** - Fileless techniques, process hollowing, signed binary proxy execution
- **Credential Access** - LSASS dumping, credential harvesting
- **Lateral Movement** - SMB, WMI, PsExec, RDP
- **Command and Control** - Beaconing, DNS tunneling, encrypted channels
- **Exfiltration** - DNS-based exfiltration, staging
- **Impact** - Ransomware encryption, data destruction

## Usage

Each platform directory contains a README with platform-specific deployment instructions. Rules should be reviewed, tested in a staging environment, and tuned for your organization's baseline before production deployment.

## Severity Levels

All rules use a standardized severity scale:

| Level | Description |
|---|---|
| Critical | Confirmed malicious activity requiring immediate response |
| High | Strong indicators of compromise requiring urgent investigation |
| Medium | Suspicious activity that may indicate compromise |
| Low | Anomalous behavior for baselining and awareness |
| Informational | Context-enrichment events for correlation |

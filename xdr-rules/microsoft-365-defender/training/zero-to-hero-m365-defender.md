# Microsoft 365 Defender Zero-to-Hero Training Guide

## 1. Introduction
Microsoft 365 Defender is Microsoft's XDR platform unifying Defender for Endpoint, Identity, Office 365, and Cloud Apps into a single portal with cross-workload advanced hunting.

## 2. Architecture
- **Defender for Endpoint (MDE)** - EDR for devices
- **Defender for Identity (MDI)** - AD/identity threat detection
- **Defender for Office 365 (MDO)** - Email/collaboration protection
- **Defender for Cloud Apps (MDCA)** - SaaS security (CASB)
- **Advanced Hunting** - Unified KQL across all workloads

## 3. Advanced Hunting Tables
| Table | Source | Contains |
|-------|--------|----------|
| `DeviceProcessEvents` | MDE | Process execution |
| `DeviceNetworkEvents` | MDE | Network connections |
| `DeviceFileEvents` | MDE | File operations |
| `DeviceLogonEvents` | MDE | Device authentication |
| `DeviceRegistryEvents` | MDE | Registry changes |
| `IdentityLogonEvents` | MDI | AD authentication |
| `IdentityDirectoryEvents` | MDI | AD changes |
| `EmailEvents` | MDO | Email metadata |
| `EmailAttachmentInfo` | MDO | Attachment details |
| `EmailUrlInfo` | MDO | URLs in emails |
| `CloudAppEvents` | MDCA | SaaS app activity |
| `AlertEvidence` | All | Alert details |

## 4. Cross-Workload Hunting (KQL)

### Email → Endpoint Attack Chain
```kql
// Find users who received malicious email then had suspicious process
let MaliciousEmails = EmailEvents
| where ThreatTypes has "Malware" or ThreatTypes has "Phish"
| project RecipientEmailAddress, NetworkMessageId, Subject, Timestamp;
DeviceProcessEvents
| where InitiatingProcessFileName in ("winword.exe","excel.exe","outlook.exe")
| where FileName in ("cmd.exe","powershell.exe","wscript.exe")
| join kind=inner (MaliciousEmails) on $left.AccountUpn == $right.RecipientEmailAddress
| project Timestamp, DeviceName, AccountName, Subject, FileName, ProcessCommandLine
```

### Identity + Endpoint Correlation
```kql
// Failed identity logins followed by endpoint compromise
let SuspiciousLogins = IdentityLogonEvents
| where ActionType == "LogonFailed" and Protocol == "Kerberos"
| summarize FailCount = count() by AccountUpn, IPAddress
| where FailCount > 10;
DeviceLogonEvents
| where ActionType == "LogonSuccess"
| join kind=inner SuspiciousLogins on $left.AccountName == $right.AccountUpn
| project Timestamp, DeviceName, AccountName, RemoteIP, FailCount
```

## 5. Custom Detections
Create from Advanced Hunting:
1. Run KQL → verify results
2. "Create detection rule"
3. Configure: frequency, severity, MITRE, actions
4. Actions: Generate alert, isolate device, disable user, collect investigation package

## 6. Automated Investigation & Remediation (AIR)
M365 Defender automatically investigates alerts:
- Analyzes alert evidence
- Determines scope (affected entities)
- Recommends/executes remediation
- Configurable: Full auto, Semi-auto (approval), Manual only

## 7. Threat Analytics
Microsoft-published reports on active threats:
- Threat description and TTPs
- Analyst report with IOCs
- "Am I affected?" exposure check against your environment
- Recommended mitigations

## 8. Incident Management
- Incidents auto-correlate related alerts across workloads
- Single view: affected devices + users + mailboxes + apps
- Investigation graph showing attack chain
- One-click response actions

## 9. API
```bash
# Advanced Hunting via API
curl -X POST 'https://api.security.microsoft.com/api/advancedhunting/run' \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"Query":"DeviceProcessEvents | where FileName == \"mimikatz.exe\" | take 10"}'
```

## 10. Labs
### Lab 1: Cross-Workload Hunt
1. Search for phishing emails with attachments
2. Correlate with endpoint process execution
3. Map full attack chain

### Lab 2: Custom Detection
1. Write KQL for encoded PowerShell
2. Create detection rule with auto-isolate
3. Test and verify response

---
*Compatible with Microsoft 365 Defender | Last updated March 2026*

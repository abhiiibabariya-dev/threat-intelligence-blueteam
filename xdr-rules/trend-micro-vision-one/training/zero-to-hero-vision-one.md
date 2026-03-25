# Trend Micro Vision One Zero-to-Hero Training Guide

## 1. Introduction
Trend Micro Vision One is an XDR platform that correlates detections across email, endpoints, servers, cloud workloads, and networks into a single investigation view.

## 2. Architecture
- **Vision One Console** - Cloud SaaS management
- **Endpoint Sensors** - Apex One, Server & Workload Protection
- **Email Sensor** - Cloud App Security
- **Network Sensor** - Deep Discovery Inspector
- **Cloud Sensors** - Cloud One (Workload, Container, Conformity)

## 3. Search Queries
Vision One uses a structured search language:

```
# Process execution search
eventType:TELEMETRY_PROCESS AND processCmd:"powershell*-enc*"
| select endpointHostName, processCmd, parentCmd, actingUserName

# Network connection to suspicious port
eventType:TELEMETRY_NETWORK AND dstPort:4444
| select endpointHostName, srcIP, dstIP, dstPort

# File creation in startup
eventType:TELEMETRY_FILE AND objectFilePath:"*\\Startup\\*"
| select endpointHostName, objectFilePath, processCmd

# DNS query to suspicious TLD
eventType:TELEMETRY_DNS AND objectDomain:("*.tk" OR "*.xyz" OR "*.top")
| select endpointHostName, objectDomain, srcIP

# Registry modification (persistence)
eventType:TELEMETRY_REGISTRY AND objectRegistryKeyHandle:"*\\CurrentVersion\\Run*"
| select endpointHostName, objectRegistryKeyHandle, objectRegistryValue

# Lateral movement - RDP
eventType:TELEMETRY_NETWORK AND dstPort:3389 AND srcIP:"10.0.0.*"
| stats count by srcIP, dstIP

# Email with malicious attachment
eventType:TELEMETRY_EMAIL AND emailAttachmentName:"*.exe" OR emailAttachmentName:"*.js"
| select mailSender, mailRecipient, emailAttachmentName, emailSubject

# Credential dumping
eventType:TELEMETRY_PROCESS AND (processCmd:"*mimikatz*" OR processCmd:"*sekurlsa*" OR processCmd:"*procdump*lsass*")
| select endpointHostName, processCmd, actingUserName
```

## 4. Detection Models
Pre-built and custom detection models:

```yaml
# Custom detection model
name: "Encoded PowerShell from Office"
description: "Office application spawning encoded PowerShell"
severity: high
mitre: [T1059.001, T1204.002]
filters:
  - eventType: TELEMETRY_PROCESS
    conditions:
      - field: parentCmd
        operator: matchesAny
        values: ["*winword.exe*", "*excel.exe*", "*powerpnt.exe*"]
      - field: processCmd
        operator: contains
        value: "powershell*-enc"
response:
  - action: alert
  - action: isolate_endpoint
```

## 5. Workbench Investigation
- **Alert correlation** - Multiple detections → single Workbench alert
- **Execution profile** - Visual attack chain (like a process tree)
- **Impact scope** - All affected endpoints, users, emails, IPs
- **Response actions** - Isolate, collect, block, quarantine from Workbench

## 6. Response Actions
| Action | Scope |
|--------|-------|
| Isolate endpoint | Network quarantine |
| Collect file | Forensic collection |
| Terminate process | Kill running process |
| Block object | Hash/IP/domain/URL/sender |
| Quarantine email | Remove from mailbox |
| Reset password | Force password change |
| Submit for analysis | Sandbox detonation |

## 7. API
```bash
# Search
curl -X POST 'https://api.xdr.trendmicro.com/v3.0/search/data' \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"query":"eventType:TELEMETRY_PROCESS AND processCmd:\"*mimikatz*\"","startTime":"2026-03-01","endTime":"2026-03-02"}'

# Isolate endpoint
curl -X POST 'https://api.xdr.trendmicro.com/v3.0/response/endpoints/isolate' \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"endpointId":"eid-123","description":"Investigating compromise"}'
```

## 8. Use Cases
1. Email → endpoint attack chain (phishing to execution)
2. Lateral movement across segments (network + endpoint correlation)
3. Ransomware detection (file + process + network correlation)
4. Cloud workload compromise (container escape + host pivot)
5. Data exfiltration (endpoint + network bytes)
6. Credential theft (LSASS access cross-correlated)
7. Supply chain (unusual update behavior)
8. Insider threat (email + file + USB correlation)

## 9. Labs
### Lab 1: Workbench Investigation
1. Trigger multi-stage alert (email → download → execute)
2. Open in Workbench
3. Review execution profile and impact scope
4. Take response actions

### Lab 2: Custom Detection Model
1. Create model for LOLBAS execution
2. Deploy and test
3. Review alerts in Workbench

---
*Compatible with Trend Micro Vision One | Last updated March 2026*

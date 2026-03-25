# Microsoft Sentinel Zero-to-Hero Training Guide

## Table of Contents
1. [Introduction](#1-introduction)
2. [Architecture](#2-architecture)
3. [KQL Fundamentals](#3-kql-fundamentals)
4. [KQL Advanced](#4-kql-advanced)
5. [Analytics Rules](#5-analytics-rules)
6. [Hunting](#6-hunting)
7. [Workbooks](#7-workbooks)
8. [Playbooks & Automation](#8-playbooks)
9. [UEBA](#9-ueba)
10. [Threat Intelligence](#10-threat-intelligence)
11. [Content Hub](#11-content-hub)
12. [Cost Optimization](#12-cost-optimization)
13. [API & Automation](#13-api)
14. [Security Use Cases](#14-use-cases)
15. [Labs](#15-labs)

---

## 1. Introduction

Microsoft Sentinel is a cloud-native SIEM and SOAR solution built on Azure. It provides intelligent security analytics across the enterprise with AI-powered threat detection, investigation, and automated response.

**Key differentiators:** Cloud-scale data collection, built-in AI/ML, fusion detection, Logic Apps SOAR, UEBA, and deep Microsoft ecosystem integration.

---

## 2. Architecture

```
┌───────────────────────────────────────────────────────┐
│                  Microsoft Sentinel                     │
│  ┌──────────┐ ┌────────────┐ ┌──────────────────────┐│
│  │Data       │ │Analytics   │ │Automation             ││
│  │Connectors │ │Rules       │ │(Logic Apps/Playbooks) ││
│  └────┬─────┘ └──────┬─────┘ └──────────┬───────────┘│
│       │               │                   │            │
│  ┌────▼───────────────▼───────────────────▼──────────┐│
│  │         Log Analytics Workspace                    ││
│  │    (Stores all ingested data & alerts)             ││
│  └───────────────────────────────────────────────────┘│
└───────────────────────────────────────────────────────┘
```

### Key Components
- **Log Analytics Workspace** - Data storage and query engine
- **Data Connectors** - 300+ built-in (Microsoft, AWS, GCP, firewalls, etc.)
- **Analytics Rules** - Detection logic (scheduled, NRT, fusion, anomaly)
- **Incidents** - Correlated alerts for investigation
- **Workbooks** - Dashboards and visualizations
- **Playbooks** - Azure Logic Apps for automated response
- **Hunting** - Proactive threat hunting with KQL
- **UEBA** - User and Entity Behavior Analytics

---

## 3. KQL Fundamentals

### Basic Query Structure
```kql
// Table | filter | transform | output
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4625
| project TimeGenerated, Account, Computer, IpAddress
| sort by TimeGenerated desc
| take 100
```

### Essential Operators

#### where (filter)
```kql
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType != "0"        // Failed logins
| where UserPrincipalName !endswith "@external.com"
| where IPAddress != "10.0.0.1"
```

#### project (select columns)
```kql
SecurityEvent
| where EventID == 4624
| project TimeGenerated, Account, LogonType, IpAddress, Computer
```

#### extend (add calculated columns)
```kql
CommonSecurityLog
| extend GeoInfo = geo_info_from_ip_address(SourceIP)
| extend Country = tostring(GeoInfo.country)
| extend BytesMB = round(SentBytes / 1048576.0, 2)
| extend Severity = case(
    SentBytes > 1000000000, "Critical",
    SentBytes > 100000000, "High",
    SentBytes > 10000000, "Medium",
    "Low")
```

#### summarize (aggregate)
```kql
SigninLogs
| where ResultType != "0"
| summarize
    FailedAttempts = count(),
    UniqueUsers = dcount(UserPrincipalName),
    TargetedUsers = make_set(UserPrincipalName),
    FirstAttempt = min(TimeGenerated),
    LastAttempt = max(TimeGenerated)
  by IPAddress, bin(TimeGenerated, 1h)
| where FailedAttempts > 10
| sort by FailedAttempts desc
```

#### join
```kql
// Inner join failed logins with successful logins from same IP
let FailedLogins = SigninLogs | where ResultType != "0" | summarize Failures=count() by IPAddress;
let SuccessLogins = SigninLogs | where ResultType == "0" | summarize Successes=count() by IPAddress;
FailedLogins
| join kind=inner SuccessLogins on IPAddress
| where Failures > 10 and Successes > 0
| project IPAddress, Failures, Successes
```

#### union
```kql
union SecurityEvent, SigninLogs, AzureActivity
| where TimeGenerated > ago(1h)
| summarize count() by Type
```

#### let (variables)
```kql
let lookback = 24h;
let threshold = 10;
let suspiciousIPs = dynamic(["1.2.3.4", "5.6.7.8"]);
SigninLogs
| where TimeGenerated > ago(lookback)
| where IPAddress in (suspiciousIPs)
| summarize count() by UserPrincipalName
| where count_ > threshold
```

#### render (visualize)
```kql
SecurityEvent
| where EventID == 4625
| summarize count() by bin(TimeGenerated, 1h)
| render timechart
```

---

## 4. KQL Advanced

### arg_max / arg_min
```kql
// Get latest sign-in per user
SigninLogs
| summarize arg_max(TimeGenerated, *) by UserPrincipalName
```

### make_set / make_list / mv-expand
```kql
// Collect unique IPs per user, then expand
SigninLogs
| summarize UniqueIPs = make_set(IPAddress) by UserPrincipalName
| mv-expand UniqueIPs
| extend IP = tostring(UniqueIPs)
```

### parse / extract
```kql
// Parse structured text
Syslog
| parse SyslogMessage with * "src=" SrcIP:string " dst=" DstIP:string " port=" Port:int *
| project TimeGenerated, SrcIP, DstIP, Port

// Regex extract
SecurityEvent
| extend Domain = extract(@"(\w+)\\", 1, Account)
| extend Username = extract(@"\\(\w+)", 1, Account)
```

### series_decompose_anomalies (ML)
```kql
// Detect anomalies in login volume
let min_t = ago(14d);
let max_t = now();
SigninLogs
| make-series LoginCount = count() on TimeGenerated from min_t to max_t step 1h
| extend (anomalies, score, baseline) = series_decompose_anomalies(LoginCount, 2.5)
| mv-expand TimeGenerated, LoginCount, anomalies, score, baseline
| where anomalies == 1
```

### ipv4_is_in_range
```kql
CommonSecurityLog
| where ipv4_is_in_range(SourceIP, "10.0.0.0/8") == false
| where ipv4_is_in_range(DestinationIP, "10.0.0.0/8") == true
| summarize count() by SourceIP
```

---

## 5. Analytics Rules

### Scheduled Rule (KQL)
```kql
// Brute Force Detection - runs every 5 minutes
SigninLogs
| where TimeGenerated > ago(15m)
| where ResultType != "0"
| summarize FailureCount = count(), TargetAccounts = dcount(UserPrincipalName) by IPAddress
| where FailureCount > 20 or TargetAccounts > 5
| extend AlertTitle = strcat("Brute Force from ", IPAddress, " - ", FailureCount, " failures")
```

**Rule Configuration:**
- Frequency: 5 minutes
- Lookup: 15 minutes
- Alert threshold: >0 results
- Entity mapping: IP → IPAddress, Account → UserPrincipalName
- MITRE: T1110.001

### Near-Real-Time (NRT) Rule
NRT rules run every minute with ~1-minute latency. Use for high-severity detections:
```kql
SecurityEvent
| where EventID == 1102  // Security log cleared
| project TimeGenerated, Computer, Account
```

### Fusion Rules
Built-in ML-based multi-stage attack detection. Automatically correlates low-fidelity alerts into high-confidence incidents.

### Anomaly Rules
Built-in behavioral analytics that establish baselines and detect deviations.

---

## 6. Hunting

### Hunting Query Example
```kql
// Hunt: Encoded PowerShell from non-standard parents
DeviceProcessEvents
| where TimeGenerated > ago(7d)
| where FileName in ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine contains "-enc"
| where InitiatingProcessFileName !in ("explorer.exe", "cmd.exe", "svchost.exe")
| project TimeGenerated, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine
```

### Bookmarks
Save interesting findings during hunting for later investigation or to create incidents.

### Livestream
Monitor query results in real-time during active investigations.

---

## 7. Workbooks

Workbooks provide interactive dashboards. Create from Azure portal → Sentinel → Workbooks.

**Key parameters:** TimeRange, Subscription, Workspace, Severity filter

**Essential workbooks:**
- SOC Overview
- Investigation Insights
- Azure AD Sign-in Analysis
- Threat Intelligence
- MITRE ATT&CK Coverage

---

## 8. Playbooks & Automation

### Automation Rules
- Trigger: When incident is created/updated
- Actions: Change status, assign owner, run playbook, add tags

### Logic App Playbook (Trigger: Sentinel Incident)
```json
{
  "trigger": "Microsoft-Sentinel-Incident",
  "actions": [
    "Get-Incident-Entities",
    "For-Each-IP: Enrich-With-VirusTotal",
    "For-Each-IP: Check-TI-Indicators",
    "Add-Comment-To-Incident",
    "Update-Incident-Severity"
  ]
}
```

---

## 9. UEBA

Enable UEBA in Sentinel → Settings → UEBA.

**Entity pages** provide:
- Timeline of entity activity
- Peer group comparison
- Anomaly scores
- Investigation priority score

**Supported entities:** Users, Hosts, IP addresses, Azure resources

---

## 10. Threat Intelligence

### TI Connectors
- TAXII 2.0/2.1 feeds
- Microsoft Defender TI
- MISP integration
- CSV/STIX import

### TI Matching Analytics Rule
```kql
ThreatIntelligenceIndicator
| where Active == true
| join kind=inner (
    CommonSecurityLog
    | where TimeGenerated > ago(1h)
) on $left.NetworkIP == $right.DestinationIP
| project TimeGenerated, SourceIP, DestinationIP, ThreatType, Description
```

---

## 11. Content Hub

Install pre-built solutions from Content Hub:
- **Microsoft 365** - Sign-in analytics, mailbox rules
- **Azure Activity** - Subscription monitoring
- **Windows Security Events** - Endpoint detection
- **Threat Intelligence** - IOC matching

---

## 12. Cost Optimization

| Tier | Best For | Savings |
|------|----------|---------|
| Pay-as-you-go | <100 GB/day | Flexible |
| Commitment (100GB) | Predictable workloads | 50% |
| Basic Logs | Low-value, high-volume | 70% |
| Archive | Compliance retention | 90% |

**Tips:**
- Use Data Collection Rules (DCR) to filter before ingestion
- Route verbose logs to Basic Logs tier
- Use workspace transformation rules
- Set appropriate retention periods

---

## 13. API & Automation

```bash
# Azure CLI - List incidents
az sentinel incident list --resource-group myRG --workspace-name myWorkspace

# PowerShell - Create analytics rule
New-AzSentinelAlertRule -ResourceGroupName myRG -WorkspaceName myWorkspace -Kind Scheduled -DisplayName "Brute Force" -Query "SigninLogs | where ResultType != '0'" -QueryFrequency "PT5M"

# REST API - Get incidents
GET https://management.azure.com/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.OperationalInsights/workspaces/{ws}/providers/Microsoft.SecurityInsights/incidents?api-version=2023-11-01
```

---

## 14. Security Use Cases with KQL

### UC-1: Password Spray
```kql
SigninLogs
| where ResultType == "50126"
| summarize AttemptCount=count(), UniqueUsers=dcount(UserPrincipalName), Users=make_set(UserPrincipalName,10) by IPAddress, bin(TimeGenerated,1h)
| where UniqueUsers > 5
```

### UC-2: Impossible Travel
```kql
SigninLogs
| where ResultType == "0"
| summarize Locations=make_set(Location), LocationCount=dcount(Location) by UserPrincipalName, bin(TimeGenerated, 1h)
| where LocationCount > 1
```

### UC-3: Suspicious Mailbox Forwarding
```kql
OfficeActivity
| where Operation == "Set-Mailbox"
| where Parameters has "ForwardingSmtpAddress"
| project TimeGenerated, UserId, Parameters
```

### UC-4: Ransomware Shadow Copy Deletion
```kql
DeviceProcessEvents
| where FileName in ("vssadmin.exe","wmic.exe","bcdedit.exe")
| where ProcessCommandLine has_any ("delete shadows","shadowcopy delete","recoveryenabled no")
```

### UC-5: Privileged Role Assignment
```kql
AuditLogs
| where OperationName == "Add member to role"
| extend Role = tostring(TargetResources[0].modifiedProperties[1].newValue)
| where Role has_any ("Global Administrator","Security Administrator","Exchange Administrator")
```

---

## 15. Labs

### Lab 1: Build Brute Force Detection Pipeline
1. Enable Windows Security Events connector
2. Write KQL for >10 EventID 4625 per source in 5 min
3. Create scheduled analytics rule
4. Configure entity mapping (Account, IP)
5. Create automation rule to assign to SOC

### Lab 2: Threat Intelligence Matching
1. Import STIX2 threat indicators
2. Create TI matching analytics rule against network logs
3. Verify incidents are created for matches

### Lab 3: UEBA Investigation
1. Enable UEBA for Azure AD
2. Generate anomalous sign-in (VPN to different location)
3. Investigate via entity page
4. Document findings

### Lab 4: Automated Phishing Response
1. Create Logic App playbook
2. Trigger: new incident with "Phishing" tag
3. Actions: extract URLs, check VirusTotal, add comment, change severity

### Lab 5: Cost Optimization
1. Analyze current ingestion with Usage table
2. Identify high-volume, low-value log sources
3. Configure DCR to filter verbose events
4. Route candidates to Basic Logs
5. Calculate savings

---

*Last updated: March 2026 | Compatible with Microsoft Sentinel (GA)*

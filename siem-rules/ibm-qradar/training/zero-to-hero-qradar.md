# IBM QRadar Zero-to-Hero Training Guide

## 1. Introduction
IBM QRadar is an enterprise SIEM that collects, normalizes, and correlates security data from across the environment. It uses AQL (Ariel Query Language) for searching and custom rules for detection.

## 2. Architecture
```
┌────────────────────────────────────────────────┐
│              QRadar Console                     │
│  (Web UI, rule engine, offense management)     │
├────────────────────────────────────────────────┤
│         Event Processor (EP)                    │
│  (Parses, normalizes, correlates events)       │
├────────────────────────────────────────────────┤
│          Flow Processor (FP)                    │
│  (Network flow collection & analysis)          │
├────────────────────────────────────────────────┤
│           Data Node (DN)                        │
│  (Additional storage for high-volume)          │
├────────────────────────────────────────────────┤
│         Event Collector (EC)                    │
│  (Remote log collection point)                 │
└────────────────────────────────────────────────┘
```

**Key Ports:** 443 (Web UI), 514 (Syslog), 32000 (Event forwarding), 7777/7789 (Recon)

## 3. AQL (Ariel Query Language)

### Basic Syntax
```sql
SELECT sourceip, destinationip, categoryname(category), COUNT(*) as event_count
FROM events
WHERE eventname = 'Authentication Failure'
  AND INCIDR('10.0.0.0/8', sourceip)
LAST 24 HOURS
GROUP BY sourceip, destinationip, category
ORDER BY event_count DESC
LIMIT 50
```

### Key Functions
| Function | Purpose | Example |
|----------|---------|---------|
| `DATEFORMAT()` | Format timestamps | `DATEFORMAT(starttime, 'yyyy-MM-dd HH:mm')` |
| `CATEGORYNAME()` | Category ID to name | `CATEGORYNAME(category)` |
| `PROTOCOLNAME()` | Protocol ID to name | `PROTOCOLNAME(protocolid)` |
| `LOGSOURCENAME()` | Log source ID to name | `LOGSOURCENAME(logsourceid)` |
| `INCIDR()` | IP in subnet check | `INCIDR('10.0.0.0/8', sourceip)` |
| `ASSETHOSTNAME()` | IP to hostname | `ASSETHOSTNAME(sourceip)` |
| `REFERENCESETCONTAINS()` | Check reference set | `REFERENCESETCONTAINS('Malicious_IPs', sourceip)` |

### Common AQL Patterns

**Brute Force Detection:**
```sql
SELECT sourceip, destinationip, username,
       COUNT(*) as failures,
       MIN(starttime) as first_attempt,
       MAX(starttime) as last_attempt
FROM events
WHERE category = 8100  -- Authentication Failure
  AND INOFFENSE(FALSE)
LAST 1 HOURS
GROUP BY sourceip, destinationip, username
HAVING COUNT(*) > 10
ORDER BY failures DESC
```

**Top Firewall Denies:**
```sql
SELECT sourceip, destinationip, destinationport,
       PROTOCOLNAME(protocolid) as protocol,
       COUNT(*) as deny_count
FROM events
WHERE categoryname(category) = 'Firewall Deny'
LAST 24 HOURS
GROUP BY sourceip, destinationip, destinationport, protocolid
ORDER BY deny_count DESC
LIMIT 20
```

**Network Flow Anomaly:**
```sql
SELECT sourceip, destinationip, destinationport,
       SUM(sourcebytes) as total_bytes,
       COUNT(*) as flow_count
FROM flows
WHERE destinationport NOT IN (80, 443, 53)
  AND NOT INCIDR('10.0.0.0/8', destinationip)
LAST 24 HOURS
GROUP BY sourceip, destinationip, destinationport
HAVING SUM(sourcebytes) > 100000000
ORDER BY total_bytes DESC
```

## 4. Rule Creation

### Rule Types
| Type | Use Case |
|------|----------|
| **Event Rule** | Single event pattern match |
| **Flow Rule** | Network flow analysis |
| **Common Rule** | Events + flows combined |
| **Offense Rule** | Modify existing offenses |
| **Anomaly Rule** | Detect behavioral deviations |

### Event Rule Example: Credential Dumping
```
Rule Name: LSASS Memory Access - Credential Dumping
Rule Type: Event
Tests:
  - When the event category is "Process Access"
  - AND when the target process name contains "lsass.exe"
  - AND when the access mask is any of: 0x1010, 0x1038, 0x1fffff
  - AND when the source process is NOT any of: csrss.exe, svchost.exe
Rule Action: Create offense, severity 9
MITRE: T1003.001
```

### Anomaly Rule Example
```
Rule Name: Abnormal Authentication Volume
Tests:
  - When the event count for Authentication events
  - Exceeds the average by 3 standard deviations
  - Over a 24-hour baseline, evaluated every 1 hour
  - Grouped by source IP
```

## 5. DSM Configuration

Device Support Modules (DSMs) parse incoming logs:
```
Admin → Data Sources → Log Sources → Add
  Log Source Type: Microsoft Windows Security Event Log
  Protocol: WinCollect
  Log Source Identifier: \\DC01
  Parsing Order: 1
```

### Custom Log Source
For unsupported devices, create custom DSM with regex parsing:
```
Field Name: src_ip
Regex: src=(\d+\.\d+\.\d+\.\d+)
Capture Group: 1
```

## 6. Reference Sets & Maps

```bash
# Create reference set via API
curl -X POST -u admin:password \
  'https://qradar/api/reference_data/sets?name=Malicious_IPs&element_type=IP'

# Add IOC
curl -X POST -u admin:password \
  'https://qradar/api/reference_data/sets/Malicious_IPs?value=1.2.3.4'

# Use in rules: REFERENCESETCONTAINS('Malicious_IPs', sourceip)
```

**Reference Map** (key-value): Map IP → threat category, hash → malware family

## 7. Offense Management

Offenses = correlated incidents. Key fields:
- **Magnitude** = Severity × Credibility × Relevance (1-10 each)
- **Source IP** and **Destination IP**
- **Contributing Rules** - what triggered it
- **Event/Flow Count** - volume of evidence

### Offense Investigation Workflow
1. Open offense → review contributing events
2. Right-click IP → check asset profile
3. Run AQL for additional context
4. Add notes documenting findings
5. Close with disposition (True/False Positive)

## 8. REST API

```bash
# Authentication
SEC_TOKEN=$(curl -s -X POST 'https://qradar/api/auth/tokens' \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"pass"}' | jq -r '.token')

# Search with AQL
curl -X POST 'https://qradar/api/ariel/searches' \
  -H "SEC: $SEC_TOKEN" \
  -d 'query_expression=SELECT sourceip, COUNT(*) FROM events WHERE category=8100 LAST 1 HOURS GROUP BY sourceip'

# Get offenses
curl -X GET 'https://qradar/api/siem/offenses?filter=status=OPEN' \
  -H "SEC: $SEC_TOKEN"
```

## 9. Use Cases
1. Brute force detection (threshold rule on auth failures)
2. Lateral movement (admin share access from non-admin host)
3. Data exfiltration (flow rule on high outbound volume)
4. Privilege escalation (new admin group membership)
5. Malware C2 (reference set match on TI IPs)
6. Insider threat (off-hours access anomaly)
7. DNS tunneling (high DNS query volume)
8. Ransomware (shadow copy deletion events)
9. Kerberoasting (RC4 TGS requests)
10. Log source failure (no events from critical source)

## 10. Labs

### Lab 1: Create Brute Force Rule
1. Write AQL to find >10 auth failures per source in 5 min
2. Create event rule with same logic
3. Test by generating failed logins
4. Verify offense is created

### Lab 2: Reference Set IOC Matching
1. Create reference set "Malicious_IPs"
2. Populate with TI feed IPs via API
3. Create rule: match firewall events against set
4. Verify offense on IOC match

### Lab 3: Custom Dashboard
1. Create AQL saved searches for top metrics
2. Build Pulse dashboard with widgets
3. Add drilldown links to offense list

---
*Compatible with QRadar 7.5.x | Last updated March 2026*

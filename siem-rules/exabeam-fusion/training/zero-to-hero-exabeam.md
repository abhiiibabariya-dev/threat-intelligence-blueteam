# Exabeam Fusion Zero-to-Hero Training Guide

## 1. Introduction
Exabeam Fusion is a cloud-native SIEM+UEBA platform combining security analytics, automation, and behavior-based threat detection. Its core strength is **User and Entity Behavior Analytics (UEBA)** with Smart Timelines.

## 2. Architecture
- **Exabeam Data Lake** - Scalable log storage and search
- **Advanced Analytics** - UEBA engine with ML models
- **Smart Timelines** - Automated session reconstruction per user/entity
- **Correlation Rules** - Traditional SIEM rule engine
- **Case Manager** - Investigation and workflow
- **SOAR** - Built-in automation playbooks
- **Threat Intelligence** - Integrated TI feeds

## 3. Key Concepts

### Smart Timelines
Automatically reconstructs user sessions showing all activity:
- Authentication events (logon/logoff)
- Process execution
- Network connections
- File access
- Email activity
- Cloud operations

Each event gets a **risk score** based on behavioral deviation from baseline.

### Peer Groups
Users grouped by: department, job title, location, manager. Behavioral baselines established per group. Deviation from peers = risk.

### Risk Scoring
- Each anomaly adds risk points to entity
- Risk accumulates over a session
- Thresholds trigger notable events
- Risk decays over time (configurable)

## 4. Data Ingestion
Supported via:
- **Syslog** (UDP/TCP/TLS)
- **API connectors** (cloud services, SaaS)
- **File-based** (CSV, JSON upload)
- **Exabeam Cloud Connectors** (O365, AWS, Azure AD, Okta, etc.)

### Parser Development
Custom parsers for unsupported log sources:
```
Parser Name: custom_firewall
Log Sample: 2026-03-01T10:00:00 FW1 action=allow src=10.0.0.1 dst=8.8.8.8 port=443
Extracted Fields:
  timestamp: 2026-03-01T10:00:00
  host: FW1
  action: allow
  src_ip: 10.0.0.1
  dest_ip: 8.8.8.8
  dest_port: 443
```

## 5. Correlation Rules
```yaml
rule_name: "Brute Force Detection"
trigger:
  data_source: authentication
  conditions:
    - field: outcome
      value: failure
  threshold: 10
  time_window: 5m
  group_by: [src_ip]
severity: high
risk_score: 30
entity: src_ip
response: [create_notable, add_to_watchlist]
```

## 6. Advanced Analytics Models
| Model | Detects |
|-------|---------|
| Abnormal logon time | Login outside user's normal hours |
| Abnormal logon location | Login from new city/country |
| First time VPN | First VPN connection for user |
| Abnormal data access | Unusual file/DB access volume |
| Peer group deviation | Activity significantly different from peers |
| Dormant account | Previously inactive account becomes active |
| Privilege escalation | Elevation outside normal pattern |
| Lateral movement | Host-to-host chain detection |

## 7. Threat Hunting with Exabeam
```
Search: event_type=authentication AND outcome=failure AND source_ip NOT IN (internal_ranges)
| stats count by source_ip, user
| where count > 10
| sort -count
```

## 8. Case Management
- Create cases from notable events
- Assign to analysts with priority
- Attach evidence (events, timelines, artifacts)
- Track investigation progress
- Document findings and resolution

## 9. API
```bash
# Authenticate
curl -X POST 'https://exabeam.company.com/api/auth/login' \
  -d '{"username":"admin","password":"pass"}'

# Search events
curl -X POST 'https://exabeam.company.com/api/search/events' \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"query":"event_type=authentication AND outcome=failure","timeRange":"last_24h"}'

# Get user timeline
curl -H "Authorization: Bearer $TOKEN" \
  'https://exabeam.company.com/api/users/jsmith/timeline?date=2026-03-01'
```

## 10. Use Cases
1. Insider threat (UEBA: data hoarding + off-hours + peer deviation)
2. Compromised account (impossible travel + first-time device)
3. Lateral movement (Smart Timeline: auth chain across hosts)
4. Privilege abuse (elevation outside change window)
5. Data exfiltration (abnormal upload volume vs peers)
6. Credential theft (brute force followed by success)
7. Dormant account abuse (90-day inactive → sudden activity)
8. Cloud misuse (abnormal resource creation)
9. Resignation risk (HR flag + data hoarding)
10. VPN anomaly (first-time VPN from new location)

## 11. Labs

### Lab 1: Investigate a Smart Timeline
1. Search for a user with high risk score
2. Open their Smart Timeline
3. Identify anomalous events (highlighted in red)
4. Document the attack chain

### Lab 2: Create Correlation Rule
1. Write rule for password spray detection
2. Set threshold: 5+ unique users from same IP
3. Configure risk scoring and response

### Lab 3: Peer Group Analysis
1. Select a user from HR department
2. Compare activity to peer group baseline
3. Identify deviations and assess risk

---
*Compatible with Exabeam Fusion | Last updated March 2026*

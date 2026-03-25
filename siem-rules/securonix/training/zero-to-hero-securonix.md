# Securonix Zero-to-Hero Training Guide

## 1. Introduction
Securonix is a cloud-native SIEM/UEBA platform specializing in insider threat detection, behavioral analytics, and risk-based monitoring. Its Spotter search interface provides real-time threat hunting.

## 2. Architecture
- **Cloud-native** multi-tenant platform (AWS/Azure hosted)
- **Hadoop-based data lake** for scalable storage
- **UEBA engine** with 1000+ behavioral models
- **Spotter** search interface (query language)
- **Threat models** and policies for automated detection
- **SOAR** module for response automation

## 3. Spotter Query Language

### Basic Syntax
```
index = activity AND riskThreatName = "Brute Force"
| where eventoutcome = "Failure"
| stats count() by sourceaddress, accountname
| where count > 10
| sort -count
| fields sourceaddress, accountname, count, datetime
```

### Operators
| Operator | Description | Example |
|----------|-------------|---------|
| `AND` / `OR` | Boolean logic | `index = activity AND status = failure` |
| `CONTAINS` | Substring match | `requesturl CONTAINS "malware"` |
| `STARTS WITH` | Prefix match | `sourceaddress STARTS WITH "10."` |
| `MATCHES` | Regex match | `accountname MATCHES "admin.*"` |
| `IN` | List membership | `destinationport IN (22, 3389, 445)` |
| `NOT` | Negation | `NOT sourceaddress IN ($whitelist)` |

### Pipe Commands
| Command | Purpose | Example |
|---------|---------|---------|
| `where` | Filter | `where count > 10` |
| `stats` | Aggregate | `stats count(), sum(bytesout) by user` |
| `sort` | Order results | `sort -count` |
| `fields` | Select columns | `fields user, ip, datetime` |
| `join` | Join datasets | `join department [...]` |
| `dc` / `distinct_count` | Unique count | `stats dc(accountname) by sourceaddress` |
| `values` | List unique values | `stats values(accountname) by sourceaddress` |

## 4. UEBA & Behavioral Analytics
Securonix's core strength - 1000+ pre-built behavioral models:

- **Peer group analysis** - Compare user to department/title peers
- **Temporal analysis** - Detect off-hours/unusual time activity
- **Volumetric analysis** - Detect abnormal data access volumes
- **Geographic analysis** - Impossible travel, new locations
- **Entity analysis** - First-time device, application, resource
- **Risk scoring** - Cumulative risk per entity with decay

## 5. Threat Models
JSON-based threat model definitions that combine multiple risk indicators:
```json
{
  "model_name": "Insider Threat",
  "risk_indicators": [
    {"name": "Off-hours access", "weight": 15},
    {"name": "Bulk file download", "weight": 25},
    {"name": "USB data transfer", "weight": 35},
    {"name": "Peer group deviation", "weight": 25}
  ],
  "thresholds": {"high": 60, "critical": 85}
}
```

## 6. Policies
Security policies define violations and automated responses:
```yaml
policy_name: "Excessive Failed Logins"
data_source: authentication
conditions:
  - field: eventoutcome
    value: Failure
  - threshold: 10
  - time_window: 5m
violation_severity: high
response: [create_incident, notify_soc]
```

## 7. Risk Scoring
- Each anomaly adds risk points to the entity
- Risk accumulates per user/host/IP
- Configurable decay rate (24h, 72h, 7d)
- Peer group comparison shows relative risk
- Thresholds trigger automated responses

## 8. Incident Management
- Incidents created from policy violations or analyst manual creation
- Workflow: Open → Investigating → Contained → Resolved
- Evidence attachment: events, timelines, screenshots
- Collaboration: assign, comment, escalate

## 9. API
```bash
# Authenticate
curl -X POST 'https://securonix.company.com/Snypr/ws/token/generate' \
  -d 'username=admin&password=pass'

# Search via Spotter
curl -X GET 'https://securonix.company.com/Snypr/ws/spotter/search' \
  -H "Authorization: Bearer $TOKEN" \
  -d 'query=index=activity AND riskThreatName="Brute Force" AND timeline="Last 24 Hours"'
```

## 10. Use Cases (UEBA-focused)
1. **Insider data theft** - bulk download + USB + personal email
2. **Compromised account** - impossible travel + new device
3. **Privilege abuse** - off-hours admin activity
4. **Resignation risk** - HR flag + data hoarding behavior
5. **Credential stuffing** - high-volume unique account failures
6. **Cloud abuse** - abnormal SaaS application usage
7. **Dormant account activation** - 90-day inactive → sudden use
8. **Peer group deviation** - resource access outside normal pattern
9. **Badge tailgating** - physical + logical access mismatch
10. **Third-party risk** - vendor account abnormal behavior

## 11. Labs
### Lab 1: Spotter Hunting
1. Write query for failed logins from external IPs
2. Pivot to successful logins from same IPs
3. Investigate affected accounts

### Lab 2: Risk Analysis
1. Find users with risk score > 80
2. Examine contributing risk indicators
3. Compare to peer group baseline

### Lab 3: Threat Model
1. Create insider threat model with 4 indicators
2. Configure risk thresholds
3. Test with simulated behavior

---
*Compatible with Securonix SNYPR | Last updated March 2026*

# LogRhythm Zero-to-Hero Training Guide

## 1. Introduction
LogRhythm is a SIEM platform with an AI Engine for advanced analytics. It combines log management, UEBA, SOAR (SmartResponse), and case management.

## 2. Architecture
- **Platform Manager (PM)** - Configuration, policies, agent management
- **Data Processor (DP)** - Log collection, parsing via Message Processing Engine (MPE)
- **Data Indexer (DI)** - Full-text search and storage
- **AI Engine** - Correlation and analytics (5 rule types)
- **Web Console** - Analyst interface, dashboards, investigations

## 3. Log Source Configuration
```
Deployment Manager → Log Sources → Add
  Log Source Type: Microsoft Windows Event Logging
  Collection Method: System Monitor Agent
  Host: DC01.corp.local
  Log Message Processing: Windows Event Log - Security
```

## 4. MPE (Message Processing Engine) Rules
MPE rules parse raw logs into structured fields:
```
Rule Name: Custom Firewall Parser
Base Rule Regex: <timestamp>\s+<hostname>\s+action=<action>\s+src=<sip>\s+dst=<dip>\s+port=<dport>
Field Mapping:
  <sip> → Origin Host (IP)
  <dip> → Impacted Host (IP)
  <dport> → Impacted Port
  <action> → Policy Action
```

## 5. AI Engine Rules (5 Types)

### Threshold
Fires when event count exceeds a value in a time window:
```
Name: Brute Force Detection
Type: Threshold
Count: > 10 events
Time Window: 5 minutes
Group By: Origin Host
Filter: Classification = Authentication Failure
```

### Unique Values
Fires when number of distinct values exceeds threshold:
```
Name: Password Spray Detection
Type: Unique Values
Unique Field: Login (user account)
Minimum Unique: 5
Time Window: 10 minutes
Group By: Origin Host
Filter: Classification = Authentication Failure
```

### Statistical
Fires on deviation from baseline:
```
Name: Data Exfiltration Anomaly
Type: Statistical
Field: Bytes Out (sum)
Standard Deviations: 3
Baseline Window: 30 days
Evaluation: Hourly
Group By: Origin Host
```

### Behavioral (Sequence)
Fires when events occur in a specific order:
```
Name: Brute Force then Success
Steps:
  1. Classification = Authentication Failure (count: 5, window: 5m)
  2. Classification = Authentication Success (same origin, within 5m)
```

### Trend
Fires when activity trend changes significantly:
```
Name: Increasing Off-Hours Activity
Direction: Increasing
Comparison: 7-day vs 30-day baseline
Minimum Increase: 200%
Filter: Time outside business hours
```

## 6. SmartResponse (SOAR)
Automated actions triggered by alarms:
```
SmartResponse Plugin: Active Directory
Action: Disable User Account
Trigger: AI Engine Alarm "DCSync Attack Detected"
Parameters: Username from alarm field
```

Built-in SmartResponse actions:
- Disable AD account
- Kill process
- Block IP at firewall
- Send email notification
- Create ServiceNow ticket
- Run custom script

## 7. Case Management
- Cases created from alarms or manually
- Evidence: attach logs, alarms, notes
- Collaboration: assign, comment, track
- Playbooks: guided investigation steps
- Metrics: MTTD, MTTR, case volume

## 8. Dashboards
Built-in and custom dashboards:
- Top Talkers, Alarms by Classification, Authentication Activity, Compliance
- Widgets: charts, tables, single value, maps
- Drilldowns to log search

## 9. API
```bash
# Authenticate
curl -X POST 'https://logrhythm:8501/lr-admin-api/auth' \
  -d '{"username":"admin","password":"pass"}'

# Search logs
curl -X POST 'https://logrhythm:8501/lr-search-api/search' \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"searchMode":"maxN","maxResults":100,"queryFilter":{"msgFilterType":1}}'
```

## 10. Labs

### Lab 1: AI Engine Threshold Rule
1. Create threshold rule for >10 auth failures per source in 5 min
2. Generate test failures
3. Verify alarm fires

### Lab 2: Behavioral Sequence
1. Create rule: brute force (5 failures) → success
2. Simulate attack
3. Investigate via case management

### Lab 3: SmartResponse Automation
1. Create alarm for LSASS access
2. Configure SmartResponse to disable account
3. Test end-to-end automation

---
*Compatible with LogRhythm SIEM 7.x | Last updated March 2026*

# ArcSight ESM Zero-to-Hero Training Guide

## 1. Introduction
ArcSight ESM (Enterprise Security Manager) is a legacy enterprise SIEM using CEF (Common Event Format) for normalization and XML-based correlation rules. Now part of OpenText (formerly Micro Focus/HPE).

## 2. Architecture
- **ESM (Manager)** - Correlation engine, console, database
- **SmartConnectors** - Log collection and normalization to CEF
- **Logger** - Long-term log storage and search
- **ArcSight Command Center** - Web-based management
- **ADP (ArcSight Data Platform)** - Hadoop-based big data analytics

## 3. CEF (Common Event Format)
All logs normalized to CEF:
```
CEF:0|Vendor|Product|Version|EventID|Name|Severity|src=10.0.0.1 dst=8.8.8.8 dpt=443 act=Allowed msg=HTTP Connection
```

Key CEF fields: `src`, `dst`, `spt`, `dpt`, `act`, `msg`, `cat`, `cs1-cs6` (custom strings), `cn1-cn3` (custom numbers)

## 4. Correlation Rules

### Rule Types
- **Filter** - Simple pattern match
- **Join** - Correlate multiple events
- **Threshold** - Count exceeds N in time window
- **Active List** - Match against dynamic lists
- **Session List** - Track stateful sessions

### XML Correlation Rule Example
```xml
<Rule name="Brute Force Detection" enabled="true" priority="8">
  <Description>10+ auth failures from same source in 5 minutes</Description>
  <Conditions>
    <ConditionGroup operator="AND">
      <Condition field="categoryBehavior" operator="equals" value="/Authentication/Verify"/>
      <Condition field="categoryOutcome" operator="equals" value="/Failure"/>
    </ConditionGroup>
  </Conditions>
  <Aggregation>
    <TimeWindow value="300"/>
    <GroupBy field="sourceAddress"/>
    <Threshold count="10"/>
  </Aggregation>
  <Actions>
    <Action type="generateCorrelationEvent" severity="8"/>
    <Action type="addToActiveList" listName="Brute_Force_Sources"/>
  </Actions>
</Rule>
```

## 5. Active Channels
Real-time event monitoring views filtered by criteria:
- Authentication Failures (last 1 hour)
- Firewall Denies (last 24 hours)
- High Severity Events (real-time)
- Custom filter by source, destination, category

## 6. Active Lists
Dynamic lists maintained in memory:
```
List: Suspicious_IPs
Type: IP Address
TTL: 3600 seconds
Population: From correlation rules or manual
Usage: Rule condition - "sourceAddress IN ActiveList(Suspicious_IPs)"
```

## 7. FlexConnectors
Custom log parser for unsupported devices:
```
# FlexConnector config
regex=^(\S+)\s+(\S+)\s+(\S+)\s+action=(\S+)\s+src=(\S+)\s+dst=(\S+)
token[0].name=deviceEventClassId
token[0].type=String
token[1].name=name
token[2].name=sourceAddress
token[2].type=IPAddress
token[3].name=destinationAddress
token[3].type=IPAddress
```

## 8. Dashboards & Reports
- **Dashboards** - Real-time widgets (chart, table, map, gauge)
- **Trend Reports** - Historical analysis and compliance
- **Query Viewer** - Ad-hoc event search
- **Pattern Discovery** - Visual event clustering

## 9. API
```bash
# ArcSight REST API
curl -X POST 'https://arcsight:8443/www/manager-service/rest/LoginService/login' \
  -d 'login=admin&password=pass'

# Search events
curl -X POST 'https://arcsight:8443/www/manager-service/rest/ActiveListService/getEntries' \
  -d 'authToken=$TOKEN&listId=/All Active Lists/Suspicious_IPs'
```

## 10. Use Cases
1. Brute force (threshold rule on auth failures)
2. Lateral movement (join rule: auth success + admin share access)
3. Data exfiltration (threshold on outbound bytes)
4. Privilege escalation (filter on admin group changes)
5. Malware C2 (active list match on TI IPs)
6. Insider threat (off-hours access filter)
7. DNS tunneling (threshold on DNS query volume)
8. Ransomware (filter on shadow copy deletion)
9. Web attack (threshold on web server errors from same source)
10. Log source failure (threshold on missing heartbeat)

## 11. Labs
### Lab 1: SmartConnector Setup
1. Install Syslog SmartConnector
2. Configure log source
3. Verify events in ESM console

### Lab 2: Correlation Rule
1. Create threshold rule for brute force
2. Test with simulated failures
3. Verify correlated event

### Lab 3: Active List + Rule
1. Create Active List for malicious IPs
2. Populate via API
3. Create rule matching firewall events against list

---
*Compatible with ArcSight ESM 7.x | Last updated March 2026*

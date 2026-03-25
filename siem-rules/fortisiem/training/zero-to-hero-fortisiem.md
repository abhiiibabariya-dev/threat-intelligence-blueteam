# FortiSIEM Zero-to-Hero Training Guide

## 1. Introduction
FortiSIEM is Fortinet's SIEM platform with integrated CMDB, analytics, and FortiGuard threat intelligence. Part of the Fortinet Security Fabric.

## 2. Architecture
- **Supervisor** - Central management, correlation, web UI
- **Worker** - Event processing, parsing, correlation
- **Collector** - Remote log collection agents
- **CMDB** - Auto-discovered asset database
- **FortiGuard** - Integrated threat intelligence

## 3. Deployment
```bash
# OVA deployment for VMware
# Import OVA → Configure network → Access web UI at https://<IP>
# Default: admin / admin*1

# Docker deployment
docker pull fortinet/fortisiem:latest
docker run -d -p 443:443 --name fortisiem fortinet/fortisiem
```

## 4. Log Parsing & Normalization
FortiSIEM auto-discovers devices and parses logs:
- **Built-in parsers** for 500+ device types
- **Custom parsers** using regex-based XML definitions
- **Syslog, SNMP, WMI, JDBC, API** collection methods

## 5. Rule Creation

### Single Subpattern Rule
```xml
<Rule naturalId="BruteForce-001" name="Brute Force Detection">
  <Description>10+ auth failures from same source in 5 minutes</Description>
  <Severity>9</Severity>
  <SubPattern>
    <SingleEvtConstr>
      eventType = "Security-Authentication" AND
      eventAction CONTAIN "Failure"
    </SingleEvtConstr>
    <GroupByAttr>srcIpAddr</GroupByAttr>
    <GroupEvtConstr>COUNT(*) >= 10</GroupEvtConstr>
    <WindowSize>300</WindowSize>
  </SubPattern>
  <Action>CREATE_INCIDENT</Action>
</Rule>
```

### Multi-Subpattern Rule (Sequence)
```xml
<Rule naturalId="LateralMov-001" name="Brute Force then Lateral Movement">
  <SubPattern id="1">
    <SingleEvtConstr>eventAction CONTAIN "Failure"</SingleEvtConstr>
    <GroupByAttr>srcIpAddr</GroupByAttr>
    <GroupEvtConstr>COUNT(*) >= 5</GroupEvtConstr>
    <WindowSize>300</WindowSize>
  </SubPattern>
  <SubPattern id="2">
    <SingleEvtConstr>eventAction = "Success" AND destPort IN (445,3389)</SingleEvtConstr>
    <GroupByAttr>srcIpAddr</GroupByAttr>
    <WindowSize>600</WindowSize>
  </SubPattern>
  <PatternRelation>1 FOLLOWED_BY 2</PatternRelation>
  <Action>CREATE_INCIDENT</Action>
</Rule>
```

## 6. CMDB (Configuration Management Database)
FortiSIEM auto-discovers and maintains:
- Device inventory (servers, workstations, network devices)
- Software inventory
- Service/port inventory
- User accounts
- Relationships between assets

Use CMDB for rule enrichment: "Alert only if target is a domain controller"

## 7. Analytics & Dashboards
- **Real-time dashboards** with widgets (charts, tables, maps, gauges)
- **Historical reports** for compliance
- **Search** with structured query language
- **Baseline analytics** for anomaly detection

## 8. FortiGuard Integration
- IOC feeds (malicious IPs, domains, URLs, hashes)
- Automatic matching against incoming events
- Threat severity enrichment
- Updated every 5 minutes

## 9. API
```bash
# Login
curl -k -X POST 'https://fortisiem/phoenix/rest/login' \
  -d '<request><user>admin</user><password>admin*1</password></request>'

# Search events
curl -k -X POST 'https://fortisiem/phoenix/rest/query/search' \
  -H "Cookie: JSESSIONID=$SESSION" \
  -d '<request><timeRange><start>2026-03-01T00:00:00</start><end>2026-03-02T00:00:00</end></timeRange><query>eventType="Security-Authentication" AND eventAction CONTAIN "Failure"</query></request>'
```

## 10. Use Cases
1. Brute force (threshold rule)
2. Lateral movement (multi-subpattern sequence)
3. Data exfiltration (high outbound bytes)
4. Malware C2 (FortiGuard IOC match)
5. Privilege escalation (admin group change)
6. Device compliance (CMDB + config drift)
7. VPN anomaly (unusual location/time)
8. Web attack (WAF + IPS correlation)
9. Insider threat (off-hours + data access)
10. Log source health (missing logs detection)

## 11. Labs
### Lab 1: Deploy & Configure
1. Deploy FortiSIEM OVA
2. Add syslog data source
3. Verify event parsing

### Lab 2: Create Detection Rule
1. Build brute force threshold rule
2. Test with simulated failures
3. Review generated incident

### Lab 3: CMDB Discovery
1. Run network discovery scan
2. Review discovered assets
3. Create rule targeting specific asset group

---
*Compatible with FortiSIEM 7.x | Last updated March 2026*

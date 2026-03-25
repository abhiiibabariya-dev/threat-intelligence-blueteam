# McAfee ESM / Trellix Zero-to-Hero Training Guide

## 1. Introduction
McAfee Enterprise Security Manager (now Trellix) is an enterprise SIEM with Advanced Correlation Engine (ACE), Enterprise Log Manager (ELM), and integration with the broader Trellix XDR ecosystem.

## 2. Architecture
- **ESM** - Central management, correlation, web UI
- **ERC (Event Receiver/Collector)** - Log collection and parsing
- **ELM (Enterprise Log Manager)** - Long-term storage
- **ACE (Advanced Correlation Engine)** - Statistical/behavioral correlation
- **DEM (Database Event Monitor)** - Database activity monitoring
- **ADM (Application Data Monitor)** - Application layer monitoring

## 3. Data Source Management
```
System Properties → Data Sources → Add
  Data Source Type: Windows Event Log
  Collection Method: WMI
  Host: DC01.corp.local
  Credentials: domain\service_account
```

Supports: Syslog, WMI, JDBC, SNMP, MEF, file tail, API

## 4. Correlation Rules

### Rule Builder
```
Rule Name: Brute Force Detection
Type: Correlation
Conditions:
  Event Subcategory = "Authentication" AND
  Event Result = "Failure" AND
  Source IP != "127.0.0.1"
Aggregation:
  Group By: Source IP
  Threshold: Count > 10
  Time Window: 5 minutes
Actions:
  Generate Alarm (Priority: High)
  Add to Watchlist: "Brute Force Sources"
```

### Correlation Rule Types
| Type | Description |
|------|-------------|
| **Simple** | Single event pattern match |
| **Correlation** | Multiple events with aggregation |
| **Sequence** | Events in specific order |
| **Threshold** | Count/rate-based detection |

## 5. Watchlists
CSV-based IOC lists:
```csv
Type,Value,Confidence,Source,Description
IP,1.2.3.4,90,ThreatFox,Emotet C2
IP,5.6.7.8,85,FeodoTracker,Qakbot C2
Domain,evil.example.com,80,URLhaus,Malware distribution
Hash,abc123...,95,MalwareBazaar,Ransomware sample
```

Use in rules: `Source IP IN Watchlist("Malicious_IPs")`

## 6. ACE (Advanced Correlation Engine)
Goes beyond standard correlation:
- **Risk-based scoring** - Accumulate risk per entity
- **Statistical baseline** - Detect deviations
- **Behavioral rules** - Sequence and pattern detection
- **Threat scoring** - Multi-factor risk calculation

## 7. Dashboards & Views
- Real-time event views with filtering
- Correlation event dashboard
- Alarm management console
- Custom report builder
- Compliance reports (PCI, HIPAA, SOX)

## 8. Trellix XDR Integration
McAfee ESM integrates with the Trellix ecosystem:
- **Trellix Endpoint** (formerly McAfee ENS) - Endpoint alerts
- **Trellix ePO** - Policy management and deployment
- **Trellix Network Security** - IPS/IDS events
- **Trellix Data Loss Prevention** - DLP alerts

## 9. API
```bash
# Login
curl -X POST 'https://esm:8443/rs/esm/login' \
  -d '{"username":"admin","password":"pass"}' | jq -r '.session'

# Query events
curl -X POST 'https://esm:8443/rs/esm/qryExecuteDetail' \
  -H "Cookie: JWTToken=$TOKEN" \
  -d '{"config":{"timeRange":"LAST_24_HOURS","filters":[{"type":"EsmFieldFilter","field":"SrcIP","operator":"IN_WATCHLIST","values":["Malicious_IPs"]}]}}'
```

## 10. Use Cases & Labs
1. Brute force detection (correlation rule)
2. IOC matching (watchlist + correlation)
3. Privilege escalation (admin group change)
4. Data exfiltration (ACE statistical rule)
5. Lateral movement (sequence rule)
6. Malware detection (ePO + ESM correlation)
7. Compliance monitoring (PCI DSS reports)
8. Insider threat (ACE behavioral baseline)

### Lab 1: Correlation Rule
1. Create brute force correlation rule
2. Test with simulated failures
3. Review alarm

### Lab 2: Watchlist IOC Matching
1. Import threat intel CSV as watchlist
2. Create rule matching firewall events to watchlist
3. Verify alarm on IOC match

---
*Compatible with McAfee ESM 11.x / Trellix | Last updated March 2026*

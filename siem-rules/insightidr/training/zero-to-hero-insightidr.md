# Rapid7 InsightIDR Zero-to-Hero Training Guide

## 1. Introduction
InsightIDR is Rapid7's cloud-native SIEM with LEQL query language, Attacker Behavior Analytics (ABA), User Behavior Analytics (UBA), deception technology, and InsightConnect SOAR integration.

## 2. Architecture
- **Cloud platform** - SaaS-hosted on AWS
- **Collectors** - On-prem log aggregation (Windows/Linux)
- **Insight Agent** - Endpoint agent for EDR data
- **Network Sensor** - Network traffic analysis
- **Event Sources** - Log integrations (AD, DHCP, DNS, cloud)
- **Honeypots/Honey Users** - Built-in deception

## 3. LEQL (Log Entry Query Language)

### Basic Syntax
```
where(destination_port = 3389 AND source_address = "10.0.0.50")
groupby(destination_address)
calculate(count)
sort(desc)
```

### Operators
| Operator | Example |
|----------|---------|
| `=`, `!=` | `status = "FAILED"` |
| `>`, `<`, `>=`, `<=` | `bytes_out > 1000000` |
| `CONTAINS` | `process_name CONTAINS "powershell"` |
| `ICONTAINS` | Case-insensitive contains |
| `IN` | `port IN [22, 3389, 445]` |
| `ICONTAINS-ANY` | `command_line ICONTAINS-ANY ["mimikatz", "sekurlsa"]` |
| `STARTS-WITH` | `user STARTS-WITH "svc_"` |
| `MATCHES` | Regex: `file_path MATCHES ".*\\\\temp\\\\.*\\.exe"` |

### Aggregation
```
// Count failed logins by source
where(result = "FAILED")
groupby(source_address)
calculate(count)
having(count > 10)

// Unique destinations per source
where(destination_port = 445)
groupby(source_address)
calculate(unique:destination_address)
having(unique > 5)

// Sum bytes transferred
where(direction = "outbound")
groupby(source_address)
calculate(sum:bytes_out)
having(sum > 1073741824)
```

## 4. Attacker Behavior Analytics (ABA)
Pre-built detection rules covering MITRE ATT&CK. Categories:
- **Malware** - Known malware families, suspicious behavior
- **Credential** - Brute force, mimikatz, pass-the-hash
- **Lateral Movement** - PsExec, WMI, RDP abuse
- **Persistence** - Registry, scheduled tasks, services
- **Exfiltration** - DNS tunneling, large transfers

Custom ABA rules use LEQL with alert configuration.

## 5. User Behavior Analytics (UBA)
- **Ingress** - Login patterns, locations, times, devices
- **Lateral** - Host-to-host authentication mapping
- **Asset** - What resources each user normally accesses
- **Anomaly** - First-time behavior, deviation from baseline

## 6. Deception Technology
Built-in honeypots and honey credentials:
- **Honey Users** - Fake AD accounts that should never authenticate
- **Honey Files** - Decoy files that trigger on access
- **Honey Credentials** - Fake credentials placed on endpoints
- **Honeypots** - Network listener services

Any interaction = immediate high-confidence alert.

## 7. Custom Alerts
```json
{
  "name": "Encoded PowerShell Execution",
  "description": "PowerShell with encoded command detected",
  "leql_query": "where(process_name ICONTAINS 'powershell' AND command_line ICONTAINS '-enc')",
  "log_sets": ["Endpoint Agent"],
  "severity": "HIGH",
  "frequency": "5m",
  "alert_actions": ["create_investigation", "notify_slack"]
}
```

## 8. InsightConnect Integration (SOAR)
- Trigger playbooks from InsightIDR alerts
- Automated enrichment (VirusTotal, WHOIS, GeoIP)
- Automated response (block IP, disable user, isolate host)
- 300+ plugins for tool integration

## 9. Investigation Dashboard
- Visual timeline of attack progression
- Entity mapping (users, assets, IPs)
- Evidence collection and notes
- Collaboration with team members

## 10. API
```bash
# Search logs
curl -X POST 'https://us.api.insight.rapid7.com/log_search/query/logs' \
  -H "X-Api-Key: $API_KEY" \
  -d '{"leql":{"statement":"where(result=\"FAILED\") groupby(source_address) calculate(count)"},"logs":["auth"],"time_range":{"from":"2026-03-01T00:00:00","to":"2026-03-02T00:00:00"}}'
```

## 11. Labs
### Lab 1: LEQL Hunting
1. Write query for top failed login sources
2. Correlate with successful logins
3. Build custom alert rule

### Lab 2: Deception Setup
1. Create honey user in Active Directory
2. Configure in InsightIDR
3. Attempt login with honey credentials
4. Verify immediate alert

### Lab 3: UBA Investigation
1. Identify user with anomalous behavior
2. Review ingress/lateral/asset patterns
3. Document investigation findings

---
*Compatible with InsightIDR | Last updated March 2026*

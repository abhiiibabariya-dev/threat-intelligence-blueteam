# LogPoint Zero-to-Hero Training Guide

## 1. Introduction
LogPoint is a European SIEM platform using LPQL (LogPoint Query Language) for search and analysis. Features UEBA, SOAR module, and strong compliance/GDPR focus.

## 2. Architecture
- **LogPoint Core** - Central server (collection, parsing, correlation, storage)
- **LogPoint Director** - Multi-instance management
- **Search Heads** - Distributed search (scale-out)
- **Collectors** - Remote log collection

## 3. LPQL (LogPoint Query Language)

### Basic Syntax
```
"Windows Security" label=Logon status=failure
| chart count() as failures by source_address, user
| search failures > 10
| sort -failures
```

### Key Components
| Component | Example |
|-----------|---------|
| **Source filter** | `"Windows Security"`, `"Firewall"` |
| **Field filter** | `label=Logon status=failure` |
| **Negation** | `-user="SYSTEM"` |
| **Wildcard** | `user="admin*"` |
| **Time** | `last 24 hours`, `timerange="2026-03-01 TO 2026-03-02"` |

### Pipe Commands
```
| chart count() by field           # Aggregate
| search count > 10                # Filter aggregated
| sort -count                      # Sort descending
| rename old_name as "New Name"    # Rename columns
| timechart count() span=1h        # Time-series
| distinct_count(user) as uniq     # Unique count
| top 10 source_address            # Top N values
```

### Advanced LPQL
```
# Join two queries
"Windows Security" label=Logon status=failure
| chart count() as failures by source_address
| join source_address [
    "Windows Security" label=Logon status=success
    | chart count() as successes by source_address
]
| search failures > 10 and successes > 0

# Subsearch
"Firewall" action=deny source_address IN [
    "Windows Security" label=Logon status=failure
    | chart count() by source_address
    | search count > 10
    | fields source_address
]
```

## 4. Normalization
LogPoint normalizes all logs to a common schema:
- `label` = Event category (Logon, Process, Network, etc.)
- `source_address` / `destination_address` = IPs
- `user` = Account name
- `status` = success/failure
- `action` = allow/deny/drop

## 5. Alert Rules
```
Alert Name: Brute Force Detection
Query: "Windows Security" label=Logon status=failure | chart count() by source_address | search count > 10
Frequency: Every 5 minutes
Lookback: 15 minutes
Severity: High
Actions: Email notification, Create incident
```

## 6. UEBA Module
- Behavioral baselines per user/entity
- Anomaly detection (login time, location, volume)
- Risk scoring with configurable thresholds
- Peer group comparison

## 7. SOAR Module (LogPoint SOAR)
Built-in automation:
- **Playbooks** - Visual workflow builder
- **Integrations** - 100+ tool connectors
- **Case management** - Investigation tracking
- **Response actions** - Block, disable, isolate, notify

## 8. Enrichment & Lookups
```yaml
# Lookup table enrichment
enrichment_name: "GeoIP Lookup"
source_field: source_address
lookup_table: geoip_database
output_fields: [country, city, latitude, longitude]
```

## 9. API
```bash
# Search
curl -X POST 'https://logpoint/api/search' \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"query":"label=Logon status=failure | chart count() by source_address","timeRange":"last 24 hours"}'
```

## 10. Use Cases
1. Brute force (chart count by source, threshold)
2. Password spray (distinct_count user by source)
3. Lateral movement (RDP/SMB to multiple hosts)
4. Data exfiltration (high bytes_out to external)
5. Privilege escalation (admin group changes)
6. Insider threat (UEBA off-hours anomaly)
7. Malware C2 (IOC lookup match)
8. DNS tunneling (high DNS query volume)
9. Compliance (PCI/GDPR access reports)
10. Log source health (missing events detection)

## 11. Labs
### Lab 1: LPQL Hunting
1. Write query for failed logins from external IPs
2. Correlate with successful logins
3. Create alert rule

### Lab 2: Dashboard
1. Build SOC overview dashboard
2. Add: alert volume, top sources, auth trends
3. Configure drilldowns

### Lab 3: SOAR Playbook
1. Create phishing response playbook
2. Configure email analysis actions
3. Test end-to-end automation

---
*Compatible with LogPoint 7.x | Last updated March 2026*

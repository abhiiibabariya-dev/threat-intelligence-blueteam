# Elastic SIEM Zero-to-Hero Training Guide

## 1. Introduction
Elastic Security (formerly Elastic SIEM) is built on the Elastic Stack (Elasticsearch, Kibana, Beats, Logstash). It provides SIEM capabilities with KQL/EQL search, detection rules, ML anomaly detection, and case management.

## 2. Architecture
```
Data Sources → Elastic Agent/Beats → Elasticsearch → Kibana Security App
                    │                      │
              Fleet Server            Ingest Pipelines
              (agent mgmt)           (parse/enrich)
```

**Components:**
- **Elasticsearch** - Search engine, data store, analytics
- **Kibana** - UI, Security app, dashboards, ML
- **Elastic Agent** - Unified data collection agent (replaces Beats)
- **Fleet** - Central agent management
- **Logstash** - Optional data processing pipeline

## 3. KQL (Kibana Query Language)
```
# Basic field matching
event.action: "logon-failed" and source.ip: "10.0.0.0/8"

# Wildcard
process.name: powershell* and process.command_line: *-enc*

# Boolean logic
(event.code: 4625 or event.code: 4771) and not user.name: "SYSTEM"

# Nested
process.parent.name: "winword.exe" and process.name: ("cmd.exe" or "powershell.exe")
```

## 4. EQL (Event Query Language)
EQL enables sequence-based and stateful detection:

```eql
// Simple process match
process where process.name == "mimikatz.exe"

// Parent-child relationship
process where process.parent.name == "winword.exe"
  and process.name in ("cmd.exe", "powershell.exe", "wscript.exe")

// Sequence detection (events in order)
sequence by host.name with maxspan=5m
  [authentication where event.outcome == "failure"] with runs=10
  [authentication where event.outcome == "success"]

// Sequence: lateral movement chain
sequence by source.ip with maxspan=30m
  [authentication where event.action == "logon-success" and host.name == "workstation1"]
  [process where process.name == "psexec.exe"]
  [authentication where event.action == "logon-success" and host.name != "workstation1"]
```

## 5. Detection Rules

### Rule Types
| Type | Description |
|------|-------------|
| **Custom query** | KQL or EQL match |
| **Threshold** | Count exceeds N in time window |
| **Machine learning** | Anomaly detection job |
| **Indicator match** | TI indicator lookup |
| **New terms** | First-time occurrence of value |
| **Event correlation** | EQL sequence |

### TOML Rule Format
```toml
[metadata]
creation_date = "2026/03/01"
maturity = "production"

[rule]
author = ["SOC Team"]
description = "Detects LSASS memory access for credential dumping"
name = "LSASS Memory Access - Credential Dumping"
risk_score = 90
severity = "critical"
type = "eql"
query = '''
process where event.type == "access" and
  process.name == "lsass.exe" and
  not process.executable : ("?:\\Windows\\System32\\*", "?:\\Program Files\\*")
'''

[rule.threat]
framework = "MITRE ATT&CK"
[[rule.threat.technique]]
id = "T1003"
name = "OS Credential Dumping"
[[rule.threat.technique.subtechnique]]
id = "T1003.001"
name = "LSASS Memory"
[rule.threat.tactic]
id = "TA0006"
name = "Credential Access"
```

## 6. Timeline Investigation
Timeline is Elastic's investigation workspace:
- Drag events from alerts into Timeline
- Add KQL filters to narrow scope
- Pin important events
- Add notes and tags
- Save and share investigations
- Create cases from Timeline findings

## 7. Machine Learning Jobs

Built-in ML jobs for anomaly detection:
- **Unusual process** - Rare process execution on host
- **Unusual network** - Anomalous network destination
- **Unusual login** - Login from unusual location/time
- **DNS tunneling** - High DNS request volume anomaly

```
Security → ML Jobs → Enable "unusual_process_for_host"
```

Custom ML job:
```json
{
  "analysis_config": {
    "bucket_span": "15m",
    "detectors": [{
      "function": "high_count",
      "by_field_name": "source.ip",
      "over_field_name": "destination.ip",
      "partition_field_name": "destination.port"
    }]
  },
  "data_description": {"time_field": "@timestamp"}
}
```

## 8. Fleet & Elastic Agent

```yaml
# Fleet Server setup
elastic-agent install --fleet-server-es=https://elasticsearch:9200 \
  --fleet-server-service-token=AAEAAWVs...

# Enroll agent
elastic-agent install --url=https://fleet:8220 \
  --enrollment-token=token123
```

**Agent Policies** define what data to collect:
- System logs (Windows Event, Syslog)
- Endpoint security (malware, behavior protection)
- Network packet capture
- Custom log files

## 9. Ingest Pipelines

```json
PUT _ingest/pipeline/enrich-geoip
{
  "processors": [
    { "geoip": { "field": "source.ip", "target_field": "source.geo" } },
    { "user_agent": { "field": "user_agent.original" } },
    { "set": { "field": "event.severity", "value": "high",
               "if": "ctx.event?.action == 'logon-failed'" } }
  ]
}
```

## 10. Use Cases
1. Brute force (threshold rule: >10 auth failures)
2. Credential dumping (EQL: LSASS access pattern)
3. Lateral movement (EQL sequence: auth → PsExec → remote auth)
4. Ransomware (shadow copy deletion + mass file rename)
5. Phishing (Office → child shell process)
6. C2 beaconing (ML anomaly on periodic connections)
7. DNS tunneling (ML high DNS volume)
8. Privilege escalation (new terms: first admin group add)
9. Data exfiltration (threshold: high outbound bytes)
10. Defense evasion (log clearing: EventID 1102)

## 11. Labs

### Lab 1: Deploy Elastic Agent
1. Set up Fleet Server
2. Create agent policy with Windows integration
3. Enroll Windows endpoint
4. Verify data in Discover

### Lab 2: Create EQL Sequence Rule
1. Write EQL: brute force followed by success
2. Create detection rule in Security app
3. Test with simulated auth failures + success
4. Investigate alert in Timeline

### Lab 3: ML Anomaly Detection
1. Enable "unusual_process_for_host" ML job
2. Wait for baseline (24h)
3. Run unusual process (e.g., certutil download)
4. Check ML anomaly explorer for detection

---
*Compatible with Elastic 8.x | Last updated March 2026*

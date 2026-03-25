# Palo Alto Cortex XDR Zero-to-Hero Training Guide

## 1. Introduction
Cortex XDR is Palo Alto Networks' extended detection and response platform that integrates endpoint, network, cloud, and identity data for unified threat detection and investigation.

## 2. Architecture
- **Cortex XDR Cloud** - SaaS analytics engine
- **Cortex XDR Agent** - Endpoint agent (Windows, Linux, macOS)
- **Cortex Data Lake** - Centralized data storage (PAN firewall logs, endpoint, cloud)
- **BIOC Rules** - Behavioral Indicators of Compromise
- **Causality Chain** - Attack visualization (like a process tree on steroids)

## 3. Agent Deployment
```bash
# Windows silent install
msiexec /i cortex-xdr-agent.msi /qn DIST_SERVER="dist-server" DIST_SERVER_PORT=443

# Linux
sudo dpkg -i cortex-xdr-agent.deb
sudo /opt/traps/bin/cytool runtime start

# Verify
cytool runtime query  # Check agent status
```

## 4. XQL (XDR Query Language)
XQL queries the Cortex Data Lake:

```xql
// Basic process search
dataset = xdr_data
| filter event_type = PROCESS
| filter action_process_image_name = "powershell.exe"
| filter actor_process_command_line contains "-enc"
| fields _time, agent_hostname, actor_primary_username, actor_process_command_line

// Aggregation
dataset = xdr_data
| filter event_type = NETWORK and action_remote_port = 3389
| comp count(agent_hostname) as target_count by action_remote_ip
| filter target_count > 3
| sort desc target_count

// Time-series
dataset = xdr_data
| filter event_type = PROCESS
| filter actor_process_command_line contains "mimikatz"
| bin _time span = 1h
| comp count() as events by _time

// Join datasets
dataset = xdr_data
| filter event_type = PROCESS and action_process_image_name = "psexesvc.exe"
| join type = inner (
    dataset = xdr_data
    | filter event_type = NETWORK
  ) as network on agent_hostname = network.agent_hostname
| fields agent_hostname, action_process_image_name, network.action_remote_ip
```

### XQL Functions
| Function | Purpose | Example |
|----------|---------|---------|
| `filter` | Where clause | `filter event_type = PROCESS` |
| `fields` | Select columns | `fields _time, agent_hostname` |
| `comp` | Aggregate | `comp count() by agent_hostname` |
| `sort` | Order | `sort desc count` |
| `bin` | Time bucket | `bin _time span = 1h` |
| `join` | Combine datasets | `join type = inner ...` |
| `alter` | Create fields | `alter risk = if(count > 10, "high", "low")` |
| `limit` | Row limit | `limit 100` |
| `dedup` | Remove duplicates | `dedup agent_hostname` |

## 5. BIOC Rules
Behavioral Indicators of Compromise - custom detection rules:

```yaml
name: "BIOC-001: Encoded PowerShell"
description: "Detects encoded PowerShell execution"
severity: HIGH
mitre_tactic: Execution
mitre_technique: T1059.001
os: windows
bioc_type: process
indicators:
  - process_name: "powershell.exe"
    command_line_contains: "-enc"
action: alert
```

### BIOC vs Correlation Rules
| Feature | BIOC | Correlation |
|---------|------|-------------|
| Scope | Single endpoint event | Cross-endpoint/network |
| Latency | Real-time | Near real-time |
| Complexity | Simple pattern | Multi-event sequences |
| Use Case | Known bad pattern | Attack chain detection |

## 6. Correlation Rules
Multi-event detection across data sources:

```yaml
name: "CORR-001: Brute Force then Lateral Movement"
severity: HIGH
sequence:
  - event_type: USER_LOGIN
    action: BLOCK
    count: "> 10"
    time_window: 5m
    group_by: source_ip
  - event_type: NETWORK
    destination_port: [445, 3389]
    source_ip: "{step1.source_ip}"
    time_after_step1: 30m
```

## 7. Causality Analysis
Cortex XDR's causality chain shows:
- **Causality Group Owner (CGO)** - Root process of the attack
- **Full process tree** - Parent → child → grandchild
- **Network connections** per process
- **File operations** per process
- **Registry modifications** per process
- **Loaded modules** per process

One-click view of entire attack chain from initial access to impact.

## 8. Incident Management
- **Incidents** - Grouped related alerts
- **Severity scoring** - Based on BIOC/correlation severity + asset value
- **Investigation** - Causality view + timeline + indicators
- **Response** - Isolate, remediate, block from incident view

## 9. Response Actions
| Action | Description |
|--------|-------------|
| Isolate endpoint | Network quarantine |
| Scan endpoint | On-demand malware scan |
| Block file | Hash-based prevention |
| Quarantine file | Remove + preserve |
| Terminate process | Kill by PID |
| Script execution | Run remediation script |
| Live terminal | Remote shell access |

## 10. API
```bash
# Get incidents
curl -X POST 'https://api-{tenant}.xdr.paloaltonetworks.com/public_api/v1/incidents/get_incidents' \
  -H "x-xdr-auth-id: $KEY_ID" \
  -H "Authorization: $API_KEY" \
  -d '{"request_data":{"filters":[{"field":"status","operator":"eq","value":"new"}]}}'

# Isolate endpoint
curl -X POST 'https://api-{tenant}.xdr.paloaltonetworks.com/public_api/v1/endpoints/isolate' \
  -H "x-xdr-auth-id: $KEY_ID" \
  -H "Authorization: $API_KEY" \
  -d '{"request_data":{"endpoint_id_list":["eid123"]}}'
```

## 11. Use Cases
1. Multi-stage attack (email → download → execute → lateral → exfil)
2. Credential theft (endpoint LSASS + network auth anomaly)
3. Ransomware (process + file + network correlation)
4. Cloud compromise (cloud logs + endpoint pivot)
5. Insider threat (endpoint + network data flow)
6. Supply chain (unusual update + outbound C2)

## 12. Labs
### Lab 1: XQL Threat Hunting
1. Write XQL for encoded PowerShell
2. Pivot from process to network connections
3. Build causality view

### Lab 2: BIOC Rule
1. Create BIOC for Office macro execution
2. Test on endpoint
3. Review alert and causality chain

### Lab 3: Incident Response
1. Trigger multi-alert incident
2. Investigate via causality analysis
3. Isolate endpoint and block IOCs

---
*Compatible with Cortex XDR 3.x | Last updated March 2026*

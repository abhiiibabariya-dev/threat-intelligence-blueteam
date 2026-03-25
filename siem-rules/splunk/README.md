# Splunk SPL Detection Rules

This directory contains detection rules written in Splunk Search Processing Language (SPL) for use with Splunk Enterprise, Splunk Cloud, and Splunk Enterprise Security (ES).

## Directory Layout

```
splunk/
├── detection-rules/           # Atomic detection rules organized by ATT&CK tactic
│   ├── credential-access.spl  # T1110, T1003, T1558 techniques
│   ├── lateral-movement.spl   # T1570, T1047, T1021 techniques
│   ├── persistence.spl        # T1053, T1547, T1543, T1546 techniques
│   └── exfiltration.spl       # T1048, T1074, T1567 techniques
├── correlation-rules/         # Multi-event correlation searches
│   └── multi-stage-attack.spl # Kill chain and attack progression detection
└── dashboards/                # Splunk XML dashboard definitions
    └── soc-overview.xml       # SOC operational overview dashboard
```

## Prerequisites

- Splunk Enterprise 8.x+ or Splunk Cloud
- Splunk Enterprise Security (recommended for notable events and risk framework)
- Common Information Model (CIM) add-on installed and configured
- Data sources: Windows Event Logs, Sysmon, firewall/proxy logs, authentication logs

## Required Sourcetypes

| Sourcetype | Purpose |
|---|---|
| `WinEventLog:Security` | Windows Security event log |
| `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` | Sysmon telemetry |
| `stream:dns` | DNS traffic (Splunk Stream) |
| `pan:traffic` / `cisco:asa` | Firewall logs |
| `access_combined` | Web proxy / HTTP logs |

## Deployment

1. Review and customize each query for your environment (index names, sourcetypes, thresholds).
2. Create saved searches or add as correlation searches in ES.
3. Configure appropriate alert actions and response workflows.
4. Test with historical data before enabling in production.

# FortiSOAR Zero-to-Hero Training Guide

## 1. Introduction
FortiSOAR is Fortinet's SOAR platform integrated with the Security Fabric. It provides visual playbook design, 300+ connectors, and case management.

## 2. Architecture
- **FortiSOAR Server** - Central platform (on-prem/cloud)
- **Playbook Designer** - Visual drag-and-drop workflow builder
- **Connectors** - 300+ tool integrations
- **Modules** - Alerts, Incidents, Indicators, Assets, Campaigns
- **Dashboards** - Real-time SOC visibility
- **Roles & Teams** - RBAC for multi-tenant SOCs

## 3. Playbook Designer
Visual workflow with steps:
- **Start** - Trigger (manual, scheduled, on-create, webhook)
- **Action** - Execute connector action
- **Decision** - If/else branching
- **Loop** - Iterate over collections
- **Approval** - Human-in-the-loop gate
- **Set Variable** - Store/transform data
- **Create/Update Record** - Modify FortiSOAR modules

## 4. Connectors
| Category | Connectors |
|----------|------------|
| SIEM | FortiSIEM, Splunk, QRadar, Elastic |
| EDR | FortiEDR, CrowdStrike, SentinelOne, MDE |
| Firewall | FortiGate, Palo Alto, Check Point |
| Email | Exchange, Gmail, Proofpoint |
| TI | VirusTotal, OTX, MISP, Anomali |
| Ticketing | ServiceNow, Jira, Zendesk |

## 5. Jinja2 Templating
FortiSOAR uses Jinja2 for dynamic data:
```jinja2
{% set ip = vars.input.records[0].sourceIP %}
{% if vars.steps.vt_check.data.malicious > 5 %}
  MALICIOUS: {{ ip }} has {{ vars.steps.vt_check.data.malicious }} detections
{% else %}
  CLEAN: {{ ip }}
{% endif %}
```

## 6. FortiSIEM Integration
- Auto-create FortiSOAR alerts from FortiSIEM incidents
- Run FortiSIEM queries from playbooks
- Bidirectional status sync
- Automated enrichment and response

## 7. API
```bash
# Create alert
curl -X POST 'https://fortisoar/api/3/alerts' \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"name":"Suspicious Activity","severity":"/api/3/picklists/HIGH","source":"FortiSIEM"}'
```

## 8. Labs
### Lab 1: Phishing Response Playbook
1. Create playbook triggered on new alert
2. Add: extract IOCs → check VT → decision → block/close
3. Test with sample alert

---
*Compatible with FortiSOAR 7.x | Last updated March 2026*

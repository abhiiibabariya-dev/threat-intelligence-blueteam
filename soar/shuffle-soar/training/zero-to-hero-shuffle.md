# Shuffle SOAR Zero-to-Hero Training Guide

## 1. Introduction
Shuffle is an open-source Security Orchestration, Automation, and Response (SOAR) platform. It's the recommended SOAR for Wazuh and other open-source security stacks.

## 2. Architecture
- **Shuffle Backend** - Go-based API server
- **Shuffle Frontend** - React web UI
- **Shuffle Orborus** - Workflow executor (Docker-based)
- **Shuffle Worker** - Runs individual app actions in containers
- **OpenAPI** - All integrations defined via OpenAPI/Swagger specs

## 3. Installation
```bash
git clone https://github.com/Shuffle/Shuffle
cd Shuffle
docker-compose up -d
# Access at https://localhost:3443
# Create admin account on first login
```

## 4. Workflow Building
Visual drag-and-drop workflow editor:
```
Trigger (Webhook/Schedule/Subflow)
  → Action 1 (e.g., Parse Wazuh Alert)
  → Action 2 (e.g., Check VirusTotal)
  → Condition (Is malicious?)
    → Yes: Action 3 (Block IP)
    → No: Action 4 (Close Alert)
  → Action 5 (Send Slack Notification)
```

## 5. Wazuh Integration
```json
// Wazuh ossec.conf webhook
{
  "integration": {
    "name": "custom-shuffle",
    "hook_url": "https://shuffle:3443/api/v1/hooks/WEBHOOK_ID",
    "level": 10,
    "alert_format": "json"
  }
}
```

### Wazuh Alert Enrichment Workflow
1. **Trigger**: Wazuh webhook (level >= 10)
2. **Parse**: Extract source IP, rule ID, agent name
3. **Enrich**: Query VirusTotal, AbuseIPDB, Shodan
4. **Decide**: If malicious → block, if clean → close
5. **Respond**: Add to Wazuh CDB list, notify via Slack
6. **Document**: Create TheHive case

## 6. App Development
All apps defined via OpenAPI specs:
```yaml
openapi: 3.0.0
info:
  title: Custom Security App
  version: "1.0"
paths:
  /check_ip:
    post:
      summary: Check IP reputation
      parameters:
        - name: ip
          in: query
          required: true
          schema:
            type: string
      responses:
        '200':
          description: IP reputation result
```

## 7. Key Integrations
| Category | Apps |
|----------|------|
| SIEM | Wazuh, Splunk, Elastic, QRadar |
| EDR | CrowdStrike, Defender, SentinelOne |
| TI | VirusTotal, AbuseIPDB, OTX, Shodan |
| Ticketing | TheHive, Jira, ServiceNow |
| Communication | Slack, Teams, Email, PagerDuty |
| Network | Firewall APIs, DNS blocklists |

## 8. Use Cases
1. Wazuh alert enrichment and auto-response
2. Phishing triage (URL/hash check + block)
3. IOC sweep across SIEM
4. Automated TheHive case creation
5. Threat intel feed management
6. Vulnerability notification workflow

## 9. Labs
### Lab 1: Wazuh + Shuffle
1. Configure Wazuh webhook to Shuffle
2. Build enrichment workflow (VirusTotal lookup)
3. Test with Wazuh alert trigger

### Lab 2: Phishing Response
1. Build workflow: receive email → extract URLs → check VT → block/allow
2. Test with sample phishing alert

---
*Open source: https://github.com/Shuffle/Shuffle | Last updated March 2026*

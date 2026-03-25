# Microsoft Sentinel SOAR Zero-to-Hero Training Guide

## 1. Introduction
Sentinel SOAR uses Azure Logic Apps for automated security response. Playbooks trigger on incidents/alerts and can enrich, investigate, and remediate automatically.

## 2. Components
- **Automation Rules** - Trigger conditions (when incident created/updated)
- **Playbooks** - Azure Logic Apps with Sentinel connector
- **Connectors** - 400+ Logic App connectors (Microsoft, third-party)
- **Managed Identity** - Secure authentication without credentials

## 3. Creating a Playbook
1. Sentinel → Automation → Create playbook
2. Choose trigger: "When Microsoft Sentinel incident is created"
3. Add actions: Get entities → Enrich → Respond → Update incident
4. Configure managed identity for permissions

### Example: Auto-Enrich IP Playbook
```
Trigger: Sentinel Incident Created
→ Get Incident Entities (extract IPs)
→ For Each IP:
  → HTTP Action: Call VirusTotal API
  → Condition: If positives > 5
    → Yes: Add comment "Malicious IP: {ip}"
    → Yes: Change severity to High
    → No: Add comment "IP clean"
→ Add tags: "auto-enriched"
```

## 4. Automation Rules
```
Name: Auto-enrich all incidents
Trigger: When incident is created
Conditions: Severity >= Medium
Actions:
  - Run playbook: "IP-Enrichment-Playbook"
  - Add tag: "auto-triaged"
  - Assign to: "SOC-L1-Queue"
```

## 5. Key Connectors
| Connector | Use |
|-----------|-----|
| Microsoft Sentinel | Get/update incidents, run queries |
| Azure AD | Disable user, revoke sessions, reset password |
| Microsoft Teams | Send alert notifications |
| Office 365 | Block sender, quarantine email |
| VirusTotal | IOC reputation |
| ServiceNow | Create tickets |
| HTTP | Call any REST API |

## 6. Managed Identity
Best practice: Use system-assigned managed identity instead of API keys.
```
Logic App → Identity → System assigned → On
→ Grant "Microsoft Sentinel Responder" role on workspace
```

## 7. Common Playbooks
1. **IP enrichment** - VirusTotal + GeoIP + AbuseIPDB
2. **User investigation** - Get sign-in logs + risk level + disable if compromised
3. **Phishing response** - Extract URLs + check reputation + block + notify
4. **Incident notification** - Teams/Slack/email alert on high severity
5. **Auto-close** - Close known false positives automatically

## 8. Labs
### Lab 1: Create IP Enrichment Playbook
1. Create Logic App with Sentinel trigger
2. Add VirusTotal HTTP action
3. Parse response and add comment
4. Test with sample incident

### Lab 2: Auto-Close False Positives
1. Create automation rule for specific analytics rule
2. Condition: if source IP in allowlist
3. Action: close incident as false positive

---
*Compatible with Microsoft Sentinel | Last updated March 2026*

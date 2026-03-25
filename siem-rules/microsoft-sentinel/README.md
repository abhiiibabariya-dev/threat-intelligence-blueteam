# Microsoft Sentinel SIEM Rules

## Overview
This directory contains Microsoft Sentinel analytics rules, hunting queries, workbooks, and automated playbooks for threat detection and response.

## Directory Structure

```
microsoft-sentinel/
├── analytics-rules/          # Scheduled & NRT analytics rules (KQL)
│   ├── identity-threats.kql
│   ├── endpoint-threats.kql
│   ├── network-threats.kql
│   ├── cloud-threats.kql
│   ├── persistence-detection.kql
│   └── data-exfiltration.kql
├── hunting-queries/           # Proactive threat hunting queries
│   └── threat-hunting-queries.kql
├── workbooks/                 # Sentinel workbook templates
│   └── soc-workbook.json
└── playbooks/                 # Logic App automation playbooks
    └── auto-enrichment-playbook.json
```

## Prerequisites

### Required Data Connectors
- Azure Active Directory (Sign-in logs, Audit logs)
- Microsoft Defender for Endpoint
- Microsoft Defender for Cloud Apps
- Azure Activity
- Security Events / Windows Security Events
- DNS Analytics
- Common Event Format (CEF)
- Syslog

### Required Tables
| Table | Data Connector |
|-------|---------------|
| SigninLogs | Azure AD |
| AADNonInteractiveUserSignInLogs | Azure AD |
| AuditLogs | Azure AD |
| SecurityEvent | Windows Security Events |
| DeviceProcessEvents | MDE |
| DeviceNetworkEvents | MDE |
| DeviceFileEvents | MDE |
| CommonSecurityLog | CEF |
| DnsEvents | DNS Analytics |
| AzureActivity | Azure Activity |
| OfficeActivity | Microsoft 365 |

## Deployment

### Using Azure CLI
```bash
az sentinel alert-rule create --resource-group <rg> --workspace-name <ws> \
  --alert-rule-id <rule-id> --template-file analytics-rules/<rule>.json
```

### Using Azure Portal
1. Navigate to Microsoft Sentinel > Analytics
2. Click "+ Create" > "Scheduled query rule"
3. Copy the KQL query from the relevant `.kql` file
4. Configure entity mapping, alert grouping, and response actions

### Using Sentinel Repositories (CI/CD)
1. Connect your GitHub/Azure DevOps repository to Sentinel
2. Place ARM templates in the appropriate directory
3. Rules will be automatically deployed on push

## MITRE ATT&CK Coverage
All rules are mapped to MITRE ATT&CK techniques. See the `threat-intelligence/mitre-attack-mapping/` directory for a complete coverage matrix.

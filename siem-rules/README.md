# SIEM Detection Rules Library

A curated collection of production-ready detection rules, correlation searches, dashboards, and hunting queries for Security Operations Centers (SOC).

## Platforms Covered

| Platform | Directory | Language | Status |
|---|---|---|---|
| Splunk Enterprise / Splunk Cloud | `splunk/` | SPL (Search Processing Language) | Active |
| Microsoft Sentinel | `microsoft-sentinel/` | KQL (Kusto Query Language) | Active |

## Repository Structure

```
siem-rules/
├── splunk/
│   ├── detection-rules/       # Individual detection rules by ATT&CK tactic
│   │   ├── credential-access.spl
│   │   ├── lateral-movement.spl
│   │   ├── persistence.spl
│   │   └── exfiltration.spl
│   ├── correlation-rules/     # Multi-stage attack detection
│   │   └── multi-stage-attack.spl
│   └── dashboards/            # Splunk XML dashboards
│       └── soc-overview.xml
├── microsoft-sentinel/
│   ├── analytics-rules/       # Scheduled analytics rules
│   │   ├── credential-access.kql
│   │   ├── identity-threats.kql
│   │   └── cloud-threats.kql
│   ├── hunting-queries/       # Proactive threat hunting
│   │   └── advanced-hunting.kql
│   └── workbooks/             # Visualization templates
│       └── security-overview.json
└── README.md
```

## MITRE ATT&CK Coverage

Rules in this library map to the following ATT&CK tactics:

- **TA0001** - Initial Access
- **TA0003** - Persistence
- **TA0004** - Privilege Escalation
- **TA0005** - Defense Evasion
- **TA0006** - Credential Access
- **TA0008** - Lateral Movement
- **TA0009** - Collection
- **TA0010** - Exfiltration
- **TA0011** - Command and Control

## How to Use

### Splunk

1. Copy the SPL query from the relevant `.spl` file.
2. Paste into Splunk Search bar or use as a saved search / correlation search in Splunk Enterprise Security.
3. Adjust index names, sourcetypes, and thresholds to match your environment.
4. Schedule the search and configure alert actions (email, webhook, notable event).

### Microsoft Sentinel

1. Open Microsoft Sentinel in the Azure Portal.
2. Navigate to **Analytics** > **Create** > **Scheduled query rule**.
3. Paste the KQL query from the relevant `.kql` file.
4. Configure entity mappings, alert grouping, and automated response as noted in the rule comments.
5. For hunting queries, navigate to **Hunting** and create a new query.

## Customization Notes

- **Index names**: Replace placeholder index names (`index=windows`, `index=auth`) with your organization's naming conventions.
- **Thresholds**: Tune numeric thresholds (failed login counts, data volume limits) based on your environment's baseline.
- **Allowlists**: Add known-good service accounts, IP ranges, and hostnames to reduce false positives.
- **Lookups**: Several rules reference lookup tables. Create these with your organization's known assets and authorized accounts.
- **Time windows**: Adjust search time ranges to match your data retention and performance requirements.

## Severity Levels

| Level | Description |
|---|---|
| Critical | Confirmed or high-confidence active threat requiring immediate response |
| High | Strong indicator of compromise requiring investigation within 1 hour |
| Medium | Suspicious activity requiring investigation within 4 hours |
| Low | Anomalous behavior for awareness and trend analysis |
| Informational | Baseline or context-enrichment data |

## Contribution Guidelines

1. **Follow the template**: Each rule must include a header comment block with rule name, description, MITRE ATT&CK mapping, severity, required data sources, and author.
2. **Test before submitting**: Validate query syntax in the target SIEM platform. Ensure queries return expected results against sample data.
3. **Document thresholds**: Explain why specific numeric thresholds were chosen and how to tune them.
4. **Map to ATT&CK**: Every rule must reference at least one MITRE ATT&CK technique ID.
5. **Minimize false positives**: Include filtering logic for common benign activity and document known false positive scenarios.
6. **Use consistent naming**: Follow the pattern `<tactic>-<technique_short_name>` for rule names.
7. **Version your changes**: Note the date and author in the rule header when modifying existing rules.

## License

These detection rules are provided as-is for defensive security purposes. Adapt and deploy at your own discretion.

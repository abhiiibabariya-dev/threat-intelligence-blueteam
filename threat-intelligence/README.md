# Threat Intelligence Resources

This directory contains operational threat intelligence resources designed for security teams to identify, track, and respond to adversary activity. All materials are structured around the intelligence lifecycle and aligned to the MITRE ATT&CK framework.

## Directory Structure

```
threat-intelligence/
├── ioc-management/           # IOC templates, lifecycle guides, and feed management
│   ├── ioc-template.csv          # Flat-file IOC template for quick ingestion
│   ├── ioc-template.stix2.json   # STIX 2.1 bundle template for structured sharing
│   └── ioc-management-guide.md   # Complete IOC lifecycle management guide
├── mitre-attack-mapping/     # ATT&CK technique coverage and gap analysis
│   ├── technique-coverage-matrix.md  # Detection coverage by tactic and technique
│   └── navigator-layer.json          # ATT&CK Navigator layer for visualization
├── threat-hunting/           # Proactive threat hunting playbooks
│   ├── hunting-playbook-ransomware.md    # Ransomware-focused hunting operations
│   ├── hunting-playbook-apt.md           # APT/nation-state hunting operations
│   └── hunting-playbook-insider-threat.md # Insider threat hunting operations
└── ttp-detection/            # TTP-based detection rules
    └── ttp-based-rules.yml       # Detection rules organized by MITRE tactic
```

## Overview

### IOC Management

Indicators of Compromise (IOCs) are the foundational artifacts used to detect known threats. The IOC management resources provide:

- **Standardized templates** in both CSV and STIX 2.1 formats for consistent IOC documentation and sharing
- **Lifecycle management guidance** covering the full IOC lifecycle from collection through retirement
- **Confidence scoring frameworks** to prioritize indicators based on reliability and relevance
- **TLP handling procedures** to ensure proper classification and dissemination controls
- **Feed management strategies** for integrating and deduplicating multiple threat intelligence feeds

### MITRE ATT&CK Mapping

All detection rules in this repository are mapped to MITRE ATT&CK techniques. The mapping resources provide:

- **Coverage matrix** showing which techniques are detected across SIEM, EDR, and XDR platforms
- **Navigator layer** for visual gap analysis using the ATT&CK Navigator tool
- **Gap identification** to prioritize detection engineering efforts

### Threat Hunting

Proactive threat hunting playbooks provide structured approaches for identifying threats that evade automated detection:

- **Ransomware hunting** focused on pre-encryption indicators, lateral movement, and data staging
- **APT hunting** targeting nation-state TTPs including living-off-the-land, supply chain compromise, and covert C2
- **Insider threat hunting** addressing data exfiltration, privilege abuse, and behavioral anomalies

Each playbook includes cross-platform hunt queries (Splunk SPL, KQL, EQL), required data sources, expected findings, and response actions.

### TTP-Based Detection

Detection rules organized by adversary tactics, techniques, and procedures rather than individual indicators. TTP-based detection provides:

- **Behavior-based rules** that detect adversary techniques regardless of specific tools or infrastructure
- **Cross-platform coverage** with detection logic adaptable to multiple SIEM/EDR/XDR platforms
- **Confidence and severity scoring** for prioritized alert handling

## Usage Guidelines

### For Threat Analysts

1. Use the IOC templates to standardize indicator documentation
2. Follow the IOC management guide for lifecycle and enrichment workflows
3. Reference the ATT&CK coverage matrix to identify detection gaps

### For Threat Hunters

1. Select the appropriate hunting playbook based on the threat scenario
2. Verify required data sources are available in your environment
3. Adapt hunt queries to your platform and data schema
4. Document findings using the templates provided in each playbook

### For Detection Engineers

1. Use the TTP-based rules as a starting point for detection development
2. Map new rules to ATT&CK techniques using the coverage matrix
3. Update the Navigator layer after deploying new detections

### For SOC Analysts

1. Reference the ATT&CK mapping when triaging alerts to understand adversary context
2. Use IOC templates to submit new indicators from investigations
3. Leverage threat hunting playbooks for proactive investigation during low-activity periods

## Integration Points

These threat intelligence resources integrate with:

- **SIEM Rules** (`/siem-rules/`): Detection rules across Splunk, Elastic, Sentinel, QRadar, Chronicle, and ArcSight
- **EDR Rules** (`/edr-rules/`): Endpoint detection rules for CrowdStrike, Defender, SentinelOne, and Carbon Black
- **XDR Rules** (`/xdr-rules/`): Cross-platform detection for Microsoft 365 Defender, Cortex XDR, and Trend Micro Vision One
- **Blue Team Resources** (`/blue-team-resources/`): Incident response playbooks and SOC runbooks

## Contributing

When adding new threat intelligence resources:

1. Follow the established templates and formats
2. Include ATT&CK technique mappings for all detection-related content
3. Assign appropriate TLP markings to all shared intelligence
4. Validate IOCs before adding them to templates or feeds
5. Include data source requirements for all hunt queries and detection rules

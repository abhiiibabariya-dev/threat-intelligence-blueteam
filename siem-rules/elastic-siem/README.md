# Elastic SIEM Detection Rules

Detection content for Elastic Security, including TOML-based detection rules, EQL (Event Query Language) queries, and Kibana dashboard exports.

## Contents

- **detection-rules/credential-access.toml** -- Detection rules for credential access techniques: LSASS access, SAM dumping, Kerberos abuse, and browser credential theft (MITRE T1003, T1555, T1558).
- **detection-rules/defense-evasion.toml** -- Detection rules for defense evasion: process injection, timestomping, indicator removal, masquerading, and AMSI bypass (MITRE T1055, T1070, T1036, T1562).
- **eql-queries/process-threats.eql** -- EQL queries for process-based threats: suspicious parent-child relationships, LOLBin abuse, process hollowing, and script interpreter abuse.
- **dashboards/threat-overview.ndjson** -- Kibana dashboard export for centralized threat monitoring.

## Deployment

1. Import detection rules via the Elastic Security **Detection Rules** UI or the `elastic/detection-rules` CLI tool.
2. Load EQL queries in **Timeline > Correlation** or use them in custom detection rules.
3. Import dashboards via **Stack Management > Saved Objects > Import**.

## Requirements

- Elastic Stack 8.x with Elastic Security enabled
- Elastic Agent with Endpoint and Windows integration
- ECS (Elastic Common Schema) compliant log sources

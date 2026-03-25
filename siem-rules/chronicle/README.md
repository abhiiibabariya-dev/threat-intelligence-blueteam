# Google Chronicle SIEM Detection Rules

Detection content for Google Chronicle using YARA-L 2.0 rule language.

## Contents

- **yara-l-rules/malware-detection.yaral** -- YARA-L rules for malware detection: C2 communication patterns, ransomware behavior, cryptominer activity, suspicious DNS, and data exfiltration (MITRE T1071, T1486, T1496, T1048).
- **yara-l-rules/insider-threat.yaral** -- YARA-L rules for insider threat detection: anomalous data access, after-hours activity, privilege escalation, mass file operations, and unauthorized cloud access (MITRE T1530, T1078, T1548).

## Deployment

1. Navigate to **Chronicle > Rules Editor**.
2. Create new rules and paste the YARA-L content for each detection.
3. Set alerting severity and enable live rules after validation against historical data using **Retrohunt**.
4. Tune reference list values (e.g., allowed domains, VPN subnets) before production deployment.

## Requirements

- Google Chronicle SIEM instance with UDM (Unified Data Model) log ingestion
- Log sources: EDR, DNS, proxy, cloud audit logs, authentication logs

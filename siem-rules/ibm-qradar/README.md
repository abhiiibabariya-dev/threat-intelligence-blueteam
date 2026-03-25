# IBM QRadar SIEM Detection Rules

Detection content for IBM QRadar, including AQL (Ariel Query Language) rules and custom XML rule definitions for offense generation.

## Contents

- **aql-rules/credential-access.aql** -- AQL queries for detecting credential theft, brute force, pass-the-hash, Kerberoasting, and credential dumping (MITRE T1110, T1550, T1558, T1003, T1098).
- **aql-rules/network-threats.aql** -- AQL queries for network-layer threats including C2 beaconing, DNS tunneling, port scanning, data exfiltration, and protocol anomalies (MITRE T1071, T1046, T1048, T1571).
- **custom-rules/offense-rules.xml** -- QRadar custom rule definitions in XML format for multi-event correlation and automated offense generation.

## Deployment

1. Import AQL rules via the QRadar **Log Activity** tab using the Advanced Search editor.
2. Schedule recurring searches or convert to custom rules via **Offenses > Rules**.
3. Import `offense-rules.xml` through **Admin > Content Management > Import**.
4. Tune thresholds to match your environment's baseline before enabling in production.

## Requirements

- IBM QRadar SIEM 7.5.0 or later
- Appropriate log sources (Windows Security, Sysmon, firewall, DNS, proxy) forwarding to QRadar

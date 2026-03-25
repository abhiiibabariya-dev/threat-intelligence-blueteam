# SOAR Platform Comparison Matrix

| Feature | Splunk SOAR | XSOAR | Sentinel SOAR | QRadar SOAR | Shuffle | TheHive+Cortex | FortiSOAR |
|---------|-------------|-------|---------------|-------------|---------|----------------|-----------|
| **Deployment** | On-prem/Cloud | On-prem/Cloud | Cloud (Azure) | On-prem/Cloud | Self-hosted | Self-hosted | On-prem/Cloud |
| **Pricing** | Commercial | Commercial | Included w/Sentinel | Commercial | Free/Open Source | Free/Open Source | Commercial |
| **Integrations** | 300+ | 700+ | 400+ (Logic Apps) | 200+ | 100+ (OpenAPI) | 100+ (Cortex) | 300+ |
| **Playbook Editor** | Visual + Python | Visual + YAML | Logic Apps designer | Visual + Python | Visual (web) | N/A (API-driven) | Visual drag-drop |
| **Code Support** | Python | Python/PowerShell | Logic Apps (low-code) | Python | Python (OpenAPI) | Python | Python/Jinja2 |
| **Case Management** | Built-in | War Room | Sentinel Incidents | Built-in | Basic | Full (TheHive) | Built-in |
| **TI Management** | Basic | Full platform | TI module | Basic | Basic | MISP integration | Built-in |
| **Best For** | Splunk shops | Large enterprises | Azure/M365 environments | QRadar shops | Open-source/Wazuh | Open-source SOCs | Fortinet shops |
| **SIEM Pairing** | Splunk | Any | Microsoft Sentinel | IBM QRadar | Wazuh/Any | Wazuh/Any | FortiSIEM |
| **Learning Curve** | Medium | High | Medium | Medium | Low | Medium | Medium |
| **Community** | Large | Large | Very Large | Medium | Growing | Large | Medium |

## Recommendation Guide

| If You Use... | Best SOAR |
|---------------|-----------|
| Splunk | Splunk SOAR |
| Microsoft Sentinel / M365 | Sentinel SOAR (Logic Apps) |
| IBM QRadar | QRadar SOAR (Resilient) |
| Wazuh (open source) | Shuffle or TheHive+Cortex |
| Palo Alto ecosystem | Cortex XSOAR |
| FortiSIEM / Fortinet | FortiSOAR |
| Budget-conscious / startup | Shuffle (free) or TheHive (free) |
| Multi-SIEM / large enterprise | Cortex XSOAR or Splunk SOAR |

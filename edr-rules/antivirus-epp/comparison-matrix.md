# EDR / XDR / AV Comparison Matrix

## EDR Platforms

| Feature | CrowdStrike Falcon | Microsoft Defender | SentinelOne | Carbon Black |
|---------|-------------------|-------------------|-------------|--------------|
| **Deployment** | Cloud + sensor | Cloud + built-in | Cloud + agent | Cloud + sensor |
| **OS Support** | Win/Lin/Mac/K8s | Win/Lin/Mac | Win/Lin/Mac/K8s | Win/Lin/Mac |
| **Query Language** | FQL/LQL | KQL | SQL-like (DV) | Process search |
| **AI/ML** | Cloud AI | Cloud + local | Behavioral AI | Cloud analytics |
| **Rollback** | No | Limited | Yes (VSS-based) | No |
| **Remote Shell** | RTR | Live Response | Remote Shell | Live Response |
| **Auto-Remediation** | Yes | AIR | Yes (Storyline) | Limited |
| **TI Integration** | Falcon X (built-in) | Microsoft TI | Integrated | Alliance feeds |
| **SOAR** | Falcon Fusion | Logic Apps | Singularity Mkt | API-based |
| **Network Discovery** | Falcon Discover | MDE Discovery | Ranger | No |
| **Strength** | Cloud speed, OverWatch | M365 integration | Autonomous AI | Process visibility |
| **Best For** | Enterprise, MDR | Microsoft shops | Autonomous EDR | VMware shops |

## XDR Platforms

| Feature | Cortex XDR | M365 Defender | Vision One |
|---------|-----------|---------------|------------|
| **Data Sources** | Endpoint+Network+Cloud | Endpoint+Identity+Email+Cloud Apps | Endpoint+Email+Network+Cloud |
| **Query Language** | XQL | KQL | Structured search |
| **Causality** | Causality chain | Investigation graph | Execution profile |
| **SOAR** | XSOAR integration | Logic Apps | Built-in |
| **Strength** | Network+endpoint correlation | Cross-Microsoft correlation | Email+endpoint chain |

## Antivirus / EPP

| Feature | Windows Defender | Symantec/Broadcom | Kaspersky | Trellix (McAfee) |
|---------|-----------------|-------------------|-----------|------------------|
| **Type** | Built-in AV + ASR | Third-party AV/EPP | Third-party AV/EPP | Third-party AV/EPP |
| **ASR Rules** | 16+ rules | Behavior blocking | App control | Exploit prevention |
| **Cloud ML** | MAPS | Insight | KSN | GTI |
| **Management** | Intune/GPO/MDE | SEPM | KSC | ePO/Trellix |
| **Cost** | Free (built-in) | Commercial | Commercial | Commercial |
| **Best For** | M365 environments | Legacy enterprise | Strong AV engine | McAfee ecosystem |

## Selection Guide

| Scenario | Recommended |
|----------|-------------|
| All-Microsoft environment | MDE + M365 Defender |
| Best-of-breed EDR | CrowdStrike Falcon |
| Open-source / budget | Wazuh + Windows Defender |
| Autonomous (no SOC) | SentinelOne |
| VMware/VDI heavy | Carbon Black |
| Fortinet firewall shop | FortiEDR + FortiSIEM |
| Palo Alto firewall shop | Cortex XDR |
| Multi-vendor XDR | Cortex XDR or CrowdStrike |

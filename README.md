# Threat Intelligence - Blue Team Toolkit

A comprehensive collection of tools, detection rules, threat hunting queries, and incident response playbooks for blue team operations. Built for defenders, mapped to MITRE ATT&CK and NIST SP 800-61.

**[Live Dashboard](https://abhiiibabariya-dev.github.io/threat-intelligence-blueteam/)**

## Structure

```
.
├── ioc/                          # Indicators of Compromise
│   ├── feeds.yaml                # 7 threat intel feed configurations
│   └── ioc_manager.py            # IOC collection and enrichment tool
├── rules/
│   ├── sigma/                    # 16 Sigma detection rules (SIEM)
│   │   ├── suspicious_login.yml  # Authentication attack detection
│   │   ├── data_exfil.yml        # Data exfiltration detection
│   │   ├── lateral_movement.yml  # Lateral movement detection
│   │   ├── privilege_escalation.yml  # Privilege escalation detection
│   │   └── defense_evasion.yml   # Defense evasion detection
│   └── yara/                     # 13 YARA malware detection rules
│       ├── malware_indicators.yar    # Common malware families
│       └── advanced_threats.yar      # APT, rootkits, stealers
├── scripts/
│   ├── email_analyzer.py         # Email header phishing/spoofing analyzer
│   ├── ip_reputation.py          # Multi-source IP reputation checker
│   ├── cve_checker.py            # CVE vulnerability lookup + CISA KEV
│   ├── timeline_generator.py     # Forensic timeline from multiple logs
│   ├── attack_mapper.py          # MITRE ATT&CK coverage mapper
│   ├── threat_report.py          # Threat intelligence report generator
│   ├── log_analyzer.py           # Log analysis and anomaly detection
│   ├── network_scan.py           # Network baseline and monitoring
│   └── hash_checker.py           # File hash reputation checker
├── hunting/                      # Threat hunting queries
│   └── threat_queries.yaml       # 18 SIEM hunting queries (Splunk/Elastic)
├── playbooks/                    # 9 Incident response playbooks
│   ├── ir_checklist.yaml         # Core IR playbooks (accounts, malware, exfil, ransomware)
│   └── ir_advanced.yaml          # Advanced playbooks (insider, DDoS, supply chain, cloud, 0day)
├── config/
│   └── settings.yaml.example     # Global configuration template
└── index.html                    # GitHub Pages dashboard
```

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Configure threat intel feeds
cp config/settings.yaml.example config/settings.yaml

# Collect IOCs from 7 threat feeds
python ioc/ioc_manager.py collect

# Analyze suspicious email headers
python scripts/email_analyzer.py -f headers.txt

# Check IP reputation across multiple sources
python scripts/ip_reputation.py 8.8.8.8 1.2.3.4

# Search CVE vulnerabilities
python scripts/cve_checker.py search "apache log4j"
python scripts/cve_checker.py lookup CVE-2024-1234
python scripts/cve_checker.py kev --recent 20

# Generate forensic timeline from logs
python scripts/timeline_generator.py /var/log/auth.log /var/log/syslog --category authentication

# Map MITRE ATT&CK coverage gaps
python scripts/attack_mapper.py
python scripts/attack_mapper.py --gaps-only

# Generate threat intelligence report
python scripts/threat_report.py
python scripts/threat_report.py --markdown report.md

# Run log analysis
python scripts/log_analyzer.py --input /var/log/syslog

# Check file hashes against threat intel
python scripts/hash_checker.py --hash <sha256>

# Network baseline and monitoring
python scripts/network_scan.py baseline
python scripts/network_scan.py scan
```

## Features

### Analysis & Intelligence Tools (8 Scripts)
| Tool | Description |
|------|-------------|
| **IOC Manager** | Aggregate IOCs from 7 feeds (Feodo, URLhaus, ThreatFox, MalwareBazaar, etc.) |
| **Email Header Analyzer** | SPF/DKIM/DMARC validation, spoofing detection, phishing indicators, risk scoring |
| **IP Reputation Checker** | AbuseIPDB, VirusTotal, blocklist.de, geolocation, reverse DNS |
| **CVE Vulnerability Checker** | NVD search, CISA KEV cross-reference, CVSS scoring |
| **Forensic Timeline Generator** | Multi-format log parsing, event classification, chronological timeline |
| **MITRE ATT&CK Mapper** | Scan rules/playbooks for technique coverage, identify gaps |
| **Threat Report Generator** | Automated reports combining IOC stats, rules, feeds, recommendations |
| **Log Analyzer** | 9 detection patterns with MITRE ATT&CK mapping across multiple log types |
| **Network Scanner** | Connection baselining, anomaly detection, IOC correlation |
| **Hash Checker** | Multi-source hash reputation (VirusTotal, MalwareBazaar, local IOCs) |

### Detection Rules
- **16 Sigma Rules** - SIEM-compatible (Splunk, Elastic, QRadar)
  - Brute force, Tor login, suspicious scheduled tasks
  - DNS tunneling, large data transfers
  - PsExec, WMI, RDP lateral movement
  - UAC bypass, sudo abuse, kernel exploits
  - Security tool termination, log tampering, process injection
- **13 YARA Rules** - Malware scanning
  - PowerShell encoders, webshells, Mimikatz, Cobalt Strike
  - APT loaders, reverse shells, credential harvesters
  - Rootkits, cryptominers, info stealers, ransomware

### Threat Hunting (18 Queries)
- Curated Splunk & Elastic queries covering the full ATT&CK kill chain
- Phishing, PowerShell cradles, Kerberoasting, LSASS access
- C2 beaconing, DNS tunneling, mass encryption detection

### Incident Response (9 Playbooks)
| Playbook | Severity | Key Phases |
|----------|----------|------------|
| IR-001: Compromised Account | High | MFA reset, session revocation, 30-day monitoring |
| IR-002: Malware Infection | Critical | YARA scan, C2 blocking, system rebuild |
| IR-003: Data Exfiltration | Critical | DLP review, legal engagement, exposure assessment |
| IR-004: Ransomware | Critical | Backup verification, offline restoration |
| IR-005: Insider Threat | High | HR/legal coordination, covert monitoring |
| IR-006: DDoS Attack | High | Mitigation provider engagement, auto-scaling |
| IR-007: Supply Chain Compromise | Critical | SBOM tracking, dependency auditing |
| IR-008: Cloud Account Compromise | Critical | IAM audit, CSPM deployment |
| IR-009: Zero-Day Exploitation | Critical | Virtual patching, vendor coordination |

### MITRE ATT&CK Coverage
Techniques covered across all 12 Enterprise tactics:
Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Exfiltration, Command & Control, Impact

## Threat Intelligence Feeds

| Feed | Type | Refresh |
|------|------|---------|
| Feodo Tracker | C2 IPs | 1 hour |
| URLhaus | Malware URLs | 1 hour |
| Emerging Threats | Compromised IPs | 4 hours |
| SSL Blacklist | Malicious SSL | 6 hours |
| Tor Exit Nodes | Tor IPs | 12 hours |
| MalwareBazaar | Malware Hashes | 1 hour |
| ThreatFox | Mixed IOCs | 1 hour |

## Requirements

- Python 3.9+
- See `requirements.txt` for Python dependencies

## License

MIT
